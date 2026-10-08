# First production deploy on a single host

A concrete runbook to take the Premkey auth broker from the local `.test.local`
dev stack to a real, internet-reachable deployment on **one Linux host**
(a VM or bare metal), fronted by Traefik with real TLS.

> **Read this first — what the stock `compose.yaml` assumes.**
> Out of the box the stack is wired for *local development*: hostnames are
> hardcoded to `app.test.local` / `app.localhost`, Keycloak runs `start-dev`
> (in-memory H2 database), and Traefik serves a self-signed / OpenBao-issued
> cert that only your machine trusts. Running `./bootstrap.sh` unchanged gives
> you the **dev** experience on a server, not a production one. The sections
> below are the specific deltas that make it production-real. Nothing here is a
> code change — it is configuration you own.

Target topology: Traefik (:80/:443) → broker app, with Keycloak, OpenBao, and
(optionally) Postgres + Prometheus/Grafana behind it on the compose network.

---

## 0. Prerequisites

- A Linux host with a public IP, root/sudo, and ports **80** and **443** open
  to the internet (443 and 80 both — ACME HTTP-01 needs 80).
- A **domain you control** (examples below use `auth.example.com` for the
  broker and `id.example.com` for Keycloak; one domain with path routing also
  works, but two names is cleaner).
- Docker Engine + the Docker Compose v2 plugin (`docker compose version`).
- The repo checked out on the host, synced to canonical (`./sync-to-canonical.sh`).

---

## 1. DNS

Create **A records** pointing both names at the host's public IP:

```
auth.example.com.   A   203.0.113.10
id.example.com.     A   203.0.113.10
```

Verify from the host *and* from off-host before continuing — ACME will fail if
the names don't resolve publicly yet:

```bash
dig +short auth.example.com
dig +short id.example.com
```

Wait for propagation (usually minutes). Don't start Traefik with ACME until
both resolve to the host, or Let's Encrypt will rate-limit failed challenges.

---

## 2. Host prep

```bash
# firewall: allow only SSH + web
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable

# make sure Docker is running and starts on boot
sudo systemctl enable --now docker
```

Do **not** publish Keycloak's 8080/9000, OpenBao's 8200, or Postgres's 5432 to
the host's public interface. In the stock compose they're already `expose:`-only
(internal to the compose network) — keep it that way. The Postgres overlay
publishes 5432 for a host-side test; drop that `ports:` mapping in production.

---

## 3. Production config deltas

These are edits to `compose.yaml` (or better, a `compose.prod.yaml` overlay you
layer on top so the dev file stays intact). Create `compose.prod.yaml`:

```yaml
# compose.prod.yaml — production overrides for a single public host.
#   docker compose -f compose.yaml -f compose.prod.yaml up -d
services:
  traefik:
    command:
      - "--providers.docker=true"
      - "--providers.docker.exposedbydefault=false"
      - "--providers.file.directory=/etc/traefik/dynamic"
      - "--entrypoints.web.address=:80"
      - "--entrypoints.websecure.address=:443"
      # Redirect all HTTP to HTTPS.
      - "--entrypoints.web.http.redirections.entrypoint.to=websecure"
      - "--entrypoints.web.http.redirections.entrypoint.scheme=https"
      # Let's Encrypt (HTTP-01). Use the staging CA first to avoid rate limits.
      - "--certificatesresolvers.le.acme.email=you@example.com"
      - "--certificatesresolvers.le.acme.storage=/letsencrypt/acme.json"
      - "--certificatesresolvers.le.acme.httpchallenge=true"
      - "--certificatesresolvers.le.acme.httpchallenge.entrypoint=web"
      # - "--certificatesresolvers.le.acme.caserver=https://acme-staging-v02.api.letsencrypt.org/directory"
    volumes:
      - letsencrypt:/letsencrypt

  keycloak:
    # Production mode (persistent DB, optimized) instead of start-dev.
    command: start --optimized
    environment:
      KC_HOSTNAME: https://id.example.com
      KC_HOSTNAME_STRICT: "true"
      KC_PROXY_HEADERS: xforwarded
      KC_HTTP_ENABLED: "true"      # Traefik terminates TLS; KC speaks HTTP behind it
      # Persistent database — H2/start-dev loses realm state on restart.
      KC_DB: postgres
      KC_DB_URL: jdbc:postgresql://kc-postgres:5432/keycloak
      KC_DB_USERNAME: keycloak
      KC_DB_PASSWORD: ${KC_DB_PASSWORD}
    labels:
      - "traefik.enable=true"
      - "traefik.http.routers.keycloak.rule=Host(`id.example.com`)"
      - "traefik.http.routers.keycloak.entrypoints=websecure"
      - "traefik.http.routers.keycloak.tls=true"
      - "traefik.http.routers.keycloak.tls.certresolver=le"
      - "traefik.http.services.keycloak.loadbalancer.server.port=8080"

  app:
    labels:
      - "traefik.enable=true"
      # Public endpoints (no auth required to GET a token / health / metrics).
      - "traefik.http.routers.app-public.rule=Host(`auth.example.com`) && (PathPrefix(`/token`) || PathPrefix(`/register`) || PathPrefix(`/auth/forward`) || Path(`/`) || PathPrefix(`/keys`) || PathPrefix(`/status`) || PathPrefix(`/health`) || Path(`/metrics`))"
      - "traefik.http.routers.app-public.entrypoints=websecure"
      - "traefik.http.routers.app-public.tls=true"
      - "traefik.http.routers.app-public.tls.certresolver=le"
      - "traefik.http.routers.app-public.priority=100"
      # Everything else is protected by ForwardAuth.
      - "traefik.http.routers.app-protected.rule=Host(`auth.example.com`)"
      - "traefik.http.routers.app-protected.entrypoints=websecure"
      - "traefik.http.routers.app-protected.tls=true"
      - "traefik.http.routers.app-protected.tls.certresolver=le"
      - "traefik.http.routers.app-protected.priority=1"
      - "traefik.http.routers.app-protected.middlewares=forward-auth@file"
    environment:
      # The app must advertise the real external issuer/redirect.
      KEYCLOAK_URL: https://id.example.com
      APP_REDIRECT_URI: https://auth.example.com/callback
      SECURITY_HSTS: "true"
      DOCS_ENABLED: "false"        # don't expose /docs publicly
      CORS_ALLOW_ORIGINS: https://your-frontend.example.com

  # Dedicated Postgres for Keycloak (separate from the OpenBao dynamic-secrets one).
  kc-postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: keycloak
      POSTGRES_USER: keycloak
      POSTGRES_PASSWORD: ${KC_DB_PASSWORD}
    volumes:
      - kc-postgres-data:/var/lib/postgresql/data
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U keycloak -d keycloak"]
      interval: 5s
      timeout: 3s
      retries: 10
    restart: unless-stopped

volumes:
  letsencrypt:
  kc-postgres-data:
```

Key points:
- **TLS** is now real (Let's Encrypt), not the OpenBao self-signed CA. Keep the
  OpenBao PKI for *internal* mTLS between Traefik and the app (`enable-mtls.sh`)
  if you want it — that's a different trust domain from the public cert.
- **Keycloak** runs `start` with a persistent Postgres and `KC_HOSTNAME_STRICT:
  true`, so issuer/redirect URLs come out as `https://id.example.com`.
- The **public-router priority (100) > protected (1)** invariant is preserved —
  `container_check.py` enforces it, so don't invert it.
- Start with the ACME **staging** `caserver` line uncommented to shake out DNS/
  firewall issues, then comment it back and `docker compose up -d --force-recreate
  traefik` to get a trusted cert.

---

## 4. Secrets

```bash
cp .env.example .env
```

Fill in, at minimum:

| Variable | What |
|---|---|
| `KEYCLOAK_ADMIN_USER` / `KEYCLOAK_ADMIN_PASSWORD` | strong admin creds |
| `KC_DB_PASSWORD` | Keycloak's Postgres password (used in the overlay) |
| `KEYCLOAK_CLIENT_SECRET` | the broker's Keycloak client secret |
| `AUTH0_DOMAIN` / `AUTH0_CLIENT_ID` / `AUTH0_CLIENT_SECRET` | if using Auth0 |
| `DEFAULT_USER_PASSWORD` / `ADMIN_USER_PASSWORD` | seeded user passwords |
| `SECRET_KEY` | `openssl rand -hex 32` |
| `POSTGRES_ADMIN_PASSWORD` | only if using the OpenBao dynamic-secrets Postgres |

`.env` is gitignored — never commit it. `./check-env.sh .env` validates it
before anything sources it (bootstrap runs this automatically). For real
production, promote these from `.env` into OpenBao (AppRole + KV) and leave
`.env` holding only `OPENBAO_ROLE_ID` / `OPENBAO_SECRET_ID` — see step 6.

---

## 5. Bring the stack up

```bash
# clears port conflicts, brings up the FULL stack with the prod overlay
./stack-up.sh -y --up    # or: docker compose -f compose.yaml -f compose.prod.yaml up -d
```

If you use `bootstrap.sh`, note it also issues the OpenBao *internal* cert and
prints the `.test.local` hosts/trust steps — those are dev-only and you can
ignore them once public ACME TLS is serving. Watch the services come healthy:

```bash
docker compose ps
docker compose logs -f traefik   # confirm "Certificates obtained for ..." (no ACME errors)
docker compose logs -f keycloak  # confirm it reached the DB and started
```

The broker provisions Keycloak (realm `Premkey`, client, scopes, roles) on
startup and re-provisions idempotently on restart, so a fresh DB self-heals.

---

## 6. Provision OpenBao (only if you use it for secrets)

With `OPENBAO_MODE=auto` (default), the broker runs fine without OpenBao and
falls back to env/Key Vault. To use OpenBao as the secret source with
least-privilege AppRole instead of a root token:

```bash
# one-time: enable AppRole + KV and mint role_id/secret_id into .env
./bootstrap.sh --provision
# or manually:
OPENBAO_TOKEN=<root> python openbao_setup.py approle
```

Then set `OPENBAO_SECRETS` to the comma-separated names you want resolved from
OpenBao first (or `*`), and restart the app. For production auto-unseal (so a
restart doesn't need a manual unseal key), use the Azure KMS overlay:

```bash
docker compose -f compose.yaml -f compose.prod.yaml -f compose.azure-kms.yaml up -d
./check-azure-kms.sh    # verifies the managed-identity + Key Vault wiring
```

---

## 7. Verify

Run these from the host (and the public checks from off-host too):

```bash
# 1. TLS + liveness, using a real public client (no -k; cert must be trusted)
curl -s https://auth.example.com/health/live -o /dev/null -w "live: %{http_code}\n"
curl -s https://auth.example.com/health/ready -o /dev/null -w "ready: %{http_code}\n"

# 2. Keycloak OIDC discovery resolves at the real issuer
curl -s https://id.example.com/realms/Premkey/.well-known/openid-configuration | head -c 200; echo

# 3. End-to-end auth path (health, M2M token, scope guards, user login)
BASE=https://auth.example.com KC=https://id.example.com REALM=Premkey \
  CLIENT=Hello-World-app TEST_USER=user TEST_PASS=<DEFAULT_USER_PASSWORD> \
  ./smoke-test.sh

# 4. Broader operational checks (health, smoke, dynamic secrets, mTLS, org-sync)
./doctor.sh
./live-test.sh
```

All green = the broker is live and issuing tokens over trusted TLS.

---

## 8. Post-deploy hardening

- **Rotate** the Keycloak admin password and any client secret you typed into
  `.env`; store the live ones in OpenBao/Key Vault.
- Set `DOCS_ENABLED=false` (done in the overlay) so `/docs` isn't public.
- Turn on `SECURITY_HSTS=true` only once you're sure you'll stay on HTTPS.
- Put the Traefik dashboard behind auth or don't expose it publicly.
- Enable Redis-backed rate-limit + lockout (`RATE_LIMIT_BACKEND=redis`,
  `LOCKOUT_BACKEND=redis`, `REDIS_URL=...`) if you run more than one app replica.
- Back up the Keycloak Postgres volume and the OpenBao data volume.
- Point Prometheus/Grafana (already in the stack) at an alerting target so the
  shipped `alert-rules.yml` actually pages someone.

---

## Rollback

```bash
# stop everything (keeps volumes/data)
docker compose -f compose.yaml -f compose.prod.yaml down

# full reset INCLUDING data (destroys Keycloak realm + OpenBao CA — last resort)
docker compose -f compose.yaml -f compose.prod.yaml down -v
```

Because the broker re-provisions Keycloak on startup, a `down` (without `-v`)
followed by `up -d` is a safe restart; `-v` wipes state and forces a clean
re-provision from scratch.
