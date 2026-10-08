# Kubernetes deployment (auth broker)

Static, schema-validated manifests for the **broker app itself**. They do **not**
reinvent Keycloak, OpenBao, Traefik, or Postgres — in production those should be
their own upstream charts/operators or managed services, and the broker points at
them via config. This keeps the broker's deployment small and the heavy stateful
components on their supported install paths.

## What's here
- `namespace.yaml`, `configmap.yaml` (non-secret env), `secret.example.yaml`
  (template — copy to `secret.yaml`, which is gitignored), `deployment.yaml`
  (2 replicas, non-root uid 10001, readonly rootfs, `/health/live` + `/health/ready`
  probes, resource limits), `service.yaml`, `ingress.yaml`, `kustomization.yaml`.

## Dependencies (bring your own)
- **Keycloak** — the Keycloak Operator or the Bitnami chart. Point `KEYCLOAK_URL`
  at its in-cluster Service.
- **OpenBao / Vault** — the official Vault Helm chart. In a cluster, auto-unseal
  via a cloud KMS (see `../openbao/config.azure.hcl.example` + `../check-azure-kms.sh`
  for the Azure Key Vault path); don't ship the dev file-storage/plaintext-unseal
  setup to production.
- **Postgres** (only for dynamic secrets) — a managed DB or an operator.

## Apply
```sh
cp k8s/secret.example.yaml k8s/secret.yaml   # fill in, or use `kubectl create secret`
# edit configmap.yaml (URLs) + kustomization.yaml (your image registry/tag)
kubectl apply -k k8s/
kubectl -n auth-broker rollout status deploy/auth-broker
```

## Notes / decisions to make
- **RSA keys across replicas.** `/data/keys` is a per-pod `emptyDir`, so each
  replica generates its own keys. If the broker's signing keys must be shared
  across replicas, mount a `Secret` (pre-generated keys) or a ReadWriteMany PVC
  there instead.
- **Shared rate-limit / lockout / API-key state.** For multi-replica correctness
  set `RATE_LIMIT_BACKEND=redis`, `LOCKOUT_BACKEND=redis`, `API_KEY_BACKEND=openbao`
  (add a Redis Service + `REDIS_URL` to the ConfigMap).
- **Ingress.** `ingressClassName`/annotations assume Traefik + cert-manager;
  adjust to your controller and TLS issuer.

## VERIFICATION BOUNDARY
These manifests are **schema-validated** (kubernetes-validate) and
cross-checked (selectors, probe ports, config/secret refs, the non-root uid
matches the Dockerfile). They have **NOT** been applied to a real cluster — pod
scheduling, PVCs, the OpenBao unseal lifecycle, and ingress behavior can only be
proven on your cluster. Treat this as a correct starting point to `kubectl apply`
and verify, not a guaranteed-working deployment.
