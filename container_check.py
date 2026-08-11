#!/usr/bin/env python3
# container_check.py
# Static validation of the container build — catches real, silent-failure bugs
# WITHOUT needing a container engine, so it runs anywhere (CI, this sandbox).
#
#     python container_check.py
#
# It is not a substitute for an actual build; it is the cheap check that runs
# first. Actually building still needs an engine:
#     docker build -t auth-broker .
#     podman build --format docker -t auth-broker .
#
# WHY EACH CHECK EXISTS (all of these were found or nearly missed for real):
#
#  - Comments inside a line continuation. Modern BuildKit strips them; older
#    Docker and some buildah versions do not, silently TRUNCATING the
#    instruction. On this project that would have dropped HOST=0.0.0.0 and
#    KEY_DIR — and the container would have bound 127.0.0.1 internally, been
#    unreachable from the host, while the healthcheck (which runs INSIDE the
#    container against 127.0.0.1) still reported healthy.
#
#  - HOST not set to 0.0.0.0. Same silent failure: healthy but unreachable.
#
#  - Every module the app imports must actually be COPYed into the image and
#    every third-party package must be in requirements.txt, or the container
#    dies at import time on first run.
#
#  - .dockerignore must exclude tests and secrets from the build context.
#
#  - Dockerfile and Containerfile must stay identical (they are meant to be
#    copies so both engines work with no extra flags).

from __future__ import annotations

import ast
import fnmatch
import os
import re
import sys


class Check:
    def __init__(self):
        self.failed: list[str] = []
        self.warned: list[str] = []

    def ok(self, msg: str):
        print(f"  \u2713 {msg}")

    def fail(self, msg: str):
        self.failed.append(msg)
        print(f"  \u2717 {msg}")

    def warn(self, msg: str):
        self.warned.append(msg)
        print(f"  ! {msg}")


def _instructions_with_continuations(text: str) -> list[str]:
    """
    Join line continuations WITHOUT stripping comments — i.e. emulate the
    least-forgiving builder. If an instruction contains a '#' after joining,
    a strict builder would truncate it there.
    """
    joined, buf = [], ""
    for raw in text.split("\n"):
        line = raw.rstrip()
        if buf:
            buf += " " + line.strip()
        elif line.endswith("\\"):
            buf = line[:-1].strip()
            continue
        else:
            joined.append(line)
            continue
        if buf.endswith("\\"):
            buf = buf[:-1].strip()
            continue
        joined.append(buf)
        buf = ""
    if buf:
        joined.append(buf)
    return joined


def check_dockerfile(path: str, c: Check) -> None:
    if not os.path.exists(path):
        c.fail(f"{path} is missing")
        return
    text = open(path).read()

    # 1. No comment inside a continuation (silent truncation risk).
    bad = []
    for instr in _instructions_with_continuations(text):
        if not instr or instr.lstrip().startswith("#"):
            continue
        # A '#' that appears after the instruction keyword, in a line that was
        # built from a continuation, is the dangerous case.
        if re.match(r"^(ENV|RUN|COPY|ARG|LABEL)\b", instr) and "#" in instr:
            bad.append(instr[:90])
    if bad:
        for b in bad:
            c.fail(f"{path}: comment inside a line continuation would truncate: "
                   f"{b}...")
    else:
        c.ok(f"{path}: no comments inside line continuations")

    # 2. HOST must be 0.0.0.0 or the container is unreachable from the host
    #    while still passing its own internal healthcheck.
    env_line = next((i for i in _instructions_with_continuations(text)
                     if i.startswith("ENV") and "HOST" in i), "")
    if "HOST=0.0.0.0" in env_line:
        c.ok(f"{path}: HOST=0.0.0.0 (reachable from outside the container)")
    else:
        c.fail(f"{path}: HOST is not set to 0.0.0.0 — the app would bind "
               "loopback inside the container and be unreachable, while the "
               "internal healthcheck still passed")

    # 3. KEY_DIR must survive and be created/chowned.
    if "KEY_DIR=" in env_line:
        c.ok(f"{path}: KEY_DIR present in ENV")
    else:
        c.fail(f"{path}: KEY_DIR missing from ENV")

    # 4. Non-root user.
    if re.search(r"^USER\s+\w+", text, re.M):
        c.ok(f"{path}: runs as a non-root USER")
    else:
        c.warn(f"{path}: no USER instruction — container would run as root")


def check_dockerignore(c: Check) -> None:
    if not os.path.exists(".dockerignore"):
        c.fail(".dockerignore is missing — tests and secrets would be sent to "
               "the build context")
        return
    pats = [l.strip() for l in open(".dockerignore")
            if l.strip() and not l.startswith("#")]

    def ignored(name: str) -> bool:
        return any(fnmatch.fnmatch(name, p) or fnmatch.fnmatch(name, p.rstrip("/"))
                   for p in pats)

    for must in ("test_main.py", "auth0_test.py", ".env", "private.pem"):
        if ignored(must):
            c.ok(f".dockerignore excludes {must}")
        else:
            c.fail(f".dockerignore does NOT exclude {must} — it would be baked "
                   "into the image")


def check_imports_shipped(c: Check) -> None:
    """Every module the app imports must be COPYed in, and every third-party
    package must be in requirements.txt, or the container dies on first run."""
    dockerignore = [l.strip() for l in open(".dockerignore")
                    if l.strip() and not l.startswith("#")] \
        if os.path.exists(".dockerignore") else []

    def shipped(name: str) -> bool:
        return not any(fnmatch.fnmatch(name, p) or
                       fnmatch.fnmatch(name, p.rstrip("/")) for p in dockerignore)

    local = {f[:-3] for f in os.listdir(".") if f.endswith(".py")}
    stdlib = set(sys.stdlib_module_names)
    reqs = open("requirements.txt").read().lower().replace("-", "") \
        if os.path.exists("requirements.txt") else ""

    # Walk the import graph from main.py through local modules only.
    seen, queue, third = set(), ["main.py"], set()
    missing_local = []
    while queue:
        f = queue.pop()
        if f in seen or not os.path.exists(f):
            continue
        seen.add(f)
        if not shipped(f):
            missing_local.append(f)
            continue
        for node in ast.walk(ast.parse(open(f).read())):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m in local:
                    queue.append(m + ".py")
                elif m not in stdlib:
                    third.add(m)

    if missing_local:
        for m in missing_local:
            c.fail(f"{m} is imported (transitively from main.py) but excluded "
                   "from the image by .dockerignore")
    else:
        c.ok(f"all {len(seen)} local modules reachable from main.py are shipped")

    unmet = [m for m in sorted(third) if m.lower().split("_")[0] not in reqs]
    if unmet:
        for m in unmet:
            c.fail(f"third-party import '{m}' is not in requirements.txt — the "
                   "container would fail at import time")
    else:
        c.ok(f"all {len(third)} third-party imports are in requirements.txt")

    # Beyond the runtime graph above: COPY *.py bakes in EVERY non-ignored .py
    # file, and any one of them run inside the container (e.g. via `exec`) needs
    # its imports satisfiable. A shipped file importing a package not in
    # requirements is a latent ModuleNotFoundError. (This is how a dev tool that
    # imported pyyaml — not a runtime dep — slipped into the image before.)
    shipped_third: dict[str, str] = {}
    for f in os.listdir("."):
        if not f.endswith(".py") or not shipped(f):
            continue
        try:
            tree = ast.parse(open(f).read())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            mods = []
            if isinstance(node, ast.Import):
                mods = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                mods = [node.module.split(".")[0]]
            for m in mods:
                if m not in stdlib and m not in local and \
                        m.lower().split("_")[0] not in reqs:
                    shipped_third.setdefault(m, f)
    if shipped_third:
        for m, f in sorted(shipped_third.items()):
            c.fail(f"shipped file {f} imports '{m}', not in requirements.txt — "
                   f"running it inside the container would crash. Either add the "
                   f"dep or exclude {f} in .dockerignore.")
    else:
        c.ok("every shipped .py file's imports are satisfiable in the image")


def check_twins(c: Check) -> None:
    # A single Dockerfile is the standard, supported setup (Docker's default).
    # A Containerfile is OPTIONAL — only relevant if you also build with Podman
    # using its default filename. If present, it must match Dockerfile so both
    # engines build the same image; if absent, that's fine, not a failure.
    if not os.path.exists("Containerfile"):
        c.ok("single Dockerfile (standard Docker setup; no Containerfile twin)")
        return
    if open("Dockerfile").read() == open("Containerfile").read():
        c.ok("Dockerfile and Containerfile are identical")
    else:
        c.fail("Dockerfile and Containerfile have DIVERGED — the two engines "
               "would build different images")


def check_compose(c: Check) -> None:
    if not os.path.exists("compose.yaml"):
        c.warn("no compose.yaml")
        return
    try:
        import yaml
    except ImportError:
        c.warn("pyyaml not installed; skipping compose checks")
        return
    try:
        conf = yaml.safe_load(open("compose.yaml"))
    except Exception as exc:  # noqa: BLE001
        c.fail(f"compose.yaml is not valid YAML: {exc}")
        return
    c.ok("compose.yaml is valid YAML")
    app = (conf.get("services") or {}).get("app") or {}
    env = app.get("environment") or {}
    if str(env.get("HOST", "")) == "0.0.0.0":
        c.ok("compose: app HOST=0.0.0.0 set explicitly")
    else:
        c.fail("compose: app does not set HOST=0.0.0.0 explicitly — it would "
               "rely on an implicit image ENV, and bind loopback if that ever "
               "changed (healthy but unreachable)")
    if app.get("ports"):
        c.ok(f"compose: app publishes {app['ports']}")


def check_traefik(c: Check) -> None:
    """
    Validate the Traefik ForwardAuth wiring. These are the mistakes that would
    silently break auth or lock you out:
      - /token, /register, /auth/forward NOT public -> you'd need a token to get
        a token (chicken-and-egg lockout).
      - public router priority <= protected -> the protected (catch-all) rule
        wins and gates everything.
      - middleware ref not matching the dynamic-config name/provider.
      - forwardAuth address not pointing at the app's /auth/forward.
    """
    if not os.path.exists("compose.yaml"):
        return
    try:
        import yaml
    except ImportError:
        c.warn("pyyaml not installed; skipping Traefik checks")
        return
    conf = yaml.safe_load(open("compose.yaml"))
    services = conf.get("services") or {}
    if "traefik" not in services:
        return  # Traefik is optional; nothing to check.

    app = services.get("app") or {}
    labels = app.get("labels") or []
    label_map = {}
    for entry in labels:
        if "=" in entry:
            k, v = entry.split("=", 1)
            label_map[k] = v

    pub_rule = label_map.get("traefik.http.routers.app-public.rule", "")
    for must in ("/token", "/register", "/auth/forward", "/health", "/metrics"):
        if must in pub_rule:
            c.ok(f"traefik: {must} is on the public router (no auth-to-get-auth)")
        else:
            c.fail(f"traefik: {must} is NOT public — it would sit behind "
                   "ForwardAuth, so a client would need a token to reach the "
                   "endpoint that issues tokens (lockout)")

    pub_pri = label_map.get("traefik.http.routers.app-public.priority")
    prot_pri = label_map.get("traefik.http.routers.app-protected.priority")
    try:
        if pub_pri and prot_pri and int(pub_pri) > int(prot_pri):
            c.ok(f"traefik: public router priority ({pub_pri}) > protected "
                 f"({prot_pri})")
        else:
            c.fail(f"traefik: public router priority ({pub_pri}) must exceed "
                   f"protected ({prot_pri}), or the catch-all protected rule "
                   "gates the public endpoints")
    except (TypeError, ValueError):
        c.fail("traefik: router priorities must be integers")

    mw = label_map.get("traefik.http.routers.app-protected.middlewares", "")
    if "forward-auth" in mw:
        c.ok("traefik: protected router references the forward-auth middleware")
    else:
        c.fail("traefik: protected router has no forward-auth middleware — it "
               "would not actually require a token")

    # Dynamic config must define the referenced middleware and point at the app.
    dyn = "traefik/dynamic/forward-auth.yml"
    if not os.path.exists(dyn):
        c.fail(f"traefik: {dyn} is missing — the forward-auth middleware is "
               "referenced but never defined")
        return
    d = yaml.safe_load(open(dyn))
    mws = ((d or {}).get("http") or {}).get("middlewares") or {}
    fa = (mws.get("forward-auth") or {}).get("forwardAuth") or {}
    addr = fa.get("address", "")
    if "app:8000" in addr and "/auth/forward" in addr:
        c.ok(f"traefik: forwardAuth address points at the app ({addr})")
    else:
        c.fail(f"traefik: forwardAuth address is wrong ({addr!r}); expected "
               "http://app:8000/auth/forward")


def check_monitoring(c: Check) -> None:
    """Validate the Prometheus + Grafana wiring when present.

    Catches the mistakes that leave you with empty dashboards: Prometheus not
    targeting the right services, or Grafana's provisioning files missing so it
    starts up blank.
    """
    if not os.path.exists("compose.yaml"):
        return
    try:
        import yaml
    except ImportError:
        return
    conf = yaml.safe_load(open("compose.yaml"))
    services = conf.get("services") or {}
    if "prometheus" not in services and "grafana" not in services:
        return  # monitoring is optional; nothing to check

    # Prometheus config must exist and target the three metrics sources.
    prom_cfg = "monitoring/prometheus.yml"
    if not os.path.exists(prom_cfg):
        c.fail(f"monitoring: {prom_cfg} missing — Prometheus has nothing to scrape")
    else:
        pc = yaml.safe_load(open(prom_cfg))
        targets = set()
        for job in pc.get("scrape_configs", []):
            for sc in job.get("static_configs", []):
                for t in sc.get("targets", []):
                    targets.add(t.split(":")[0])
        for svc in ("app", "traefik", "keycloak"):
            if svc in targets:
                c.ok(f"monitoring: Prometheus scrapes {svc}")
            else:
                c.fail(f"monitoring: Prometheus does not target '{svc}' — its "
                       "metrics won't be collected")

    # Grafana provisioning files must exist, or Grafana starts up blank.
    for path, what in [
        ("monitoring/grafana/provisioning/datasources/prometheus.yml",
         "datasource"),
        ("monitoring/grafana/provisioning/dashboards/provider.yml",
         "dashboard provider"),
    ]:
        if os.path.exists(path):
            c.ok(f"monitoring: Grafana {what} provisioning present")
        else:
            c.fail(f"monitoring: Grafana {what} provisioning missing ({path}) — "
                   "Grafana would start blank")

    # The datasource UID the dashboard references must match the datasource.
    ds = "monitoring/grafana/provisioning/datasources/prometheus.yml"
    dash_dir = "monitoring/grafana/provisioning/dashboards"
    if os.path.exists(ds) and os.path.isdir(dash_dir):
        ds_conf = yaml.safe_load(open(ds))
        ds_uids = {d.get("uid") for d in ds_conf.get("datasources", [])}
        import glob
        import json as _json
        for dash in glob.glob(os.path.join(dash_dir, "*.json")):
            body = open(dash).read()
            try:
                _json.loads(body)  # must be valid JSON
            except ValueError:
                c.fail(f"monitoring: {dash} is not valid JSON")
                continue
            # every datasource uid referenced should exist in provisioning
            referenced = set(re.findall(r'"uid":\s*"([^"]+)"', body))
            # dashboard uid itself is also matched; filter to datasource-like refs
            unknown = {u for u in referenced
                       if u not in ds_uids and u != "auth-broker-overview"}
            if unknown:
                c.warn(f"monitoring: {os.path.basename(dash)} references uid(s) "
                       f"{unknown} not in datasource provisioning — panels may "
                       "show 'datasource not found'")
            else:
                c.ok(f"monitoring: {os.path.basename(dash)} datasource uid matches")


def run() -> int:
    print("=" * 68)
    print("CONTAINER BUILD — STATIC CHECK (no engine required)")
    print("=" * 68)
    c = Check()
    print("\n[Dockerfile]")
    check_dockerfile("Dockerfile", c)
    # Containerfile is optional (Podman-only). Check it only if it exists.
    if os.path.exists("Containerfile"):
        print("\n[Containerfile]")
        check_dockerfile("Containerfile", c)
    check_twins(c)
    print("\n[build context]")
    check_dockerignore(c)
    print("\n[imports & dependencies]")
    check_imports_shipped(c)
    print("\n[compose]")
    check_compose(c)
    print("\n[traefik]")
    check_traefik(c)
    print("\n[monitoring]")
    check_monitoring(c)

    print("-" * 68)
    if c.failed:
        print(f"\u2717 {len(c.failed)} problem(s):")
        for f in c.failed:
            print("   - " + f)
        return 1
    if c.warned:
        print(f"({len(c.warned)} warning(s))")
    print("ALL CONTAINER CHECKS PASSED")
    print("\nStatic checks only. Build for real with:")
    print("    docker build -t auth-broker .")
    print("    podman build --format docker -t auth-broker .")
    return 0


if __name__ == "__main__":
    raise SystemExit(run())
