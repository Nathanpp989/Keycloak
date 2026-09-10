#!/usr/bin/env python3
# metrics.py
# Prometheus metrics for the broker.
#
# Exposes a /metrics endpoint (wired in main.py) in the Prometheus text format,
# plus a middleware that records request count and latency for every request.
# Auth-specific counters (token issuance outcomes) are incremented from the
# relevant endpoints.
#
# Why prometheus_client rather than hand-rolling: the text exposition format has
# subtle rules (histogram buckets, label escaping, thread-safety) that a scraper
# depends on. The library gets these right; reinventing them invites format bugs
# that only surface when Prometheus rejects the payload.
#
# For a single-host compose deployment this runs in one process, so the default
# in-process registry is correct. (If you later run multiple app workers, switch
# to prometheus_client's multiprocess mode — noted in the README.)

from __future__ import annotations

import time

from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST

# ── HTTP request metrics ────────────────────────────────────────────────────
# Count every request by method, path template, and status. Using the ROUTE
# TEMPLATE (not the raw path) keeps cardinality bounded — /users/{id} is one
# series, not one per user id.
REQUESTS = Counter(
    "http_requests_total",
    "Total HTTP requests",
    ["method", "path", "status"],
)

# Latency distribution per method+path. Histograms let you compute p50/p95/p99
# in Prometheus. Default buckets are tuned for typical web latencies.
LATENCY = Histogram(
    "http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path"],
)

# ── Auth-specific metrics ───────────────────────────────────────────────────
# Token issuance outcomes — the single most operationally useful auth signal.
# A spike in 'failure' means credentials, Keycloak, or brokering is broken.
TOKEN_REQUESTS = Counter(
    "auth_token_requests_total",
    "Token issuance attempts by outcome",
    ["outcome"],   # "success" | "invalid_credentials" | "error"
)

# ForwardAuth decisions — how often the gateway allows vs denies.
FORWARD_AUTH = Counter(
    "auth_forward_decisions_total",
    "Traefik ForwardAuth decisions",
    ["decision"],   # "allow" | "deny"
)


def record_token_result(outcome: str) -> None:
    """Increment the token-issuance counter. outcome in
    {success, invalid_credentials, error}."""
    TOKEN_REQUESTS.labels(outcome=outcome).inc()


def record_forward_auth(decision: str) -> None:
    """Increment the ForwardAuth decision counter. decision in {allow, deny}."""
    FORWARD_AUTH.labels(decision=decision).inc()


def _route_template(request) -> str:
    """Return the matched route template (e.g. '/users/{id}') rather than the
    concrete path, to keep metric cardinality bounded. Falls back to the raw
    path if no route matched (e.g. a 404)."""
    route = request.scope.get("route")
    if route is not None and getattr(route, "path", None):
        return route.path
    # Unmatched — bucket all unknowns under a single label to avoid unbounded
    # cardinality from random 404-probing paths.
    return "__unmatched__"


# Paths that are infrastructure noise, not application traffic: the metrics
# scrape (every 15s) and health probes (every 30s) would otherwise dominate
# http_requests_total and make request-rate dashboards meaningless. We skip
# recording them. (They still work; they're just not counted as app traffic.)
_EXCLUDED_PATHS = frozenset({"/metrics", "/health/live", "/health/ready"})


async def metrics_middleware(request, call_next):
    """Record request count and latency for every request.

    Timing wraps the downstream handler. The path label uses the route template
    so cardinality stays bounded regardless of path parameters or junk URLs.
    Observability endpoints (see _EXCLUDED_PATHS) are not recorded, so frequent
    scrapes/probes don't drown out real application traffic in the metrics.
    """
    # request.url.path is the concrete path; the excluded set is exact paths.
    if request.url.path in _EXCLUDED_PATHS:
        return await call_next(request)
    start = time.perf_counter()
    status = 500
    try:
        response = await call_next(request)
        status = response.status_code
        return response
    finally:
        elapsed = time.perf_counter() - start
        path = _route_template(request)
        method = request.method
        REQUESTS.labels(method=method, path=path, status=str(status)).inc()
        LATENCY.labels(method=method, path=path).observe(elapsed)

# Metrics endpoint handler — returns the Prometheus text format for scraping.

def metrics_endpoint():
    """Return a FastAPI endpoint handler for /metrics."""
    from fastapi.responses import Response
    body, content_type = render_metrics()
    return Response(content=body, media_type=content_type)


def render_metrics() -> tuple[bytes, str]:
    """Return (body, content_type) for the /metrics endpoint."""
    return generate_latest(), CONTENT_TYPE_LATEST
