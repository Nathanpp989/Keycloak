# Tests for the Prometheus metrics endpoint and instrumentation.
import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("AUTH0_DOMAIN", "x")
    monkeypatch.setenv("AUTH0_CLIENT_ID", "x")
    monkeypatch.setenv("AUTH0_CLIENT_SECRET", "x")
    monkeypatch.setenv("KEY_DIR", "/tmp/mtest")
    monkeypatch.setenv("KEYCLOAK_REQUIRED", "false")
    import main
    import contextlib

    @contextlib.asynccontextmanager
    async def _noop_lifespan(app):
        yield

    # Skip the real lifespan (which would try to provision Keycloak and hang).
    monkeypatch.setattr(main.app.router, "lifespan_context", _noop_lifespan)
    with TestClient(main.app) as c:
        yield c


def test_metrics_endpoint_returns_prometheus_format(client):
    r = client.get("/metrics")
    assert r.status_code == 200
    assert "text/plain" in r.headers["content-type"]
    # Prometheus format has HELP/TYPE comment lines
    assert "# HELP" in r.text
    assert "# TYPE" in r.text


def test_metrics_records_request_count(client):
    # make a request, then confirm the counter incremented
    client.get("/")
    body = client.get("/metrics").text
    assert 'http_requests_total{' in body
    # the GET / should be recorded with status 200
    assert 'path="/"' in body


def test_metrics_records_latency_histogram(client):
    client.get("/")
    body = client.get("/metrics").text
    assert "http_request_duration_seconds_bucket" in body
    assert "http_request_duration_seconds_count" in body


def test_token_success_metric(monkeypatch):
    # a successful token issuance increments the success counter
    import metrics
    before = metrics.TOKEN_REQUESTS.labels(outcome="success")._value.get()
    metrics.record_token_result("success")
    after = metrics.TOKEN_REQUESTS.labels(outcome="success")._value.get()
    assert after == before + 1


def test_forward_auth_metric(monkeypatch):
    import metrics
    before = metrics.FORWARD_AUTH.labels(decision="deny")._value.get()
    metrics.record_forward_auth("deny")
    after = metrics.FORWARD_AUTH.labels(decision="deny")._value.get()
    assert after == before + 1


def test_metrics_path_uses_route_template_not_raw_path(client):
    # cardinality guard: a 404 to a random path must NOT create a per-path series
    client.get("/some/random/junk/path/12345")
    body = client.get("/metrics").text
    # the junk path must not appear as its own label
    assert "12345" not in body


def test_metrics_endpoint_not_self_recorded(client):
    # Scraping /metrics must NOT count itself — otherwise frequent scrapes
    # dominate http_requests_total and make request-rate dashboards useless.
    for _ in range(3):
        client.get("/metrics")
    body = client.get("/metrics").text
    assert 'path="/metrics"' not in body

def test_health_endpoints_not_recorded(client):
    # Health probes (every 30s) are infrastructure noise, not app traffic.
    client.get("/health/live")
    client.get("/health/ready")
    body = client.get("/metrics").text
    assert 'path="/health/live"' not in body
    assert 'path="/health/ready"' not in body

def test_real_traffic_still_recorded_alongside_excluded(client):
    # The exclusion must not accidentally drop real traffic.
    client.get("/")
    client.get("/metrics")   # excluded
    body = client.get("/metrics").text
    assert 'path="/"' in body   # real traffic present
