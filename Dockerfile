# Containerfile — builds an image for the Keycloak+Auth0 broker API.
#
# This file uses only standard, OCI-compliant instructions, so it builds
# identically with either engine:
#     docker build -t auth-broker .
#     podman build --format docker -t auth-broker .
#
# NOTE (Podman): the default OCI image format does not store HEALTHCHECK, and
# podman will warn and ignore it. Build with `--format docker` (as above) to
# keep the healthcheck, or supply one at run time with `--health-cmd`.
#
# (Podman reads "Containerfile" by default; Docker reads "Dockerfile". A
#  Dockerfile is included too — it's a copy of this file — so both engines work
#  with no extra flags.)

FROM python:3.12-slim

# Don't write .pyc files; unbuffer stdout/stderr so logs stream in real time.
# App defaults below can be overridden at run time with -e / --env-file.
# NOTE: no comments inside this continuation — some builders (older Docker,
# certain buildah versions) do not strip them, which would silently truncate
# the ENV and drop KEY_DIR. Keep comments above the instruction.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HOST=0.0.0.0 \
    PORT=8000 \
    KEY_DIR=/data/keys

WORKDIR /app

# Install dependencies first (better layer caching: deps change less than code).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the application code.
COPY *.py ./

# Run as a non-root user. Create the writable key directory and hand it to that
# user, so the app can write private.pem (0600) without needing root. This works
# the same under Docker and rootless Podman.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p ${KEY_DIR} \
    && chown -R appuser:appuser ${KEY_DIR} /app
USER appuser

EXPOSE 8000

# A simple healthcheck hitting the public root endpoint. Docker runs this
# natively; Podman honours it when the image is run with --health-cmd or via
# podman play. Kept dependency-free (uses Python's stdlib urllib).
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/').status==200 else 1)"

# Start the API. main.py reads HOST/PORT from the environment.
CMD ["python", "main.py"]
