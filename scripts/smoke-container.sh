#!/usr/bin/env bash
# Exercise the packaged app against a disposable database and loopback Redis.
set -euo pipefail

image=${1:?Usage: bash scripts/smoke-container.sh IMAGE}
container="fief-smoke-${RANDOM}-$$"
cleanup() {
    result=$?
    if (( result != 0 )); then
        docker logs "$container" >&2 || true
    fi
    docker rm -f -v "$container" >/dev/null 2>&1 || true
    exit "$result"
}
trap cleanup EXIT

# These credentials are only for this short-lived container, which publishes no ports.
docker run -d --name "$container" \
    -e ENVIRONMENT=development -e TELEMETRY_ENABLED=false \
    -e SENTRY_DSN_SERVER= -e SENTRY_DSN_WORKER= \
    -e SECRET=fief-container-smoke-only \
    -e ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
    -e MFA_SECRET_ENCRYPTION_KEY=MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWY= \
    -e DATABASE_TYPE=SQLITE -e DATABASE_NAME=smoke.db \
    -e FIEF_DOMAIN=localhost:8000 \
    -e FIEF_CLIENT_ID=FiefClientID -e FIEF_CLIENT_SECRET=FiefClientSecret \
    -e FIEF_MAIN_USER_EMAIL=admin@example.com \
    -e FIEF_MAIN_USER_PASSWORD=fief-test-correct-horse-battery-staple \
    -e BREACHED_PASSWORD_CHECK_ENABLED=false \
    "$image" >/dev/null

ready=false
for ((attempt = 0; attempt < 60; attempt++)); do
    if docker exec "$container" python -c \
        'from urllib.request import urlopen; urlopen("http://localhost:8000/healthz", timeout=2)' \
        >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 2
done
if [[ "$ready" != true ]]; then
    echo "Container did not become ready within two minutes" >&2
    exit 1
fi

docker exec -i "$container" python - <<'PY'
from urllib.request import urlopen

from fief import tasks

for path in ("/login", "/static/admin.css", "/static/auth.css",
             "/static/dependencies.bundle.js", "/static/webauthn.bundle.js",
             "/static/code-editor.bundle.js"):
    with urlopen(f"http://localhost:8000{path}", timeout=5) as response:
        assert response.status == 200, path
        assert response.read(), path

# Joining the real Redis queue also verifies that the packaged worker processes jobs.
tasks.cleanup.send()
tasks.cleanup.broker.join(tasks.cleanup.queue_name, timeout=30000)
print("Container startup, migrations, login, static assets, and worker checks passed.")
PY
