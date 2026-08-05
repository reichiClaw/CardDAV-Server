#!/bin/sh
set -eu

python -m contactdav.manage init

gunicorn \
  --bind 127.0.0.1:8000 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --timeout "${GUNICORN_TIMEOUT:-60}" \
  --access-logfile - \
  --error-logfile - \
  "contactdav.main:app" &
GUNICORN_PID=$!

cleanup() {
  kill "$GUNICORN_PID" 2>/dev/null || true
  if [ -n "${CADDY_PID:-}" ]; then
    kill "$CADDY_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
}
trap cleanup INT TERM EXIT

# Wait until the app accepts health checks before starting the proxy.
i=0
while [ "$i" -lt 30 ]; do
  if python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).read()" >/dev/null 2>&1; then
    break
  fi
  if ! kill -0 "$GUNICORN_PID" 2>/dev/null; then
    echo "gunicorn exited before becoming healthy" >&2
    exit 1
  fi
  i=$((i + 1))
  sleep 0.5
done

if [ -n "${CONTACT_DOMAIN:-}" ]; then
  {
    if [ -n "${ACME_EMAIL:-}" ]; then
      printf "{\n  email %s\n}\n\n" "$ACME_EMAIL"
    fi
    printf "%s {\n" "$CONTACT_DOMAIN"
    printf "  encode zstd gzip\n"
    printf "  reverse_proxy 127.0.0.1:8000\n"
    printf "}\n"
  } > /tmp/Caddyfile
else
  cat > /tmp/Caddyfile <<'EOF'
:8080 {
  encode zstd gzip
  reverse_proxy 127.0.0.1:8000
}
EOF
fi

caddy run --config /tmp/Caddyfile --adapter caddyfile &
CADDY_PID=$!

# Exit the container if either process dies.
while kill -0 "$GUNICORN_PID" 2>/dev/null && kill -0 "$CADDY_PID" 2>/dev/null; do
  sleep 1
done

echo "backing process exited; shutting down" >&2
exit 1
