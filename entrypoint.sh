#!/bin/sh
set -eu

python -m contactdav.manage init

gunicorn \
  --bind 127.0.0.1:8000 \
  --workers "${GUNICORN_WORKERS:-2}" \
  --threads "${GUNICORN_THREADS:-4}" \
  --access-logfile - \
  --error-logfile - \
  "contactdav.main:app" &

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

exec caddy run --config /tmp/Caddyfile --adapter caddyfile
