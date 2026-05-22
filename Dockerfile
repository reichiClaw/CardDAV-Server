FROM caddy:2-alpine AS caddy

FROM python:3.12-alpine

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app \
    CONTACT_DATA_DIR=/data \
    XDG_CONFIG_HOME=/data/caddy-config \
    XDG_DATA_HOME=/data/caddy-data

WORKDIR /app

COPY --from=caddy /usr/bin/caddy /usr/bin/caddy
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY app/ /app/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh && mkdir -p /data

VOLUME ["/data"]
EXPOSE 80 443 8080

ENTRYPOINT ["/entrypoint.sh"]
