# Simple Company Contacts CardDAV Server

One Docker container for a company-wide contact directory:

- iOS-compatible CardDAV sync
- Android sync through DAVx5 or another CardDAV client
- One central address book for all employees
- Employees can read/sync contacts but cannot change the server copy
- Admins can add, edit, delete, import, and export contacts
- Caddy is included in the same container for automatic trusted HTTPS certificates

The design goal is simple and reliable: use a real public DNS name and let Caddy get a
Let's Encrypt certificate. This avoids the most common iPhone sync failure: self-signed
or incomplete certificates.

## What you get

```text
Browser admin UI  --->  https://contacts.example.com/admin
iOS CardDAV       --->  https://contacts.example.com/dav/<username>/contacts/
Android CardDAV   --->  same URL, usually with DAVx5
```

Employee accounts are read-only at the server. If a phone or app tries to upload,
change, or delete a contact, the server returns `403 Forbidden`.

## Quick start

### 1. Prepare DNS

Create a DNS record for the server, for example:

```text
contacts.example.com  A  <your-server-public-ip>
```

For iOS, use a real domain with a publicly trusted certificate. Do not use a self-signed
certificate unless you also install and trust your own CA profile on every iPhone.

### 2. Open firewall ports

Open these ports to the internet:

```text
80/tcp
443/tcp
```

Port 80 is required for the first Let's Encrypt HTTP challenge. Port 443 is used for
normal secure sync.

### 3. Create `.env`

```bash
CONTACT_DOMAIN=contacts.example.com
ACME_EMAIL=admin@example.com
CONTACT_ADMIN_USER=admin
CONTACT_ADMIN_PASSWORD=replace-with-a-long-random-password

# Optional: create one first employee account at startup.
CONTACT_EMPLOYEE_USER=employee
CONTACT_EMPLOYEE_PASSWORD=replace-with-another-long-random-password
```

### 4. Start

```bash
docker compose up -d --build
```

Check logs:

```bash
docker compose logs -f
```

Caddy will automatically request and renew the HTTPS certificate for
`CONTACT_DOMAIN`.

### 5. Open the admin UI

Go to:

```text
https://contacts.example.com/admin
```

Log in with `CONTACT_ADMIN_USER` and `CONTACT_ADMIN_PASSWORD`.

From the admin UI you can:

- add contacts
- edit contacts
- delete contacts from sync
- import CSV
- export CSV
- create employee read-only users
- create additional admins


## Install behind an existing reverse proxy

Use this mode if you already have nginx, Traefik, Caddy, Apache, Nginx Proxy
Manager, Cloudflare Tunnel, or another reverse proxy on the host.

In this setup the external reverse proxy handles the public HTTPS certificate.
The contacts container only listens on local HTTP port `8080`.

```text
iPhone / Android
      |
      | https://contacts.example.com
      v
Existing reverse proxy with trusted certificate
      |
      | http://127.0.0.1:8080
      v
company-contacts container
```

### 1. DNS and certificate

Point DNS to the server or tunnel endpoint that runs your reverse proxy:

```text
contacts.example.com  A  <reverse-proxy-public-ip>
```

Your reverse proxy must serve a publicly trusted certificate for exactly the
same hostname that users enter on the phone:

```text
contacts.example.com
```

For iOS, first test this in Safari on the phone:

```text
https://contacts.example.com/admin
```

If Safari shows a certificate warning, CardDAV sync will usually fail too.
Fix the certificate before configuring the Contacts account.

### 2. Configure `.env` for reverse-proxy mode

Leave `CONTACT_DOMAIN` empty. This disables the container's public HTTPS mode
and makes the included Caddy listen on plain HTTP port `8080` instead.

```bash
CONTACT_DOMAIN=
ACME_EMAIL=
CONTACT_ADMIN_USER=admin
CONTACT_ADMIN_PASSWORD=replace-with-a-long-random-password
CONTACT_EMPLOYEE_USER=employee
CONTACT_EMPLOYEE_PASSWORD=replace-with-another-long-random-password
```

### 3. Bind the container only to localhost

For a reverse-proxy installation, expose only local port `8080` and do not
publish container ports `80` and `443` directly to the internet.

`8080` is already bound to `127.0.0.1` in `docker-compose.yml`. Remove or
comment the public `80`/`443` mappings in reverse-proxy mode:

```yaml
ports:
  # - "80:80"
  # - "443:443"
  - "127.0.0.1:8080:8080"
```

Then start the container:

```bash
docker compose up -d --build
```

Test from the server itself:

```bash
curl -I http://127.0.0.1:8080/health
```

Expected result:

```text
HTTP/1.1 200 OK
```

### 4. Reverse proxy requirements

The reverse proxy must:

- proxy the site at the domain root, not under a subpath
- forward all paths unchanged, especially `/dav/`
- allow WebDAV/CardDAV methods: `OPTIONS`, `GET`, `HEAD`, `PROPFIND`, `REPORT`,
  `PUT`, and `DELETE`
- forward the `Authorization` header for Basic Auth
- keep HTTPS enabled on the public side
- avoid changing or stripping trailing slashes

Use this public URL:

```text
https://contacts.example.com
```

Do not publish it as:

```text
https://example.com/contacts
```

CardDAV clients, especially iOS, are more reliable when the service is mounted
at the domain root.

### 5. nginx example

```nginx
server {
    listen 80;
    server_name contacts.example.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name contacts.example.com;

    ssl_certificate /etc/letsencrypt/live/contacts.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/contacts.example.com/privkey.pem;

    client_max_body_size 20m;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;

        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header Authorization $http_authorization;
    }
}
```

Reload nginx after changing the config:

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 6. Caddy reverse proxy example

This is for an external Caddy instance on the host, not the Caddy inside the
container.

```caddyfile
contacts.example.com {
    reverse_proxy 127.0.0.1:8080
}
```

Caddy will automatically issue and renew the public certificate.

### 7. Traefik example labels

If Traefik is your public reverse proxy, remove direct `ports:` from the
contacts service and attach it to the Traefik network. Example labels:

```yaml
labels:
  - "traefik.enable=true"
  - "traefik.http.routers.company-contacts.rule=Host(`contacts.example.com`)"
  - "traefik.http.routers.company-contacts.entrypoints=websecure"
  - "traefik.http.routers.company-contacts.tls.certresolver=letsencrypt"
  - "traefik.http.services.company-contacts.loadbalancer.server.port=8080"
```

### 8. Nginx Proxy Manager checklist

In Nginx Proxy Manager create a new Proxy Host:

```text
Domain Names: contacts.example.com
Scheme: http
Forward Hostname / IP: host.docker.internal or the Docker host IP
Forward Port: 8080
Websockets Support: optional
Block Common Exploits: off if PROPFIND/REPORT are blocked
SSL Certificate: request a new Let's Encrypt certificate
Force SSL: on
HTTP/2 Support: on
```

If Nginx Proxy Manager runs in Docker on Linux, `127.0.0.1` points to the NPM
container itself, not the Docker host. Use one of these instead:

- the Docker host LAN IP
- a shared Docker network and the service name `company-contacts`
- `host.docker.internal` if configured for your Docker installation

### 9. Reverse-proxy troubleshooting for iOS

Check from a computer:

```bash
curl -I https://contacts.example.com/health
curl -u employee:employee-password -X PROPFIND https://contacts.example.com/dav/ -H 'Depth: 1'
```

The first command should return `200 OK`. The second should return `207
MULTI-STATUS` after successful authentication.

If iOS still fails:

1. Open `https://contacts.example.com/admin` in Safari on the iPhone and confirm
   there is no certificate warning.
2. Confirm the reverse proxy forwards `Authorization`.
3. Confirm `PROPFIND` and `REPORT` are not blocked by a WAF/security rule.
4. Confirm the service is mounted at `/`, not a subpath.
5. Confirm the public URL redirects HTTP to HTTPS, but does not redirect
   `/dav/` to another hostname.
6. Check container logs with `docker compose logs -f contacts` while adding the
   CardDAV account on the phone.

## iPhone / iPad setup

On iOS:

```text
Settings
  > Apps
  > Contacts
  > Contacts Accounts
  > Add Account
  > Other
  > Add CardDAV Account
```

Use:

```text
Server: contacts.example.com
User Name: employee username
Password: employee password
Description: Company Contacts
```

If iOS does not discover the address book automatically, use the full URL as the server:

```text
contacts.example.com/dav/<username>/contacts/
```

Replace `<username>` with the employee account name.

### iOS certificate checklist

If iOS refuses to sync, check these first:

1. `https://contacts.example.com/admin` opens in Safari without a certificate warning.
2. DNS points to the server running the container.
3. Ports 80 and 443 are reachable from the internet.
4. `CONTACT_DOMAIN` exactly matches the DNS name used on the phone.
5. There is no old reverse proxy presenting a different certificate in front of this container.
6. The phone date/time is correct.

## Android setup

Most Android phones need a CardDAV sync app. The recommended option is DAVx5.

In DAVx5:

```text
Login with URL and user name
Base URL: https://contacts.example.com/dav/<username>/contacts/
User name: employee username
Password: employee password
```

Select the `Company Contacts` address book and enable contact sync.

## Admin CSV import format

The import box expects a CSV header row. Supported columns:

```csv
uid,first_name,last_name,display_name,organization,department,title,email,phone_work,phone_mobile,phone_other,notes
```

Example:

```csv
uid,first_name,last_name,display_name,organization,department,title,email,phone_work,phone_mobile,phone_other,notes
jane-smith,Jane,Smith,Jane Smith,Example GmbH,Sales,Account Manager,jane@example.com,+4930123456,+491711234567,,
```

If `uid` is empty, the server creates one. Keep stable `uid` values for CSV imports so
future imports update existing contacts instead of creating duplicates.

## Local test mode

If `CONTACT_DOMAIN` is empty, the container listens on plain HTTP port 8080:

```bash
CONTACT_ADMIN_PASSWORD=dev-password docker compose up --build
```

Then open:

```text
http://localhost:8080/admin
```

Use local mode only for testing. iOS production sync should use HTTPS with a trusted
certificate.

## Backups

All persistent data is in the Docker volume `company-contacts-data`, including:

- SQLite contact/user database
- Caddy certificates and renewal data
- admin secret key

Back up the volume regularly.

Example manual backup:

```bash
docker run --rm \
  -v company-contacts-data:/data \
  -v "$PWD:/backup" \
  alpine \
  tar czf /backup/contacts-data-backup.tgz /data
```

Restore by stopping the container and extracting the archive back into the volume.

## Security notes

- Use one account per employee or per device group.
- Use long random passwords.
- Keep admin credentials separate from employee sync credentials.
- Employee accounts are server-side read-only: CardDAV `PUT`/`DELETE` return `403`, `OPTIONS` omits write methods, and WebDAV privileges advertise read-only access.
- Admin writes honor `If-Match` / `If-None-Match` to avoid silent overwrites.
- Deleted contacts are soft-deleted and published as CardDAV sync tombstones so phones drop them.
- Port `8080` is bound to `127.0.0.1` for local/reverse-proxy mode; do not publish it publicly without TLS.
- Delete old employee accounts when people leave.
- Keep the host and Docker updated.
- Do not expose the SQLite database directly.

## CardDAV endpoints

For a user named `employee`:

```text
Discovery/root:  https://contacts.example.com/dav/
Principal:       https://contacts.example.com/dav/employee/
Address book:    https://contacts.example.com/dav/employee/contacts/
Contact vCards:  https://contacts.example.com/dav/employee/contacts/<uid>.vcf
```

Every user sees the same central company directory. Admin users may also write via
CardDAV clients, while employee users are denied all CardDAV writes.
