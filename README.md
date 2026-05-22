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
- Employee accounts are server-side read-only.
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
