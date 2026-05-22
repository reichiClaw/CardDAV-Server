from __future__ import annotations

import base64
import importlib


def auth(username: str, password: str) -> dict[str, str]:
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def load_app(monkeypatch, tmp_path):
    monkeypatch.setenv("CONTACT_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CONTACT_ADMIN_USER", "admin")
    monkeypatch.setenv("CONTACT_ADMIN_PASSWORD", "admin-pass")
    module = importlib.import_module("contactdav.main")
    module = importlib.reload(module)
    module.store.create_user("employee", "employee-pass", "employee")
    return module.app, module.store


def test_employee_can_read_but_not_write(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    store.save_contact(
        {
            "uid": "jane-smith",
            "first_name": "Jane",
            "last_name": "Smith",
            "display_name": "Jane Smith",
            "organization": "Example GmbH",
            "phone_mobile": "+491711234567",
            "email": "jane@example.com",
        }
    )

    client = app.test_client()
    response = client.get("/dav/employee/contacts/jane-smith.vcf", headers=auth("employee", "employee-pass"))
    assert response.status_code == 200
    assert b"FN:Jane Smith" in response.data

    response = client.put(
        "/dav/employee/contacts/jane-smith.vcf",
        headers=auth("employee", "employee-pass"),
        data="BEGIN:VCARD\r\nVERSION:3.0\r\nFN:Changed\r\nEND:VCARD\r\n",
    )
    assert response.status_code == 403


def test_propfind_exposes_addressbook(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.open(
        "/dav/",
        method="PROPFIND",
        headers={**auth("admin", "admin-pass"), "Depth": "1"},
        data="""<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal />
  </D:prop>
</D:propfind>""",
    )
    assert response.status_code == 207
    assert b"/dav/admin/" in response.data


def test_admin_can_write_vcard(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.put(
        "/dav/admin/contacts/max.vcf",
        headers=auth("admin", "admin-pass"),
        data=(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:max\r\nFN:Max Example\r\n"
            "N:Example;Max;;;\r\nTEL;TYPE=CELL:+491700000\r\nEND:VCARD\r\n"
        ),
    )
    assert response.status_code == 201
    assert store.get_contact("max")["display_name"] == "Max Example"

