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

    response = client.delete(
        "/dav/employee/contacts/jane-smith.vcf",
        headers=auth("employee", "employee-pass"),
    )
    assert response.status_code == 403
    assert store.get_contact("jane-smith") is not None


def test_employee_options_hides_write_methods(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()

    employee = client.open("/dav/employee/contacts/", method="OPTIONS", headers=auth("employee", "employee-pass"))
    assert employee.status_code == 204
    assert "PUT" not in employee.headers["Allow"]
    assert "DELETE" not in employee.headers["Allow"]
    assert "PROPFIND" in employee.headers["Allow"]

    admin = client.open("/dav/admin/contacts/", method="OPTIONS", headers=auth("admin", "admin-pass"))
    assert "PUT" in admin.headers["Allow"]
    assert "DELETE" in admin.headers["Allow"]


def test_propfind_exposes_addressbook_and_privileges(monkeypatch, tmp_path):
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
    <D:current-user-privilege-set />
  </D:prop>
</D:propfind>""",
    )
    assert response.status_code == 207
    assert b"/dav/admin/" in response.data
    assert b"current-user-privilege-set" in response.data
    assert b"<D:write" in response.data or b"{DAV:}write" in response.data or b"write" in response.data

    employee = client.open(
        "/dav/employee/contacts/",
        method="PROPFIND",
        headers={**auth("employee", "employee-pass"), "Depth": "0"},
        data="""<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-privilege-set />
  </D:prop>
</D:propfind>""",
    )
    assert employee.status_code == 207
    assert b"<D:read" in employee.data or b"read" in employee.data
    assert b"<D:write" not in employee.data


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
    assert response.headers["Location"].endswith("/dav/admin/contacts/max.vcf")
    assert store.get_contact("max")["display_name"] == "Max Example"


def test_put_forces_path_uid_and_honors_if_match(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    create = client.put(
        "/dav/admin/contacts/path-uid.vcf",
        headers={**auth("admin", "admin-pass"), "If-None-Match": "*"},
        data="BEGIN:VCARD\r\nVERSION:3.0\r\nUID:body-uid\r\nFN:Path Wins\r\nEND:VCARD\r\n",
    )
    assert create.status_code == 201
    assert store.get_contact("path-uid") is not None
    assert store.get_contact("body-uid") is None

    etag = create.headers["ETag"]
    stale = client.put(
        "/dav/admin/contacts/path-uid.vcf",
        headers={**auth("admin", "admin-pass"), "If-Match": '"deadbeef"'},
        data="BEGIN:VCARD\r\nVERSION:3.0\r\nUID:path-uid\r\nFN:Stale\r\nEND:VCARD\r\n",
    )
    assert stale.status_code == 412

    update = client.put(
        "/dav/admin/contacts/path-uid.vcf",
        headers={**auth("admin", "admin-pass"), "If-Match": etag},
        data="BEGIN:VCARD\r\nVERSION:3.0\r\nUID:path-uid\r\nFN:Fresh\r\nEND:VCARD\r\n",
    )
    assert update.status_code == 204
    assert store.get_contact("path-uid")["display_name"] == "Fresh"

    conflict = client.put(
        "/dav/admin/contacts/path-uid.vcf",
        headers={**auth("admin", "admin-pass"), "If-None-Match": "*"},
        data="BEGIN:VCARD\r\nVERSION:3.0\r\nUID:path-uid\r\nFN:Nope\r\nEND:VCARD\r\n",
    )
    assert conflict.status_code == 412


def test_path_username_must_match_authenticated_user(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    store.save_contact({"uid": "shared", "display_name": "Shared"})
    client = app.test_client()
    response = client.get("/dav/admin/contacts/shared.vcf", headers=auth("employee", "employee-pass"))
    assert response.status_code == 404


def test_sync_collection_returns_delete_tombstones(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    store.save_contact({"uid": "keep", "display_name": "Keep"})
    store.save_contact({"uid": "gone", "display_name": "Gone"})
    token_before_delete = store.collection_token()

    assert store.delete_contact("gone") is True
    client = app.test_client()
    response = client.open(
        "/dav/employee/contacts/",
        method="REPORT",
        headers=auth("employee", "employee-pass"),
        data=f"""<?xml version="1.0"?>
<D:sync-collection xmlns:D="DAV:">
  <D:sync-token>{token_before_delete}</D:sync-token>
  <D:sync-level>1</D:sync-level>
  <D:prop><D:getetag/></D:prop>
</D:sync-collection>""",
    )
    assert response.status_code == 207
    assert b"gone.vcf" in response.data
    assert b"404 Not Found" in response.data
    assert store.collection_token().encode() in response.data


def test_multiget_returns_404_for_missing_contacts(monkeypatch, tmp_path):
    app, store = load_app(monkeypatch, tmp_path)
    store.save_contact({"uid": "present", "display_name": "Present"})
    client = app.test_client()
    response = client.open(
        "/dav/employee/contacts/",
        method="REPORT",
        headers=auth("employee", "employee-pass"),
        data="""<?xml version="1.0"?>
<C:addressbook-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:carddav">
  <D:prop><D:getetag/><C:address-data/></D:prop>
  <D:href>/dav/employee/contacts/present.vcf</D:href>
  <D:href>/dav/employee/contacts/missing.vcf</D:href>
</C:addressbook-multiget>""",
    )
    assert response.status_code == 207
    assert b"FN:Present" in response.data
    assert b"missing.vcf" in response.data
    assert b"404 Not Found" in response.data


def test_well_known_carddav_redirects(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.get("/.well-known/carddav", headers=auth("employee", "employee-pass"))
    assert response.status_code == 301
    assert response.headers["Location"].endswith("/dav/")


def test_root_propfind_discovers_principal(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.open(
        "/",
        method="PROPFIND",
        headers={**auth("employee", "employee-pass"), "Depth": "0"},
        data="""<?xml version="1.0"?>
<D:propfind xmlns:D="DAV:">
  <D:prop><D:current-user-principal/></D:prop>
</D:propfind>""",
    )
    assert response.status_code == 207
    assert b"/dav/employee/" in response.data


def test_invalid_sync_token_rejected(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.open(
        "/dav/employee/contacts/",
        method="REPORT",
        headers=auth("employee", "employee-pass"),
        data="""<?xml version="1.0"?>
<D:sync-collection xmlns:D="DAV:">
  <D:sync-token>not-a-real-token</D:sync-token>
  <D:prop><D:getetag/></D:prop>
</D:sync-collection>""",
    )
    assert response.status_code == 403
    assert b"valid-sync-token" in response.data


def test_delete_missing_contact_is_404(monkeypatch, tmp_path):
    app, _store = load_app(monkeypatch, tmp_path)
    client = app.test_client()
    response = client.delete("/dav/admin/contacts/nope.vcf", headers=auth("admin", "admin-pass"))
    assert response.status_code == 404
