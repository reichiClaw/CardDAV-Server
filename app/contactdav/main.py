from __future__ import annotations

import csv
import hmac
import io
import os
from functools import wraps
from hashlib import sha256
from pathlib import Path
from urllib.parse import quote, unquote
from xml.etree import ElementTree as ET

from flask import Flask, Response, abort, make_response, redirect, render_template_string, request, url_for

from .security import data_dir
from .storage import CONTACT_FIELDS, Store
from .vcard import contact_to_vcard, etag_for_vcard, parse_vcard

D = "DAV:"
C = "urn:ietf:params:xml:ns:carddav"
CS = "http://calendarserver.org/ns/"

ET.register_namespace("D", D)
ET.register_namespace("C", C)
ET.register_namespace("CS", CS)


def q(namespace: str, name: str) -> str:
    return f"{{{namespace}}}{name}"


def local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def make_app_store() -> Store:
    return Store(data_dir() / "contacts.sqlite3")


store = make_app_store()
store.init()
store.bootstrap_from_env()


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SECRET_KEY"] = load_secret_key()
    register_routes(app)
    return app


def load_secret_key() -> str:
    configured = os.environ.get("CONTACT_SECRET_KEY")
    if configured:
        return configured
    path = data_dir() / "secret.key"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    secret = os.urandom(32).hex()
    path.write_text(secret, encoding="utf-8")
    return secret


def auth_challenge() -> Response:
    response = Response("Authentication required", 401)
    response.headers["WWW-Authenticate"] = 'Basic realm="Company Contacts"'
    return response


def current_user() -> dict | None:
    auth = request.authorization
    if not auth or not auth.username or auth.password is None:
        return None
    return store.verify_user(auth.username, auth.password)


def require_user(role: str | None = None):
    user = current_user()
    if not user:
        return None, auth_challenge()
    if role and user["role"] != role:
        return None, Response("Forbidden", 403)
    return user, None


def require_admin(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        user, error = require_user("admin")
        if error:
            return error
        return view(user, *args, **kwargs)

    return wrapped


def csrf_token(username: str) -> str:
    return hmac.new(
        app.config["SECRET_KEY"].encode("utf-8"),
        username.encode("utf-8"),
        sha256,
    ).hexdigest()


def validate_csrf(user: dict) -> None:
    token = request.form.get("csrf", "")
    if not hmac.compare_digest(token, csrf_token(user["username"])):
        abort(400, "Invalid CSRF token")


def xml_response(root: ET.Element, status: int = 207) -> Response:
    body = ET.tostring(root, encoding="utf-8", xml_declaration=True)
    return Response(body, status=status, content_type="application/xml; charset=utf-8")


def href(value: str) -> ET.Element:
    element = ET.Element(q(D, "href"))
    element.text = value
    return element


def prop_element(tag: str, text: str | None = None) -> ET.Element:
    element = ET.Element(tag)
    if text is not None:
        element.text = text
    return element


def resourcetype(*types: str) -> ET.Element:
    element = ET.Element(q(D, "resourcetype"))
    for item in types:
        namespace = C if item == "addressbook" else D
        ET.SubElement(element, q(namespace, item))
    return element


def href_property(tag: str, target: str) -> ET.Element:
    element = ET.Element(tag)
    element.append(href(target))
    return element


def supported_report_set() -> ET.Element:
    element = ET.Element(q(D, "supported-report-set"))
    for namespace, name in [(C, "addressbook-query"), (C, "addressbook-multiget")]:
        supported = ET.SubElement(element, q(D, "supported-report"))
        report = ET.SubElement(supported, q(D, "report"))
        ET.SubElement(report, q(namespace, name))
    return element


def supported_address_data() -> ET.Element:
    element = ET.Element(q(C, "supported-address-data"))
    child = ET.SubElement(element, q(C, "address-data-type"))
    child.set("content-type", "text/vcard")
    child.set("version", "3.0")
    return element


def parse_requested_props() -> set[str] | None:
    body = request.get_data()
    if not body:
        return None
    try:
        root = ET.fromstring(body)
    except ET.ParseError:
        return None
    if root.find(q(D, "allprop")) is not None:
        return None
    prop = root.find(q(D, "prop"))
    if prop is None:
        return None
    return {child.tag for child in list(prop)}


def add_propstat(response: ET.Element, ok_props: list[ET.Element], missing: list[str] | None = None) -> None:
    if ok_props:
        propstat = ET.SubElement(response, q(D, "propstat"))
        prop = ET.SubElement(propstat, q(D, "prop"))
        for item in ok_props:
            prop.append(item)
        ET.SubElement(propstat, q(D, "status")).text = "HTTP/1.1 200 OK"
    if missing:
        propstat = ET.SubElement(response, q(D, "propstat"))
        prop = ET.SubElement(propstat, q(D, "prop"))
        for tag in missing:
            ET.SubElement(prop, tag)
        ET.SubElement(propstat, q(D, "status")).text = "HTTP/1.1 404 Not Found"


def response_for(href_value: str, available: dict[str, ET.Element], requested: set[str] | None) -> ET.Element:
    response = ET.Element(q(D, "response"))
    response.append(href(href_value))
    if requested is None:
        add_propstat(response, list(available.values()))
    else:
        add_propstat(
            response,
            [available[tag] for tag in requested if tag in available],
            [tag for tag in requested if tag not in available],
        )
    return response


def root_props(username: str) -> dict[str, ET.Element]:
    principal = f"/dav/{quote(username)}/"
    return {
        q(D, "resourcetype"): resourcetype("collection"),
        q(D, "displayname"): prop_element(q(D, "displayname"), "Company Contacts DAV"),
        q(D, "current-user-principal"): href_property(q(D, "current-user-principal"), principal),
        q(D, "principal-collection-set"): href_property(q(D, "principal-collection-set"), "/dav/"),
    }


def principal_props(username: str) -> dict[str, ET.Element]:
    principal = f"/dav/{quote(username)}/"
    return {
        q(D, "resourcetype"): resourcetype("collection", "principal"),
        q(D, "displayname"): prop_element(q(D, "displayname"), username),
        q(D, "principal-URL"): href_property(q(D, "principal-URL"), principal),
        q(C, "addressbook-home-set"): href_property(q(C, "addressbook-home-set"), principal),
        q(D, "current-user-principal"): href_property(q(D, "current-user-principal"), principal),
    }


def collection_props(username: str) -> dict[str, ET.Element]:
    token = store.collection_token()
    return {
        q(D, "resourcetype"): resourcetype("collection", "addressbook"),
        q(D, "displayname"): prop_element(q(D, "displayname"), "Company Contacts"),
        q(CS, "getctag"): prop_element(q(CS, "getctag"), token),
        q(D, "sync-token"): prop_element(q(D, "sync-token"), token),
        q(D, "owner"): href_property(q(D, "owner"), f"/dav/{quote(username)}/"),
        q(D, "supported-report-set"): supported_report_set(),
        q(C, "supported-address-data"): supported_address_data(),
    }


def contact_props(contact: dict, include_card: bool = False) -> dict[str, ET.Element]:
    vcard = contact_to_vcard(contact)
    props = {
        q(D, "resourcetype"): resourcetype(),
        q(D, "getetag"): prop_element(q(D, "getetag"), etag_for_vcard(vcard)),
        q(D, "getcontenttype"): prop_element(q(D, "getcontenttype"), "text/vcard; charset=utf-8"),
        q(D, "getcontentlength"): prop_element(q(D, "getcontentlength"), str(len(vcard.encode("utf-8")))),
    }
    if include_card:
        props[q(C, "address-data")] = prop_element(q(C, "address-data"), vcard)
    return props


def split_dav_path(subpath: str) -> tuple[str, str | None]:
    parts = [unquote(part) for part in subpath.split("/") if part]
    if not parts:
        return "root", None
    if len(parts) == 1:
        return "principal", None
    if len(parts) == 2 and parts[1] == "contacts":
        return "collection", None
    if len(parts) == 3 and parts[1] == "contacts":
        uid = parts[2]
        if uid.endswith(".vcf"):
            uid = uid[:-4]
        return "contact", uid
    return "missing", None


def contact_href(username: str, uid: str) -> str:
    return f"/dav/{quote(username)}/contacts/{quote(uid)}.vcf"


def register_routes(app: Flask) -> None:
    @app.get("/health")
    def health() -> Response:
        return Response("ok\n", content_type="text/plain")

    @app.get("/")
    def index() -> Response:
        return redirect(url_for("admin_contacts"))

    @app.route("/admin", methods=["GET"])
    @require_admin
    def admin_contacts(user: dict) -> str:
        contacts = store.list_contacts()
        return render_template_string(ADMIN_TEMPLATE, user=user, csrf=csrf_token(user["username"]), contacts=contacts)

    @app.route("/admin/contacts", methods=["POST"])
    @require_admin
    def create_contact(user: dict) -> Response:
        validate_csrf(user)
        store.save_contact(form_contact())
        return redirect(url_for("admin_contacts"))

    @app.route("/admin/contacts/<uid>", methods=["GET", "POST"])
    @require_admin
    def edit_contact(user: dict, uid: str):
        contact = store.get_contact(uid, include_inactive=True)
        if not contact:
            abort(404)
        if request.method == "POST":
            validate_csrf(user)
            data = form_contact()
            data["uid"] = uid
            store.save_contact(data)
            return redirect(url_for("admin_contacts"))
        return render_template_string(EDIT_TEMPLATE, user=user, csrf=csrf_token(user["username"]), contact=contact)

    @app.route("/admin/contacts/<uid>/delete", methods=["POST"])
    @require_admin
    def delete_contact(user: dict, uid: str) -> Response:
        validate_csrf(user)
        store.delete_contact(uid)
        return redirect(url_for("admin_contacts"))

    @app.route("/admin/users", methods=["GET", "POST"])
    @require_admin
    def admin_users(user: dict):
        error = None
        if request.method == "POST":
            validate_csrf(user)
            try:
                store.create_user(request.form["username"], request.form["password"], request.form["role"])
                return redirect(url_for("admin_users"))
            except Exception as exc:  # noqa: BLE001 - show admin-safe validation errors in the UI.
                error = str(exc)
        return render_template_string(
            USERS_TEMPLATE,
            user=user,
            csrf=csrf_token(user["username"]),
            users=store.list_users(),
            error=error,
        )

    @app.route("/admin/users/<username>/delete", methods=["POST"])
    @require_admin
    def delete_user(user: dict, username: str) -> Response:
        validate_csrf(user)
        store.delete_user(username)
        return redirect(url_for("admin_users"))

    @app.route("/admin/export.csv", methods=["GET"])
    @require_admin
    def export_csv(user: dict) -> Response:
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=CONTACT_FIELDS)
        writer.writeheader()
        for contact in store.list_contacts():
            writer.writerow({field: contact.get(field, "") for field in CONTACT_FIELDS})
        return Response(
            output.getvalue(),
            content_type="text/csv; charset=utf-8",
            headers={"Content-Disposition": "attachment; filename=company-contacts.csv"},
        )

    @app.route("/admin/import", methods=["POST"])
    @require_admin
    def import_csv(user: dict) -> Response:
        validate_csrf(user)
        text = request.form.get("csv_data", "")
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            store.save_contact(row)
        return redirect(url_for("admin_contacts"))

    @app.route("/dav", defaults={"subpath": ""}, methods=["OPTIONS", "GET", "HEAD", "PROPFIND", "REPORT", "PUT", "DELETE"])
    @app.route("/dav/<path:subpath>", methods=["OPTIONS", "GET", "HEAD", "PROPFIND", "REPORT", "PUT", "DELETE"])
    def dav(subpath: str):
        user, error = require_user()
        if error:
            return error
        if request.method == "OPTIONS":
            response = Response("", 204)
            response.headers["DAV"] = "1, 2, 3, addressbook"
            response.headers["Allow"] = "OPTIONS, GET, HEAD, PROPFIND, REPORT, PUT, DELETE"
            response.headers["MS-Author-Via"] = "DAV"
            return response

        kind, uid = split_dav_path(subpath)
        username = user["username"]

        if request.method in {"PUT", "DELETE"}:
            if user["role"] != "admin":
                return Response("This address book is read-only for employee accounts", 403)
            if kind != "contact" or not uid:
                return Response("Only contact resources can be changed", 409)
            if request.method == "DELETE":
                store.delete_contact(uid)
                return Response("", 204)
            data = parse_vcard(request.get_data(as_text=True), fallback_uid=uid)
            existed = store.get_contact(data["uid"], include_inactive=True) is not None
            saved_uid = store.save_contact(data)
            vcard = contact_to_vcard(store.get_contact(saved_uid))
            response = Response("", 204 if existed else 201)
            response.headers["ETag"] = etag_for_vcard(vcard)
            return response

        if request.method in {"GET", "HEAD"}:
            if kind == "contact" and uid:
                contact = store.get_contact(uid)
                if not contact:
                    abort(404)
                vcard = contact_to_vcard(contact)
                response = Response("" if request.method == "HEAD" else vcard, content_type="text/vcard; charset=utf-8")
                response.headers["ETag"] = etag_for_vcard(vcard)
                return response
            return Response("", 200)

        if request.method == "PROPFIND":
            return handle_propfind(kind, uid, username)
        if request.method == "REPORT":
            return handle_report(username)

        abort(405)


def form_contact() -> dict:
    return {field: request.form.get(field, "") for field in CONTACT_FIELDS}


def handle_propfind(kind: str, uid: str | None, username: str) -> Response:
    requested = parse_requested_props()
    depth = request.headers.get("Depth", "0")
    root = ET.Element(q(D, "multistatus"))

    if kind == "root":
        root.append(response_for("/dav/", root_props(username), requested))
        if depth != "0":
            root.append(response_for(f"/dav/{quote(username)}/", principal_props(username), requested))
    elif kind == "principal":
        root.append(response_for(f"/dav/{quote(username)}/", principal_props(username), requested))
        if depth != "0":
            root.append(response_for(f"/dav/{quote(username)}/contacts/", collection_props(username), requested))
    elif kind == "collection":
        root.append(response_for(f"/dav/{quote(username)}/contacts/", collection_props(username), requested))
        if depth != "0":
            for contact in store.list_contacts():
                root.append(response_for(contact_href(username, contact["uid"]), contact_props(contact), requested))
    elif kind == "contact" and uid:
        contact = store.get_contact(uid)
        if not contact:
            abort(404)
        root.append(response_for(contact_href(username, contact["uid"]), contact_props(contact), requested))
    else:
        abort(404)
    return xml_response(root)


def report_requested_props(root: ET.Element) -> tuple[set[str] | None, bool]:
    prop = root.find(q(D, "prop"))
    if prop is None:
        return None, True
    requested = {child.tag for child in list(prop)}
    return requested, q(C, "address-data") in requested


def handle_report(username: str) -> Response:
    try:
        report = ET.fromstring(request.get_data() or b"<empty />")
    except ET.ParseError:
        abort(400)

    requested, include_card = report_requested_props(report)
    multistatus = ET.Element(q(D, "multistatus"))
    name = local_name(report.tag)

    if name in {"addressbook-query", "sync-collection"}:
        for contact in store.list_contacts():
            multistatus.append(
                response_for(contact_href(username, contact["uid"]), contact_props(contact, include_card), requested)
            )
        if name == "sync-collection":
            sync_token = ET.SubElement(multistatus, q(D, "sync-token"))
            sync_token.text = store.collection_token()
        return xml_response(multistatus)

    if name == "addressbook-multiget":
        hrefs = [node.text or "" for node in report.findall(q(D, "href"))]
        for item in hrefs:
            uid = unquote(Path(item).name)
            if uid.endswith(".vcf"):
                uid = uid[:-4]
            contact = store.get_contact(uid)
            if contact:
                multistatus.append(
                    response_for(contact_href(username, contact["uid"]), contact_props(contact, include_card), requested)
                )
        return xml_response(multistatus)

    return Response("Unsupported REPORT", 400)


BASE_STYLE = """
<style>
body{font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;margin:2rem;line-height:1.45;max-width:1200px}
input,select,textarea{font:inherit;padding:.45rem;margin:.15rem 0;width:100%;box-sizing:border-box}
button,.button{font:inherit;padding:.45rem .75rem;margin:.25rem 0;display:inline-block}
table{border-collapse:collapse;width:100%;margin-top:1rem}
th,td{border-bottom:1px solid #ddd;text-align:left;padding:.5rem;vertical-align:top}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:.75rem}
.card{border:1px solid #ddd;border-radius:8px;padding:1rem;margin:1rem 0}
.muted{color:#666}.danger{color:#a00}.nav a{margin-right:1rem}
</style>
"""

CONTACT_FORM = """
<input type="hidden" name="csrf" value="{{ csrf }}">
<div class="grid">
  <label>UID <input name="uid" value="{{ contact.uid if contact else '' }}" placeholder="auto-generated if empty"></label>
  <label>Display name <input name="display_name" value="{{ contact.display_name if contact else '' }}"></label>
  <label>First name <input name="first_name" value="{{ contact.first_name if contact else '' }}"></label>
  <label>Last name <input name="last_name" value="{{ contact.last_name if contact else '' }}"></label>
  <label>Organization <input name="organization" value="{{ contact.organization if contact else '' }}"></label>
  <label>Department <input name="department" value="{{ contact.department if contact else '' }}"></label>
  <label>Title <input name="title" value="{{ contact.title if contact else '' }}"></label>
  <label>Email <input name="email" value="{{ contact.email if contact else '' }}"></label>
  <label>Work phone <input name="phone_work" value="{{ contact.phone_work if contact else '' }}"></label>
  <label>Mobile phone <input name="phone_mobile" value="{{ contact.phone_mobile if contact else '' }}"></label>
  <label>Other phone <input name="phone_other" value="{{ contact.phone_other if contact else '' }}"></label>
</div>
<label>Notes <textarea name="notes" rows="3">{{ contact.notes if contact else '' }}</textarea></label>
"""

ADMIN_TEMPLATE = BASE_STYLE + """
<h1>Company Contacts</h1>
<p class="muted">Logged in as {{ user.username }}. Employee accounts can sync these contacts but cannot change them.</p>
<p class="nav"><a href="/admin/users">Users</a><a href="/admin/export.csv">Export CSV</a><a href="/dav/{{ user.username }}/contacts/">CardDAV URL</a></p>
<section class="card">
  <h2>Add contact</h2>
  <form method="post" action="/admin/contacts">
""" + CONTACT_FORM + """
    <button type="submit">Save contact</button>
  </form>
</section>
<section class="card">
  <h2>Import CSV</h2>
  <p class="muted">Header row: uid, first_name, last_name, display_name, organization, department, title, email, phone_work, phone_mobile, phone_other, notes</p>
  <form method="post" action="/admin/import">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <textarea name="csv_data" rows="6"></textarea>
    <button type="submit">Import / update contacts</button>
  </form>
</section>
<h2>Current contacts</h2>
<table>
  <tr><th>Name</th><th>Organization</th><th>Phone</th><th>Email</th><th></th></tr>
  {% for contact in contacts %}
  <tr>
    <td><strong>{{ contact.display_name }}</strong><br><span class="muted">{{ contact.title }}</span></td>
    <td>{{ contact.organization }}<br><span class="muted">{{ contact.department }}</span></td>
    <td>{{ contact.phone_work }}<br>{{ contact.phone_mobile }}</td>
    <td>{{ contact.email }}</td>
    <td><a href="/admin/contacts/{{ contact.uid }}">Edit</a></td>
  </tr>
  {% else %}
  <tr><td colspan="5" class="muted">No contacts yet.</td></tr>
  {% endfor %}
</table>
"""

EDIT_TEMPLATE = BASE_STYLE + """
<h1>Edit contact</h1>
<p class="nav"><a href="/admin">Back to contacts</a></p>
<form method="post">
""" + CONTACT_FORM + """
  <button type="submit">Save changes</button>
</form>
<form method="post" action="/admin/contacts/{{ contact.uid }}/delete" onsubmit="return confirm('Delete this contact from employee sync?')">
  <input type="hidden" name="csrf" value="{{ csrf }}">
  <button class="danger" type="submit">Delete contact</button>
</form>
"""

USERS_TEMPLATE = BASE_STYLE + """
<h1>Users</h1>
<p class="nav"><a href="/admin">Back to contacts</a></p>
{% if error %}<p class="danger">{{ error }}</p>{% endif %}
<section class="card">
  <h2>Add user</h2>
  <form method="post">
    <input type="hidden" name="csrf" value="{{ csrf }}">
    <div class="grid">
      <label>Username <input name="username" required></label>
      <label>Password <input name="password" type="password" required></label>
      <label>Role
        <select name="role">
          <option value="employee">Employee read-only sync</option>
          <option value="admin">Admin full access</option>
        </select>
      </label>
    </div>
    <button type="submit">Create user</button>
  </form>
</section>
<table>
  <tr><th>Username</th><th>Role</th><th>Created</th><th></th></tr>
  {% for row in users %}
  <tr>
    <td>{{ row.username }}</td>
    <td>{{ row.role }}</td>
    <td>{{ row.created_at }}</td>
    <td>
      {% if row.username != user.username %}
      <form method="post" action="/admin/users/{{ row.username }}/delete" onsubmit="return confirm('Delete this user?')">
        <input type="hidden" name="csrf" value="{{ csrf }}">
        <button type="submit">Delete</button>
      </form>
      {% endif %}
    </td>
  </tr>
  {% endfor %}
</table>
"""


app = create_app()

