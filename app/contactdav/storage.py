from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path

from werkzeug.security import check_password_hash, generate_password_hash

from .security import read_secret
from .vcard import utc_now


CONTACT_FIELDS = [
    "uid",
    "first_name",
    "last_name",
    "display_name",
    "organization",
    "department",
    "title",
    "email",
    "phone_work",
    "phone_mobile",
    "phone_other",
    "notes",
]


class Store:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def init(self) -> None:
        with self.connect() as db:
            db.executescript(
                """
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL CHECK (role IN ('admin', 'employee')),
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS contacts (
                    uid TEXT PRIMARY KEY,
                    first_name TEXT NOT NULL DEFAULT '',
                    last_name TEXT NOT NULL DEFAULT '',
                    display_name TEXT NOT NULL DEFAULT '',
                    organization TEXT NOT NULL DEFAULT '',
                    department TEXT NOT NULL DEFAULT '',
                    title TEXT NOT NULL DEFAULT '',
                    email TEXT NOT NULL DEFAULT '',
                    phone_work TEXT NOT NULL DEFAULT '',
                    phone_mobile TEXT NOT NULL DEFAULT '',
                    phone_other TEXT NOT NULL DEFAULT '',
                    notes TEXT NOT NULL DEFAULT '',
                    active INTEGER NOT NULL DEFAULT 1,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                """
            )
            db.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('revision', '1')")

    def bootstrap_from_env(self) -> None:
        admin_user = read_secret("CONTACT_ADMIN_USER", "admin") or "admin"
        admin_password = read_secret("CONTACT_ADMIN_PASSWORD")
        employee_user = read_secret("CONTACT_EMPLOYEE_USER")
        employee_password = read_secret("CONTACT_EMPLOYEE_PASSWORD")

        with self.connect() as db:
            count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if count == 0:
            if not admin_password:
                raise RuntimeError("CONTACT_ADMIN_PASSWORD must be set for first startup")
            self.create_user(admin_user, admin_password, "admin")

        if employee_user and employee_password and not self.get_user(employee_user):
            self.create_user(employee_user, employee_password, "employee")

    def revision(self) -> str:
        with self.connect() as db:
            return db.execute("SELECT value FROM meta WHERE key = 'revision'").fetchone()[0]

    def bump_revision(self, db: sqlite3.Connection) -> None:
        db.execute("UPDATE meta SET value = CAST(CAST(value AS INTEGER) + 1 AS TEXT) WHERE key = 'revision'")

    def collection_token(self) -> str:
        return f"company-contacts-{self.revision()}"

    def create_user(self, username: str, password: str, role: str) -> None:
        if role not in {"admin", "employee"}:
            raise ValueError("role must be admin or employee")
        username = username.strip()
        if not username:
            raise ValueError("username is required")
        now = utc_now()
        with self.connect() as db:
            db.execute(
                """
                INSERT INTO users(username, password_hash, role, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (username, generate_password_hash(password), role, now, now),
            )

    def delete_user(self, username: str) -> None:
        with self.connect() as db:
            user = db.execute("SELECT role FROM users WHERE username = ?", (username,)).fetchone()
            if not user:
                return
            if user["role"] == "admin":
                admins = db.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0]
                if admins <= 1:
                    raise ValueError("cannot delete the last admin user")
            db.execute("DELETE FROM users WHERE username = ?", (username,))

    def get_user(self, username: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT username, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
            return dict(row) if row else None

    def list_users(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT username, role, created_at, updated_at FROM users ORDER BY username"
            ).fetchall()
            return [dict(row) for row in rows]

    def verify_user(self, username: str, password: str) -> dict | None:
        with self.connect() as db:
            row = db.execute(
                "SELECT username, password_hash, role FROM users WHERE username = ?",
                (username,),
            ).fetchone()
        if row and check_password_hash(row["password_hash"], password):
            return {"username": row["username"], "role": row["role"]}
        return None

    def list_contacts(self, include_inactive: bool = False) -> list[dict]:
        query = "SELECT * FROM contacts"
        if not include_inactive:
            query += " WHERE active = 1"
        query += " ORDER BY last_name COLLATE NOCASE, first_name COLLATE NOCASE, display_name COLLATE NOCASE"
        with self.connect() as db:
            return [dict(row) for row in db.execute(query).fetchall()]

    def get_contact(self, uid: str, include_inactive: bool = False) -> dict | None:
        query = "SELECT * FROM contacts WHERE uid = ?"
        params: tuple = (uid,)
        if not include_inactive:
            query += " AND active = 1"
        with self.connect() as db:
            row = db.execute(query, params).fetchone()
            return dict(row) if row else None

    def save_contact(self, data: dict) -> str:
        uid = (data.get("uid") or "").strip() or str(uuid.uuid4())
        values = {field: (data.get(field) or "").strip() for field in CONTACT_FIELDS}
        values["uid"] = uid
        if not values["display_name"]:
            values["display_name"] = " ".join(
                part for part in [values["first_name"], values["last_name"]] if part
            ).strip()
        if not values["display_name"]:
            values["display_name"] = values["organization"] or values["email"] or uid

        now = utc_now()
        with self.connect() as db:
            existing = db.execute("SELECT uid FROM contacts WHERE uid = ?", (uid,)).fetchone()
            if existing:
                db.execute(
                    """
                    UPDATE contacts
                    SET first_name = ?, last_name = ?, display_name = ?, organization = ?,
                        department = ?, title = ?, email = ?, phone_work = ?, phone_mobile = ?,
                        phone_other = ?, notes = ?, active = 1, updated_at = ?
                    WHERE uid = ?
                    """,
                    (
                        values["first_name"],
                        values["last_name"],
                        values["display_name"],
                        values["organization"],
                        values["department"],
                        values["title"],
                        values["email"],
                        values["phone_work"],
                        values["phone_mobile"],
                        values["phone_other"],
                        values["notes"],
                        now,
                        uid,
                    ),
                )
            else:
                db.execute(
                    """
                    INSERT INTO contacts(
                        uid, first_name, last_name, display_name, organization, department,
                        title, email, phone_work, phone_mobile, phone_other, notes,
                        active, created_at, updated_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        values["uid"],
                        values["first_name"],
                        values["last_name"],
                        values["display_name"],
                        values["organization"],
                        values["department"],
                        values["title"],
                        values["email"],
                        values["phone_work"],
                        values["phone_mobile"],
                        values["phone_other"],
                        values["notes"],
                        now,
                        now,
                    ),
                )
            self.bump_revision(db)
        return uid

    def delete_contact(self, uid: str) -> None:
        now = utc_now()
        with self.connect() as db:
            db.execute("UPDATE contacts SET active = 0, updated_at = ? WHERE uid = ?", (now, uid))
            self.bump_revision(db)

