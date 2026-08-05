from __future__ import annotations

import hashlib
import re
import uuid
from datetime import datetime, timezone


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def card_timestamp(value: str | None) -> str:
    if not value:
        return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return value.replace("-", "").replace(":", "").replace("+00:00", "Z")


def escape_value(value: str | None) -> str:
    if not value:
        return ""
    return (
        value.replace("\\", "\\\\")
        .replace("\n", "\\n")
        .replace(";", "\\;")
        .replace(",", "\\,")
    )


def unescape_value(value: str) -> str:
    """Unescape vCard text values without corrupting literal backslashes."""
    output: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "\\" and index + 1 < len(value):
            nxt = value[index + 1]
            if nxt == "n":
                output.append("\n")
            elif nxt == "N":
                output.append("\n")
            elif nxt in {",", ";", "\\"}:
                output.append(nxt)
            else:
                output.append(nxt)
            index += 2
            continue
        output.append(char)
        index += 1
    return "".join(output)


def fold_line(line: str) -> list[str]:
    """Fold vCard lines at a conservative byte length."""
    encoded = line.encode("utf-8")
    if len(encoded) <= 73:
        return [line]

    output: list[str] = []
    current = ""
    for char in line:
        candidate = current + char
        if len(candidate.encode("utf-8")) > 73:
            output.append(current)
            current = " " + char
        else:
            current = candidate
    if current:
        output.append(current)
    return output


def contact_to_vcard(contact: dict) -> str:
    uid = contact["uid"]
    first = escape_value(contact.get("first_name"))
    last = escape_value(contact.get("last_name"))
    display = escape_value(contact.get("display_name") or f"{first} {last}".strip() or uid)
    org = escape_value(contact.get("organization"))
    department = escape_value(contact.get("department"))

    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"UID:{escape_value(uid)}",
        f"FN:{display}",
        f"N:{last};{first};;;",
    ]
    if org or department:
        lines.append(f"ORG:{org};{department}")
    if contact.get("title"):
        lines.append(f"TITLE:{escape_value(contact.get('title'))}")
    if contact.get("phone_work"):
        lines.append(f"TEL;TYPE=WORK,VOICE:{escape_value(contact.get('phone_work'))}")
    if contact.get("phone_mobile"):
        lines.append(f"TEL;TYPE=CELL,VOICE:{escape_value(contact.get('phone_mobile'))}")
    if contact.get("phone_other"):
        lines.append(f"TEL;TYPE=VOICE:{escape_value(contact.get('phone_other'))}")
    if contact.get("email"):
        lines.append(f"EMAIL;TYPE=WORK:{escape_value(contact.get('email'))}")
    if contact.get("notes"):
        lines.append(f"NOTE:{escape_value(contact.get('notes'))}")
    lines.append(f"REV:{card_timestamp(contact.get('updated_at'))}")
    lines.append("END:VCARD")

    folded: list[str] = []
    for line in lines:
        folded.extend(fold_line(line))
    return "\r\n".join(folded) + "\r\n"


def etag_for_vcard(vcard: str) -> str:
    return '"' + hashlib.sha256(vcard.encode("utf-8")).hexdigest() + '"'


def unfold_vcard(raw: str) -> list[str]:
    normalized = raw.replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    for line in normalized.split("\n"):
        if not line:
            continue
        if line.startswith((" ", "\t")) and lines:
            lines[-1] += line[1:]
        else:
            lines.append(line)
    return lines


def parse_vcard(raw: str, fallback_uid: str | None = None) -> dict:
    fields: dict[str, str] = {}
    phones: list[tuple[str, str]] = []
    for line in unfold_vcard(raw):
        if ":" not in line:
            continue
        name_part, value = line.split(":", 1)
        name = name_part.split(";", 1)[0].upper()
        value = unescape_value(value.strip())
        if name == "TEL":
            phones.append((name_part.upper(), value))
        else:
            fields[name] = value

    uid = fields.get("UID") or fallback_uid or str(uuid.uuid4())
    first = ""
    last = ""
    if "N" in fields:
        parts = fields["N"].split(";")
        last = parts[0] if len(parts) > 0 else ""
        first = parts[1] if len(parts) > 1 else ""
    elif "FN" in fields:
        first = fields["FN"]

    organization = ""
    department = ""
    if "ORG" in fields:
        org_parts = fields["ORG"].split(";")
        organization = org_parts[0] if org_parts else ""
        department = org_parts[1] if len(org_parts) > 1 else ""

    phone_work = ""
    phone_mobile = ""
    phone_other = ""
    for meta, value in phones:
        if "CELL" in meta and not phone_mobile:
            phone_mobile = value
        elif "WORK" in meta and not phone_work:
            phone_work = value
        elif not phone_other:
            phone_other = value

    safe_uid = re.sub(r"[^A-Za-z0-9_.-]", "-", uid)
    return {
        "uid": safe_uid,
        "first_name": first,
        "last_name": last,
        "display_name": fields.get("FN") or " ".join(part for part in [first, last] if part),
        "organization": organization,
        "department": department,
        "title": fields.get("TITLE", ""),
        "email": fields.get("EMAIL", ""),
        "phone_work": phone_work,
        "phone_mobile": phone_mobile,
        "phone_other": phone_other,
        "notes": fields.get("NOTE", ""),
    }

