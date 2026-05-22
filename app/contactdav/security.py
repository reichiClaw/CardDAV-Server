from __future__ import annotations

import os
from pathlib import Path


def read_secret(name: str, default: str | None = None) -> str | None:
    """Read an env var or Docker-style *_FILE secret."""
    file_name = os.environ.get(f"{name}_FILE")
    if file_name:
        return Path(file_name).read_text(encoding="utf-8").strip()
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def data_dir() -> Path:
    path = Path(os.environ.get("CONTACT_DATA_DIR", "/data"))
    path.mkdir(parents=True, exist_ok=True)
    return path

