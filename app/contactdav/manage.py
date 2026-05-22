from __future__ import annotations

import sys

from .main import store


def init() -> None:
    store.init()
    store.bootstrap_from_env()
    print("ContactDAV database ready", flush=True)


def main() -> None:
    command = sys.argv[1] if len(sys.argv) > 1 else "init"
    if command == "init":
        init()
        return
    raise SystemExit(f"Unknown command: {command}")


if __name__ == "__main__":
    main()

