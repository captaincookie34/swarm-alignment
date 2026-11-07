"""Load API keys from a .env file, so they never need to be in the repo or the shell history.

Only the harness process reads it. Nothing in it is passed into the sandbox, and the logs
redact known key patterns.
"""
from __future__ import annotations

import os
from pathlib import Path


def load_dotenv(path: Path = Path(".env")) -> list[str]:
    """Set variables from path that aren't already set. Returns the names it set.

    Variables already in the environment win, so `export X=...` still overrides the file.
    Lines look like KEY=value, optionally with `export ` in front or quotes around the value.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    loaded = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line = line.removeprefix("export ").strip()
        key, sep, value = line.partition("=")
        key, value = key.strip(), value.strip()
        if not sep or not key.replace("_", "").isalnum():
            continue
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
            value = value[1:-1]
        elif " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        if value and key not in os.environ:
            os.environ[key] = value
            loaded.append(key)
    return loaded
