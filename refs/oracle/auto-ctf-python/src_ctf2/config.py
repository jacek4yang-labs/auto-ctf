"""Credential loading for the CTF2 Open API.

Token resolution order:
1. ``CTF2_TOKEN`` environment variable (recommended for scripts/CI).
2. A local key file (default ``api-key.txt`` in the project root).

The token is never logged or embedded in generated configs, per the
ctf2-platform skill safety rules.
"""

from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_API_KEY_FILE = PROJECT_ROOT / "api-key.txt"


class MissingTokenError(RuntimeError):
    """Raised when no API token can be located."""


def load_token(env_var: str = "CTF2_TOKEN", key_file: Path | None = None) -> str:
    """Return the PAT from the environment or the local key file."""
    token = os.environ.get(env_var, "").strip()
    if token:
        return token

    path = Path(key_file) if key_file else DEFAULT_API_KEY_FILE
    if path.is_file():
        token = path.read_text(encoding="utf-8").strip()
        if token:
            return token

    raise MissingTokenError(
        f"No CTF2 token found. Set the {env_var} environment variable "
        f"or create {path} containing your personal access token."
    )
