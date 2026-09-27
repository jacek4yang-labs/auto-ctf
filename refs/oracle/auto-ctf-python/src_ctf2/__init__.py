"""CTF2 Open API client package (zero third-party dependencies)."""

from .client import (
    CTF2AuthError,
    CTF2Client,
    CTF2Error,
    CTF2ForbiddenError,
    CTF2NotFoundError,
    CTF2RateLimitError,
    CTF2ServerError,
    CTF2ValidationError,
)
from .config import DEFAULT_API_KEY_FILE, load_token

__all__ = [
    "CTF2Client",
    "CTF2Error",
    "CTF2AuthError",
    "CTF2ForbiddenError",
    "CTF2NotFoundError",
    "CTF2RateLimitError",
    "CTF2ServerError",
    "CTF2ValidationError",
    "load_token",
    "DEFAULT_API_KEY_FILE",
]

__version__ = "0.1.0"
