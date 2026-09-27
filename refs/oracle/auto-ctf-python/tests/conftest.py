"""Shared fixtures: project src on sys.path + a fake transport."""

from __future__ import annotations

import json
import sys
import urllib.error
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ctf2 import CTF2Client  # noqa: E402

TOKEN = "ctf2_test_token"


class FakeResponse:
    def __init__(self, raw: bytes, status: int = 200, headers=None):
        self._raw = raw
        self.status = status
        self.headers = headers or {}

    def read(self) -> bytes:
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def http_error(status: int, body: bytes, headers=None) -> urllib.error.HTTPError:
    import io

    return urllib.error.HTTPError(
        url="https://ctf2.dasctf.com", code=status, msg="error",
        hdrs=headers or {}, fp=io.BytesIO(body),
    )


def envelope(data) -> bytes:
    return json.dumps({"success": True, "data": data}).encode("utf-8")


class Recorder:
    """Stands in for ``CTF2Client._urlopen`` and records requests."""

    def __init__(self, responses=None):
        self.requests: list[urllib.request.Request] = []
        self.responses = list(responses or [])

    def __call__(self, req: urllib.request.Request) -> FakeResponse:
        self.requests.append(req)
        if self.responses:
            item = self.responses.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return FakeResponse(envelope({}))


@pytest.fixture()
def recorder(monkeypatch):
    def install(*responses):
        rec = Recorder(responses)
        monkeypatch.setattr(CTF2Client, "_urlopen", staticmethod(rec))
        return rec
    return install


@pytest.fixture()
def client() -> CTF2Client:
    return CTF2Client(TOKEN, max_retries=0)
