"""Offline unit tests: transport, envelope handling, errors, guards."""

from __future__ import annotations

import json

import pytest

from ctf2 import (
    CTF2AuthError,
    CTF2Client,
    CTF2ForbiddenError,
    CTF2NotFoundError,
    CTF2RateLimitError,
    CTF2ServerError,
    CTF2ValidationError,
    load_token,
)
from conftest import TOKEN, FakeResponse, http_error


# ------------------------------------------------------------------ #
# transport basics                                                    #
# ------------------------------------------------------------------ #

def test_auth_header_and_url(recorder, client):
    rec = recorder(FakeResponse(b'{"success": true, "data": {"id": "u1"}}'))
    profile = client.get_profile()

    assert profile == {"id": "u1"}
    req = rec.requests[0]
    assert req.get_method() == "GET"
    assert req.full_url == "https://ctf2.dasctf.com/api/open/v1/user/profile/"
    assert req.headers["Authorization"] == f"Bearer {TOKEN}"
    assert req.headers["Accept"] == "application/json"


def test_query_params_drop_none(recorder, client):
    rec = recorder()
    client.get_daily(limit=5)
    assert rec.requests[0].full_url.endswith("daily/?limit=5")


def test_json_body_post(recorder, client):
    rec = recorder()
    client.create_ticket("t", "c", confirm=True)
    req = rec.requests[0]
    assert req.get_method() == "POST"
    body = json.loads(req.data)
    assert body == {"title": "t", "content": "c"}


def test_plain_json_without_envelope(recorder, client):
    recorder(FakeResponse(b'{"raw": true}'))
    assert client.get_points() == {"raw": True}


# ------------------------------------------------------------------ #
# error mapping                                                       #
# ------------------------------------------------------------------ #

@pytest.mark.parametrize("status,exc_cls", [
    (401, CTF2AuthError),
    (403, CTF2ForbiddenError),
    (404, CTF2NotFoundError),
    (400, CTF2ValidationError),
    (422, CTF2ValidationError),
    (500, CTF2ServerError),
])
def test_error_mapping(recorder, client, status, exc_cls):
    recorder(http_error(status, b'{"message": "boom"}'))
    with pytest.raises(exc_cls) as excinfo:
        client.get_profile()
    assert excinfo.value.status == status
    assert "boom" in str(excinfo.value)


def test_429_no_retry_raises_rate_limit(recorder, client):
    recorder(http_error(429, b'{"message": "slow down"}'))
    with pytest.raises(CTF2RateLimitError):
        client.get_profile()


def test_429_retry_after_then_success(monkeypatch, client):
    sleeps = []
    monkeypatch.setattr("time.sleep", lambda s: sleeps.append(s))
    calls = {"n": 0}

    def fake_urlopen(req):
        calls["n"] += 1
        if calls["n"] == 1:
            raise http_error(429, b"{}", headers={"Retry-After": "3"})
        return FakeResponse(b'{"success": true, "data": {"ok": 1}}')

    client.max_retries = 2
    monkeypatch.setattr(CTF2Client, "_urlopen", staticmethod(fake_urlopen))
    assert client.get_profile() == {"ok": 1}
    assert sleeps == [3.0]


def test_network_failure_maps_to_status_zero(recorder, client):
    import urllib.error
    recorder(urllib.error.URLError("conn refused"))
    with pytest.raises(Exception) as excinfo:
        client.get_profile()
    assert "network failure" in str(excinfo.value)


# ------------------------------------------------------------------ #
# safety guards                                                       #
# ------------------------------------------------------------------ #

def test_submit_flag_requires_confirm(recorder, client):
    with pytest.raises(ValueError, match="confirm=True"):
        client.submit_flag("p1", "c1", "flag{x}")


def test_submit_flag_with_confirm_sends_body(recorder, client):
    rec = recorder()
    client.submit_flag("p1", "c1", "flag{x}", confirm=True, sub_flag_id="sf9")
    req = rec.requests[0]
    assert req.full_url.endswith("challenges/c1/submit/")
    assert json.loads(req.data) == {
        "flag": "flag{x}", "confirmation": True, "sub_flag_id": "sf9",
    }


def test_update_profile_requires_confirm(client):
    with pytest.raises(ValueError, match="confirm=True"):
        client.update_profile(username="new")


def test_write_helpers_require_confirm(client):
    with pytest.raises(ValueError):
        client.create_ticket("t", "c")
    with pytest.raises(ValueError):
        client.reply_ticket("1", "c")
    with pytest.raises(ValueError):
        client.transition_ticket("1", "close")


def test_environment_calls_are_plain_posts(recorder, client):
    rec = recorder()
    client.start_environment("p1", "c1")
    client.destroy_environment("p1", "c1")
    assert rec.requests[0].get_method() == "POST"
    assert rec.requests[0].full_url.endswith("environment/start/")
    assert rec.requests[1].get_method() == "DELETE"


# ------------------------------------------------------------------ #
# config                                                              #
# ------------------------------------------------------------------ #

def test_load_token_from_env(monkeypatch, tmp_path):
    monkeypatch.setenv("CTF2_TOKEN", "ctf2_env_token")
    assert load_token() == "ctf2_env_token"


def test_load_token_from_file(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF2_TOKEN", raising=False)
    key_file = tmp_path / "api-key.txt"
    key_file.write_text("ctf2_file_token\n", encoding="utf-8")
    from ctf2.config import load_token as lt
    assert lt(key_file=key_file) == "ctf2_file_token"


def test_load_token_missing(monkeypatch, tmp_path):
    monkeypatch.delenv("CTF2_TOKEN", raising=False)
    from ctf2.config import load_token as lt, MissingTokenError
    with pytest.raises(MissingTokenError):
        lt(key_file=tmp_path / "absent.txt")


def test_client_rejects_empty_token():
    with pytest.raises(ValueError):
        CTF2Client("")
