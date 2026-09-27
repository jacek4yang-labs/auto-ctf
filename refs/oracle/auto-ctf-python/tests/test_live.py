"""Live read-only tests against the real CTF2 API.

Run with:  pytest -m live
Skipped automatically when no token is available. Strictly read-only:
no flag submission, no environment lifecycle, no ticket/profile writes.
"""

from __future__ import annotations

import pytest

from conftest import PROJECT_ROOT  # noqa: F401  (also installs src on path)

import sys

sys.path.insert(0, str(PROJECT_ROOT / "src"))

from ctf2 import CTF2Client, load_token  # noqa: E402

pytestmark = pytest.mark.live


@pytest.fixture(scope="module")
def client():
    try:
        token = load_token()
    except Exception as exc:  # pragma: no cover
        pytest.skip(f"no CTF2 token available: {exc}")
    return CTF2Client(token)


def test_profile(client):
    profile = client.get_profile()
    assert profile["id"]
    assert profile["username"]
    assert profile["role"] == "user"


def test_announcements(client):
    client.get_announcements(5)


def test_platform_update_logs(client):
    client.get_platform_update_logs(5)


def test_daily(client):
    client.get_daily(5)


def test_practice(client):
    client.get_practice(5)


def test_private_practice(client):
    client.get_private_practice(5)


def test_competitions(client):
    client.get_competitions(5)


def test_submissions(client):
    client.get_submissions(5)


def test_private_practice_submissions(client):
    client.get_private_practice_submissions(5)


def test_tickets(client):
    client.get_tickets(5)


def test_teams_and_my_team(client):
    client.get_teams(5)
    client.get_my_team()


def test_learning_family(client):
    client.get_learning_events(5)
    client.get_learning_recommendations()
    client.get_points()
    client.get_points_transactions(5)
    client.get_point_shop_products(5)
    client.get_point_shop_orders(5)
    client.get_courses(5)
    client.get_my_classes(5)


def test_community_family(client):
    client.get_community_feeds(5)
    client.get_community_topics(5)
    client.get_community_discussions(5)


def test_writeups_family(client):
    client.get_writeups(5)
    client.get_my_writeups(5)


def test_bad_token_is_auth_error():
    bad = CTF2Client("ctf2_invalid_token", max_retries=0)
    with pytest.raises(Exception) as excinfo:
        bad.get_profile()
    assert getattr(excinfo.value, "status", None) in (401, 403)
