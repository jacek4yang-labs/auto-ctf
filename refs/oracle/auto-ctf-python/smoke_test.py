"""Live smoke test against the real CTF2 API (read-only endpoints).

Usage:
    python scripts/smoke_test.py

Reads the token from $CTF2_TOKEN or ./api-key.txt, then exercises every
read-only scope family reachable for the current account and prints a
PASS/FAIL summary. Exit code 0 means all checks passed.

No write endpoint is called: no flag submission, no environment start,
no ticket creation, no profile change.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ctf2 import CTF2Client, load_token  # noqa: E402

READ_ONLY_CHECKS = [
    ("profile (profile:read)", lambda c: c.get_profile()),
    ("announcements (profile:read)", lambda c: c.get_announcements(5)),
    ("platform-update-logs (platform:update:read)", lambda c: c.get_platform_update_logs(5)),
    ("daily (daily:read)", lambda c: c.get_daily(5)),
    ("practice (practice:read)", lambda c: c.get_practice(5)),
    ("private-practice (practice:read)", lambda c: c.get_private_practice(5)),
    ("competitions (competition:read)", lambda c: c.get_competitions(5)),
    ("submissions (submission:read)", lambda c: c.get_submissions(5)),
    ("private-practice submissions (submission:read)", lambda c: c.get_private_practice_submissions(5)),
    ("tickets (ticket:read)", lambda c: c.get_tickets(5)),
    ("teams (team:read)", lambda c: c.get_teams(5)),
    ("my-team (team:read)", lambda c: c.get_my_team()),
    ("learning-events (learning:read)", lambda c: c.get_learning_events(5)),
    ("learning-recommendations (learning:read)", lambda c: c.get_learning_recommendations()),
    ("points (learning:read)", lambda c: c.get_points()),
    ("points-transactions (learning:read)", lambda c: c.get_points_transactions(5)),
    ("point-shop-products (learning:read)", lambda c: c.get_point_shop_products(5)),
    ("point-shop-orders (learning:read)", lambda c: c.get_point_shop_orders(5)),
    ("community-feeds (community:read)", lambda c: c.get_community_feeds(5)),
    ("community-topics (community:read)", lambda c: c.get_community_topics(5)),
    ("community-discussions (community:read)", lambda c: c.get_community_discussions(5)),
    ("courses (learning:read)", lambda c: c.get_courses(5)),
    ("my-classes (learning:read)", lambda c: c.get_my_classes(5)),
    ("writeups (writeup:read)", lambda c: c.get_writeups(5)),
    ("my-writeups (writeup:read)", lambda c: c.get_my_writeups(5)),
]


def main() -> int:
    client = CTF2Client(load_token())
    passed: list[str] = []
    failed: list[tuple[str, str]] = []

    print(f"CTF2 smoke test against {client.api_base}\n")
    for name, call in READ_ONLY_CHECKS:
        start = time.monotonic()
        try:
            data = call(client)
            elapsed = (time.monotonic() - start) * 1000
            summary = _summarize(data)
            print(f"  PASS  {name:<48} {elapsed:6.0f} ms  {summary}")
            passed.append(name)
        except Exception as exc:  # noqa: BLE001 - report every failure
            elapsed = (time.monotonic() - start) * 1000
            print(f"  FAIL  {name:<48} {elapsed:6.0f} ms  {exc}")
            failed.append((name, str(exc)))

    print(f"\n{len(passed)} passed, {len(failed)} failed, "
          f"{len(READ_ONLY_CHECKS)} total")
    if failed:
        print("\nFailed checks:")
        for name, err in failed:
            print(f"  - {name}: {err}")
        return 1
    print("\nAll read-only endpoints responded successfully.")
    return 0


def _summarize(data) -> str:
    if isinstance(data, list):
        return f"list[{len(data)}]"
    if isinstance(data, dict):
        if "items" in data and isinstance(data["items"], list):
            return f"items[{len(data['items'])}]"
        keys = ", ".join(list(data.keys())[:4])
        return f"dict({keys}{'...' if len(data) > 4 else ''})"
    return type(data).__name__


if __name__ == "__main__":
    sys.exit(main())
