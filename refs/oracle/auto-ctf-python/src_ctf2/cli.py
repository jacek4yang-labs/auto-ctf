"""Command line front-end: ``python -m ctf2 <command>``.

Read-only commands print live API results. Write commands (profile update,
flag submission, environment lifecycle, tickets) require ``--yes`` and are
guarded by the client library as well.
"""

from __future__ import annotations

import argparse
import json
import sys

from .client import CTF2Client
from .config import load_token


def _print(data) -> None:
    print(json.dumps(data, ensure_ascii=False, indent=2, default=str))


def _add_limit(sub: argparse.ArgumentParser) -> argparse.ArgumentParser:
    sub.add_argument("--limit", type=int, default=None,
                     help="max items for list endpoints")
    return sub


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="ctf2", description="CTF2 platform CLI")
    sub = parser.add_subparsers(dest="command", required=True)

    _add_limit(sub.add_parser("whoami", help="show current profile"))
    _add_limit(sub.add_parser("announcements", help="list active announcements"))
    _add_limit(sub.add_parser("update-logs", help="list platform update logs"))
    _add_limit(sub.add_parser("daily", help="list daily challenges"))
    _add_limit(sub.add_parser("practice", help="list public practice grounds"))
    _add_limit(sub.add_parser("private-practice", help="list private practice grounds"))
    _add_limit(sub.add_parser("competitions", help="list visible competitions"))
    _add_limit(sub.add_parser("submissions", help="list my submissions"))
    _add_limit(sub.add_parser("tickets", help="list my tickets"))
    _add_limit(sub.add_parser("teams", help="list teams"))
    _add_limit(sub.add_parser("my-team", help="show my team"))
    _add_limit(sub.add_parser("points", help="show point balances"))
    _add_limit(sub.add_parser("recommendations", help="learning recommendations"))
    _add_limit(sub.add_parser("courses", help="list published courses"))
    _add_limit(sub.add_parser("writeups", help="list public approved writeups"))

    p_status = sub.add_parser("competition-status", help="competition status")
    p_status.add_argument("id")
    p_stage = sub.add_parser("stage-challenges", help="stage challenges")
    p_stage.add_argument("stage_id")

    p_flag = sub.add_parser("submit-flag", help="submit a practice flag (needs --yes)")
    p_flag.add_argument("practice_id")
    p_flag.add_argument("challenge_id")
    p_flag.add_argument("flag")
    p_flag.add_argument("--sub-flag-id", default=None)
    p_flag.add_argument("--yes", action="store_true")

    p_env = sub.add_parser("start-env", help="start a practice environment")
    p_env.add_argument("practice_id")
    p_env.add_argument("challenge_id")

    p_stop = sub.add_parser("stop-env", help="destroy a practice environment")
    p_stop.add_argument("practice_id")
    p_stop.add_argument("challenge_id")
    p_stop.add_argument("--yes", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    args = _build_parser().parse_args(argv)
    client = CTF2Client(load_token())

    if args.command == "whoami":
        _print(client.get_profile())
    elif args.command == "announcements":
        _print(client.get_announcements(args.limit))
    elif args.command == "update-logs":
        _print(client.get_platform_update_logs(args.limit))
    elif args.command == "daily":
        _print(client.get_daily(args.limit))
    elif args.command == "practice":
        _print(client.get_practice(args.limit))
    elif args.command == "private-practice":
        _print(client.get_private_practice(args.limit))
    elif args.command == "competitions":
        _print(client.get_competitions(args.limit))
    elif args.command == "competition-status":
        _print(client.get_competition_status(args.id))
    elif args.command == "stage-challenges":
        _print(client.get_stage_challenges(args.stage_id))
    elif args.command == "submissions":
        _print(client.get_submissions(args.limit))
    elif args.command == "tickets":
        _print(client.get_tickets(args.limit))
    elif args.command == "teams":
        _print(client.get_teams(args.limit))
    elif args.command == "my-team":
        _print(client.get_my_team())
    elif args.command == "points":
        _print(client.get_points())
    elif args.command == "recommendations":
        _print(client.get_learning_recommendations())
    elif args.command == "courses":
        _print(client.get_courses(args.limit))
    elif args.command == "writeups":
        _print(client.get_writeups(args.limit))
    elif args.command == "submit-flag":
        _print(client.submit_flag(
            args.practice_id, args.challenge_id, args.flag,
            confirm=args.yes, sub_flag_id=args.sub_flag_id,
        ))
    elif args.command == "start-env":
        _print(client.start_environment(args.practice_id, args.challenge_id))
    elif args.command == "stop-env":
        _print(client.destroy_environment(args.practice_id, args.challenge_id))
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
