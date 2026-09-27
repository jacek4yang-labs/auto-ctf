"""CTF2 Open API client.

Implements the user-facing endpoints documented in
``.agents/skills/ctf2-platform/references/open-api.md`` and the upstream
OpenAPI 3.1 document at ``https://ctf2.dasctf.com/api/openapi/v1/user.json``.

Transport uses only the Python standard library. Responses follow the
platform envelope ``{"success": bool, "data": ...}``; this client unwraps
and returns the ``data`` member when present.

Safety rules honoured here (see the skill's ``references/safety.md``):

- Write helpers that change platform state (flag submission, environment
  lifecycle, tickets, profile update) require an explicit ``confirmation``
  / ``confirm`` argument — the library refuses to fire them implicitly.
- 401 raises :class:`CTF2AuthError`, 403 raises :class:`CTF2ForbiddenError`,
  and 429 raises :class:`CTF2RateLimitError` after honouring ``Retry-After``
  up to ``max_retries`` times.
"""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

__all__ = [
    "CTF2Client",
    "CTF2Error",
    "CTF2AuthError",
    "CTF2ForbiddenError",
    "CTF2NotFoundError",
    "CTF2RateLimitError",
    "CTF2ServerError",
    "CTF2ValidationError",
]

DEFAULT_BASE_URL = "https://ctf2.dasctf.com"
USER_API_PREFIX = "/api/open/v1/user"


class CTF2Error(Exception):
    """Base error carrying the HTTP status and decoded payload."""

    def __init__(self, status: int, message: str, payload: Any = None) -> None:
        super().__init__(f"HTTP {status}: {message}")
        self.status = status
        self.message = message
        self.payload = payload


class CTF2AuthError(CTF2Error):
    """401 — token expired, revoked, or invalid."""


class CTF2ForbiddenError(CTF2Error):
    """403 — missing scope or permission."""


class CTF2NotFoundError(CTF2Error):
    """404 — unknown resource."""


class CTF2ValidationError(CTF2Error):
    """400/409/422 — request rejected (bad flag, missing sub_flag_id, ...)."""


class CTF2RateLimitError(CTF2Error):
    """429 — rate limited; ``retry_after`` is seconds when provided."""

    def __init__(self, status: int, message: str, payload: Any = None,
                 retry_after: float | None = None) -> None:
        super().__init__(status, message, payload)
        self.retry_after = retry_after


class CTF2ServerError(CTF2Error):
    """5xx — platform-side failure."""


class CTF2Client:
    """Small typed client over the CTF2 user Open API."""

    def __init__(
        self,
        token: str,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        max_retries: int = 2,
        user_agent: str = "auto-ctf/0.1",
    ) -> None:
        if not token:
            raise ValueError("token must be a non-empty string")
        self.token = token
        self.base_url = base_url.rstrip("/")
        self.api_base = self.base_url + USER_API_PREFIX
        self.timeout = timeout
        self.max_retries = max_retries
        self.user_agent = user_agent

    # ------------------------------------------------------------------ #
    # transport                                                          #
    # ------------------------------------------------------------------ #

    def request(
        self,
        method: str,
        path: str,
        params: dict[str, Any] | None = None,
        json_body: dict[str, Any] | None = None,
    ) -> Any:
        """Perform one API call and return the unwrapped ``data`` payload.

        ``path`` is relative to the user API base, e.g. ``profile/``.
        """
        url = self.api_base + "/" + path.lstrip("/")
        if params:
            clean = {k: v for k, v in params.items() if v is not None}
            if clean:
                url += "?" + urllib.parse.urlencode(clean)

        data = None
        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
            "User-Agent": self.user_agent,
        }
        if json_body is not None:
            data = json.dumps(json_body).encode("utf-8")
            headers["Content-Type"] = "application/json"

        attempt = 0
        while True:
            req = urllib.request.Request(url, data=data, headers=headers, method=method)
            try:
                with self._urlopen(req) as resp:
                    return self._decode(resp.read())
            except urllib.error.HTTPError as exc:
                body = self._safe_body(exc)
                payload = self._try_json(body)
                message = self._error_message(payload, body, exc)

                if exc.code == 429 and attempt < self.max_retries:
                    attempt += 1
                    time.sleep(self._retry_after_seconds(exc))
                    continue
                raise self._error_for(exc.code, message, payload) from exc
            except urllib.error.URLError as exc:
                if attempt < self.max_retries:
                    attempt += 1
                    time.sleep(min(2 ** attempt, 8))
                    continue
                raise CTF2Error(0, f"network failure: {exc.reason}") from exc

    def _urlopen(self, req: urllib.request.Request):
        return urllib.request.urlopen(req, timeout=self.timeout)

    @staticmethod
    def _decode(raw: bytes) -> Any:
        if not raw:
            return None
        payload = json.loads(raw.decode("utf-8"))
        if isinstance(payload, dict) and "success" in payload and "data" in payload:
            if not payload["success"]:
                raise CTF2Error(200, "platform reported success=false", payload)
            return payload["data"]
        return payload

    @staticmethod
    def _safe_body(exc: urllib.error.HTTPError) -> str:
        try:
            return exc.read().decode("utf-8", "replace")
        except Exception:  # pragma: no cover - body already consumed
            return ""

    @staticmethod
    def _try_json(body: str) -> Any:
        try:
            return json.loads(body) if body else None
        except json.JSONDecodeError:
            return None

    @staticmethod
    def _error_message(payload: Any, body: str, exc: urllib.error.HTTPError) -> str:
        if isinstance(payload, dict):
            detail = payload.get("message") or payload.get("detail") or payload.get("error")
            if detail:
                return str(detail)
        return body.strip()[:300] or exc.reason

    @staticmethod
    def _retry_after_seconds(exc: urllib.error.HTTPError) -> float:
        raw = exc.headers.get("Retry-After") if exc.headers else None
        if raw:
            try:
                return max(0.0, float(raw))
            except ValueError:
                pass
        return 1.0

    @staticmethod
    def _error_for(status: int, message: str, payload: Any) -> CTF2Error:
        if status == 401:
            return CTF2AuthError(status, message, payload)
        if status == 403:
            return CTF2ForbiddenError(status, message, payload)
        if status == 404:
            return CTF2NotFoundError(status, message, payload)
        if status in (400, 409, 422):
            return CTF2ValidationError(status, message, payload)
        if status == 429:
            return CTF2RateLimitError(status, message, payload)
        if status >= 500:
            return CTF2ServerError(status, message, payload)
        return CTF2Error(status, message, payload)

    # ------------------------------------------------------------------ #
    # profile & announcements                                            #
    # ------------------------------------------------------------------ #

    def get_profile(self) -> dict:
        return self.request("GET", "profile/")

    def update_profile(self, *, confirm: bool = False, **fields: Any) -> dict:
        """Update username/avatar/bio/invisible_mode. Requires ``confirm``."""
        if not confirm:
            raise ValueError("refusing to update profile without confirm=True")
        allowed = {"username", "avatar", "bio", "invisible_mode"}
        body = {k: v for k, v in fields.items() if k in allowed and v is not None}
        return self.request("PUT", "profile/", json_body=body)

    def get_announcements(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "announcements/", params={"limit": limit})

    def get_platform_update_logs(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "platform-update-logs/", params={"limit": limit})

    # ------------------------------------------------------------------ #
    # challenges                                                         #
    # ------------------------------------------------------------------ #

    def get_daily(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "daily/", params={"limit": limit})

    def get_practice(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "practice/", params={"limit": limit})

    def get_private_practice(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "private-practice/", params={"limit": limit})

    def get_practice_challenge(self, practice_id: str, challenge_id: str) -> dict:
        return self.request(
            "GET", f"practice/{practice_id}/challenges/{challenge_id}/"
        )

    def submit_flag(
        self,
        practice_id: str,
        challenge_id: str,
        flag: str,
        *,
        confirm: bool = False,
        sub_flag_id: str | None = None,
    ) -> dict:
        """Submit a confirmed practice flag. Requires ``confirm=True``."""
        if not confirm:
            raise ValueError(
                "refusing to submit a flag without confirm=True "
                "(re-confirm the exact flag and challenge first)"
            )
        body: dict[str, Any] = {"flag": flag, "confirmation": True}
        if sub_flag_id:
            body["sub_flag_id"] = sub_flag_id
        return self.request(
            "POST", f"practice/{practice_id}/challenges/{challenge_id}/submit/",
            json_body=body,
        )

    def start_environment(self, practice_id: str, challenge_id: str) -> dict:
        """Start (or reuse) a practice environment. Idempotent per the docs."""
        return self.request(
            "POST",
            f"practice/{practice_id}/challenges/{challenge_id}/environment/start/",
            json_body={},
        )

    def destroy_environment(self, practice_id: str, challenge_id: str) -> dict:
        return self.request(
            "DELETE", f"practice/{practice_id}/challenges/{challenge_id}/environment/"
        )

    # ------------------------------------------------------------------ #
    # competitions & stages                                              #
    # ------------------------------------------------------------------ #

    def get_competitions(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "competitions/", params={"limit": limit})

    def get_competition_status(self, competition_id: str) -> dict:
        return self.request("GET", f"competitions/{competition_id}/status/")

    def get_competition_teams(self, competition_id: str) -> list | dict:
        return self.request("GET", f"competitions/{competition_id}/teams/")

    def get_competition_stages(self, competition_id: str) -> list | dict:
        return self.request("GET", f"competitions/{competition_id}/stages/")

    def get_stage(self, stage_id: str) -> dict:
        return self.request("GET", f"stages/{stage_id}/")

    def get_stage_challenges(self, stage_id: str) -> list | dict:
        return self.request("GET", f"stages/{stage_id}/challenges/")

    def get_stage_submissions(self, stage_id: str) -> list | dict:
        return self.request("GET", f"stages/{stage_id}/submissions/")

    def get_stage_tickets(self, stage_id: str) -> list | dict:
        return self.request("GET", f"stages/{stage_id}/tickets/")

    # ------------------------------------------------------------------ #
    # submissions & tickets                                              #
    # ------------------------------------------------------------------ #

    def get_submissions(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "submissions/", params={"limit": limit})

    def get_private_practice_submissions(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "private-practice/submissions/", params={"limit": limit})

    def get_tickets(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "tickets/", params={"limit": limit})

    def create_ticket(self, title: str, content: str, *, confirm: bool = False,
                      **optional: Any) -> dict:
        if not confirm:
            raise ValueError("refusing to create a ticket without confirm=True")
        body = {"title": title, "content": content, **optional}
        return self.request("POST", "tickets/", json_body=body)

    def reply_ticket(self, ticket_id: str, content: str, *, confirm: bool = False) -> dict:
        if not confirm:
            raise ValueError("refusing to reply to a ticket without confirm=True")
        return self.request(
            "POST", f"tickets/{ticket_id}/replies/", json_body={"content": content}
        )

    def transition_ticket(self, ticket_id: str, action: str, *, confirm: bool = False) -> dict:
        if not confirm:
            raise ValueError("refusing to transition a ticket without confirm=True")
        return self.request(
            "POST", f"tickets/{ticket_id}/transition/", json_body={"action": action}
        )

    # ------------------------------------------------------------------ #
    # teams, learning, community, writeups                               #
    # ------------------------------------------------------------------ #

    def get_teams(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "teams/", params={"limit": limit})

    def get_my_team(self) -> dict:
        return self.request("GET", "team/my/")

    def get_team(self, team_id: str) -> dict:
        return self.request("GET", f"teams/{team_id}/")

    def get_learning_events(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "learning/events/", params={"limit": limit})

    def get_learning_recommendations(self) -> list | dict:
        return self.request("GET", "learning/recommendations/")

    def get_points(self) -> list | dict:
        return self.request("GET", "points/")

    def get_points_transactions(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "points/transactions/", params={"limit": limit})

    def get_point_shop_products(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "point-shop/products/", params={"limit": limit})

    def get_point_shop_orders(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "point-shop/orders/", params={"limit": limit})

    def get_community_feeds(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "community/feeds/", params={"limit": limit})

    def get_community_topics(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "community/topics/", params={"limit": limit})

    def get_community_discussions(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "community/discussions/", params={"limit": limit})

    def get_courses(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "courses/", params={"limit": limit})

    def get_my_classes(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "classes/my/", params={"limit": limit})

    def get_writeups(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "writeups/", params={"limit": limit})

    def get_my_writeups(self, limit: int | None = None) -> list | dict:
        return self.request("GET", "writeups/my/", params={"limit": limit})
