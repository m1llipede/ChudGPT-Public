"""Lightweight request protection used by the public inference server."""

from __future__ import annotations

import hmac
import threading
import time


class RequestGate:
    """In-process authentication and fixed-window rate limiting."""

    def __init__(self, requests_per_minute: int, api_token: str = "") -> None:
        self.limit = max(1, requests_per_minute)
        self.api_token = api_token
        self.clients: dict[str, tuple[int, float]] = {}
        self.lock = threading.Lock()

    def authorize(self, authorization: str) -> bool:
        if not self.api_token:
            return True
        scheme, _, token = authorization.partition(" ")
        return scheme.casefold() == "bearer" and hmac.compare_digest(token, self.api_token)

    def allow(self, client: str, now: float | None = None) -> tuple[bool, int]:
        current = time.monotonic() if now is None else now
        with self.lock:
            count, started = self.clients.get(client, (0, current))
            if current - started >= 60:
                count, started = 0, current
            if count >= self.limit:
                return False, max(1, int(60 - (current - started)))
            self.clients[client] = (count + 1, started)
            return True, 0
