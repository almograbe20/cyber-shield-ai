"""
Rate Limiting — Cyber Shield AI (Phase 4 hardening)
===================================================
A simple in-memory sliding-window limiter to stop the platform from being
abused as an attack tool (too many scans in a short time).

- Keyed by user id when signed in, otherwise by client IP.
- Default: 20 scan requests per 60 seconds per key.
- In production you would back this with Redis (shared across instances);
  the in-memory version is enough for the MVP / a single process.
"""

import time
from collections import defaultdict

from fastapi import Request, HTTPException, Depends

from backend.auth import get_current_user
from backend.db import User

# key -> list of request timestamps (seconds)
_HITS: dict = defaultdict(list)

SCAN_LIMIT = 20       # max requests
SCAN_WINDOW = 60      # per this many seconds


def _client_ip(request: Request) -> str:
    # honor a reverse proxy header if present, else the socket peer
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _check(key: str, limit: int, window: int) -> None:
    now = time.time()
    hits = _HITS[key]
    # drop timestamps outside the window
    cutoff = now - window
    hits[:] = [t for t in hits if t >= cutoff]
    if len(hits) >= limit:
        retry = int(window - (now - hits[0])) + 1
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded. Try again in {retry}s.",
            headers={"Retry-After": str(retry)},
        )
    hits.append(now)


def scan_rate_limit(
    request: Request,
    user: User | None = Depends(get_current_user),
) -> None:
    """FastAPI dependency: enforces the scan rate limit per user (or per IP)."""
    key = f"user:{user.id}" if user else f"ip:{_client_ip(request)}"
    _check(key, SCAN_LIMIT, SCAN_WINDOW)
