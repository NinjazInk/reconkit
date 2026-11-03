"""Shared HTTP helpers."""
from __future__ import annotations

import requests

USER_AGENT = "reconkit/0.1 (+security research tool)"
DEFAULT_TIMEOUT = 15


def make_session(user_agent: str = USER_AGENT) -> requests.Session:
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent, "Accept": "*/*"})
    return s


def normalize_url(target: str) -> str:
    """Add a scheme if the user passed a bare host like 'example.com'."""
    target = target.strip()
    if "://" not in target:
        target = "https://" + target
    return target


def get_set_cookies(resp: requests.Response) -> list[str]:
    """Return every raw Set-Cookie header (requests folds duplicates otherwise)."""
    raw = getattr(resp, "raw", None)
    headers = getattr(raw, "headers", None)
    if headers is not None and hasattr(headers, "getlist"):
        values = headers.getlist("Set-Cookie")
        if values:
            return list(values)
    value = resp.headers.get("Set-Cookie")
    return [value] if value else []
