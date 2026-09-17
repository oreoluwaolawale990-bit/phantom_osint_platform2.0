"""Email validation, MX sanity, disposable detection, Gravatar and breach checks."""

from __future__ import annotations

import asyncio
import hashlib
import re
from typing import Any
from urllib.parse import quote

import dns.exception
import dns.resolver
import httpx

EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]{1,64}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")

# Small embedded denylist keeps the application fully functional even if the remote
# provider is unavailable. The list is intentionally conservative and not exhaustive.
COMMON_DISPOSABLE_DOMAINS = {
    "10minutemail.com", "10minutemail.net", "guerrillamail.com", "mailinator.com",
    "tempmail.com", "temp-mail.org", "throwawaymail.com", "yopmail.com", "getnada.com",
    "sharklasers.com", "grr.la", "dispostable.com", "maildrop.cc", "emailondeck.com",
    "mohmal.com", "fakeinbox.com", "trashmail.com", "mintemail.com", "mailnesia.com",
}


def _mx_lookup_sync(domain: str) -> list[str]:
    try:
        resolver = dns.resolver.Resolver(configure=True)
        answers = resolver.resolve(domain, "MX", lifetime=4.0)
        return [f"{a.preference} {a.exchange.to_text().rstrip('.') }" for a in answers]
    except Exception:
        return []


async def _xon_breach_check(client: httpx.AsyncClient, email: str) -> dict[str, Any]:
    try:
        url = f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='@.+_-') }"
        response = await client.get(url)
        if response.status_code == 429:
            return {"status": "rate_limited", "breaches": []}
        if response.status_code == 404:
            return {"status": "not_found", "breaches": []}
        response.raise_for_status()
        payload = response.json()
        breaches: list[str] = []
        raw = payload.get("breaches") if isinstance(payload, dict) else None
        if isinstance(raw, list):
            for group in raw:
                if isinstance(group, list):
                    breaches.extend(str(x) for x in group)
                elif isinstance(group, str):
                    breaches.append(group)
        return {"status": "found" if breaches else "clear", "breaches": sorted(set(breaches))[:100], "raw": payload}
    except Exception as exc:
        return {"status": "unavailable", "breaches": [], "error": type(exc).__name__}


async def lookup_email(email: str) -> dict[str, Any]:
    normalized = email.strip().lower()
    if len(normalized) > 254 or not EMAIL_RE.fullmatch(normalized):
        return {"ok": False, "error": "Enter a syntactically valid email address."}

    try:
        local, domain = normalized.rsplit("@", 1)
        disposable = domain in COMMON_DISPOSABLE_DOMAINS
        mx_records = await asyncio.wait_for(asyncio.to_thread(_mx_lookup_sync, domain), timeout=8)
        gravatar_hash = hashlib.md5(normalized.encode("utf-8"), usedforsecurity=False).hexdigest()
        gravatar_url = f"https://www.gravatar.com/avatar/{gravatar_hash}?d=404"

        timeout = httpx.Timeout(7.0, connect=4.0)
        headers = {"User-Agent": "Phantom-OSINT/1.0"}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=False) as client:
            try:
                avatar_response = await client.head(gravatar_url)
                gravatar_found = avatar_response.status_code == 200
            except Exception:
                gravatar_found = False
            breach = await _xon_breach_check(client, normalized)

        return {
            "ok": True,
            "data": {
                "email": normalized,
                "local_part_length": len(local),
                "domain": domain,
                "mx": mx_records,
                "mx_present": bool(mx_records),
                "disposable": disposable,
                "gravatar": {"hash": gravatar_hash, "profile_or_avatar_found": gravatar_found, "url": gravatar_url},
                "breach": breach,
                "notes": [
                    "A clear breach result only means the queried public database returned no matching record.",
                    "A disposable-domain result is based on a conservative built-in list.",
                ],
            },
        }
    except Exception as exc:
        return {"ok": False, "error": f"Email lookup failed safely: {type(exc).__name__}"}
