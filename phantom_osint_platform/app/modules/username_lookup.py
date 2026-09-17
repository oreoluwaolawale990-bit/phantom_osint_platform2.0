"""Concurrent public username footprint checks across major platforms.

The module only performs ordinary GET requests to public profile URLs. It never
attempts authentication, CAPTCHA bypassing, rate-limit evasion or scraping of
private content.
"""

from __future__ import annotations

import asyncio
import re
from typing import Any
from urllib.parse import quote

import httpx

USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{2,50}$")

PLATFORMS: tuple[dict[str, str], ...] = (
    {"name": "GitHub", "url": "https://github.com/{u}", "category": "code"},
    {"name": "GitLab", "url": "https://gitlab.com/{u}", "category": "code"},
    {"name": "Reddit", "url": "https://www.reddit.com/user/{u}/", "category": "social"},
    {"name": "X / Twitter", "url": "https://x.com/{u}", "category": "social"},
    {"name": "Instagram", "url": "https://www.instagram.com/{u}/", "category": "social"},
    {"name": "TikTok", "url": "https://www.tiktok.com/@{u}", "category": "social"},
    {"name": "Medium", "url": "https://medium.com/@{u}", "category": "publishing"},
    {"name": "Dev.to", "url": "https://dev.to/{u}", "category": "code"},
    {"name": "Product Hunt", "url": "https://www.producthunt.com/@{u}", "category": "tech"},
    {"name": "Telegram", "url": "https://t.me/{u}", "category": "messaging"},
    {"name": "Steam", "url": "https://steamcommunity.com/id/{u}", "category": "gaming"},
    {"name": "CodePen", "url": "https://codepen.io/{u}", "category": "code"},
    {"name": "Stack Overflow", "url": "https://stackoverflow.com/users/{u}", "category": "code"},
    {"name": "npm", "url": "https://www.npmjs.com/~{u}", "category": "code"},
    {"name": "PyPI", "url": "https://pypi.org/user/{u}/", "category": "code"},
    {"name": "Hugging Face", "url": "https://huggingface.co/{u}", "category": "ai"},
    {"name": "Kaggle", "url": "https://www.kaggle.com/{u}", "category": "data"},
    {"name": "Behance", "url": "https://www.behance.net/{u}", "category": "creative"},
    {"name": "Dribbble", "url": "https://dribbble.com/{u}", "category": "creative"},
    {"name": "Pinterest", "url": "https://www.pinterest.com/{u}/", "category": "social"},
    {"name": "Vimeo", "url": "https://vimeo.com/{u}", "category": "media"},
    {"name": "Twitch", "url": "https://www.twitch.tv/{u}", "category": "gaming"},
    {"name": "SoundCloud", "url": "https://soundcloud.com/{u}", "category": "media"},
    {"name": "Keybase", "url": "https://keybase.io/{u}", "category": "security"},
    {"name": "Linktree", "url": "https://linktr.ee/{u}", "category": "social"},
    {"name": "Buy Me a Coffee", "url": "https://www.buymeacoffee.com/{u}", "category": "creator"},
    {"name": "Patreon", "url": "https://www.patreon.com/{u}", "category": "creator"},
    {"name": "Flickr", "url": "https://www.flickr.com/people/{u}/", "category": "media"},
    {"name": "DeviantArt", "url": "https://www.deviantart.com/{u}", "category": "creative"},
    {"name": "Replit", "url": "https://replit.com/@{u}", "category": "code"},
    {"name": "Hashnode", "url": "https://hashnode.com/@{u}", "category": "publishing"},
    {"name": "Gravatar", "url": "https://gravatar.com/{u}", "category": "identity"},
    {"name": "About.me", "url": "https://about.me/{u}", "category": "identity"},
)


def _status_from_response(response: httpx.Response) -> tuple[str, str]:
    code = response.status_code
    if 200 <= code < 400:
        return "found", f"HTTP {code}"
    if code == 404:
        return "not_found", "HTTP 404"
    if code in {401, 403, 429}:
        return "blocked", f"HTTP {code}"
    return "unknown", f"HTTP {code}"


async def _check_one(client: httpx.AsyncClient, item: dict[str, str], username: str, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    url = item["url"].format(u=quote(username, safe="._-@"))
    async with semaphore:
        try:
            response = await client.get(url, headers={"Accept": "text/html,application/json;q=0.9,*/*;q=0.8"})
            status, detail = _status_from_response(response)
            return {
                "platform": item["name"],
                "category": item["category"],
                "status": status,
                "detail": detail,
                "url": url,
            }
        except httpx.TimeoutException:
            return {"platform": item["name"], "category": item["category"], "status": "timeout", "detail": "Timed out", "url": url}
        except httpx.RequestError as exc:
            return {"platform": item["name"], "category": item["category"], "status": "error", "detail": type(exc).__name__, "url": url}
        except Exception as exc:
            return {"platform": item["name"], "category": item["category"], "status": "error", "detail": type(exc).__name__, "url": url}


async def lookup_username(username: str) -> dict[str, Any]:
    normalized = username.strip().lstrip("@").strip()
    if not USERNAME_RE.fullmatch(normalized):
        return {"ok": False, "error": "Username must be 2-50 characters using letters, digits, dot, underscore or hyphen."}

    try:
        timeout = httpx.Timeout(8.0, connect=5.0)
        headers = {"User-Agent": "Phantom-OSINT/1.0"}
        semaphore = asyncio.Semaphore(8)
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=True, max_redirects=3) as client:
            tasks = [_check_one(client, item, normalized, semaphore) for item in PLATFORMS]
            results = await asyncio.gather(*tasks, return_exceptions=True)

        clean_results: list[dict[str, Any]] = []
        for index, result in enumerate(results):
            if isinstance(result, Exception):
                clean_results.append({
                    "platform": PLATFORMS[index]["name"],
                    "category": PLATFORMS[index]["category"],
                    "status": "error",
                    "detail": type(result).__name__,
                    "url": PLATFORMS[index]["url"].format(u=quote(normalized)),
                })
            else:
                clean_results.append(result)

        counts: dict[str, int] = {}
        for result in clean_results:
            counts[result["status"]] = counts.get(result["status"], 0) + 1
        return {"ok": True, "data": {"username": normalized, "total": len(clean_results), "counts": counts, "results": clean_results}}
    except Exception as exc:
        return {"ok": False, "error": f"Username checks failed safely: {type(exc).__name__}"}
