"""Defensive web target auditor with SSRF protections."""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

USER_AGENT = "Phantom-OSINT/1.0"
MAX_BODY = 1_000_000
MAX_REDIRECTS = 3

SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
    "permissions-policy": "Permissions-Policy",
}

TECH_SIGNATURES = {
    "WordPress": [re.compile(r"wp-content", re.I), re.compile(r"wordpress", re.I)],
    "Next.js": [re.compile(r"__next_data__", re.I), re.compile(r"/_next/", re.I)],
    "React": [re.compile(r"data-reactroot", re.I)],
    "Vue": [re.compile(r"data-v-", re.I)],
    "Django": [re.compile(r"csrfmiddlewaretoken", re.I)],
    "Joomla": [re.compile(r"joomla", re.I)],
    "Shopify": [re.compile(r"cdn\.shopify\.com", re.I), re.compile(r"shopify", re.I)],
    "Cloudflare": [re.compile(r"cf-ray", re.I)],
}


class PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.in_title = False
        self.meta: list[dict[str, str]] = []
        self.links: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        attrs_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag.lower() == "title":
            self.in_title = True
        if tag.lower() == "meta":
            self.meta.append(attrs_dict)
        if tag.lower() == "a" and attrs_dict.get("href"):
            self.links.append({"href": attrs_dict["href"]})

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self.in_title = False

    def handle_data(self, data: str) -> None:
        if self.in_title:
            self.title = (self.title + " " + data.strip()).strip()[:300]


async def _resolve_public(hostname: str) -> list[str]:
    def resolve() -> list[str]:
        results: set[str] = set()
        for family, _, _, _, sockaddr in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM):
            try:
                ip = ipaddress.ip_address(sockaddr[0])
            except ValueError:
                continue
            if (
                ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
                or ip.is_reserved or ip.is_unspecified
            ):
                raise ValueError(f"Unsafe destination address: {ip}")
            if family in {socket.AF_INET, socket.AF_INET6}:
                results.add(str(ip))
        return sorted(results)

    return await asyncio.to_thread(resolve)


def _validate_url(value: str) -> str | None:
    candidate = value.strip()
    if not candidate.startswith(("http://", "https://")):
        candidate = "https://" + candidate
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    if parsed.username or parsed.password:
        return None
    return candidate


async def _safe_request(client: httpx.AsyncClient, url: str) -> tuple[httpx.Response | None, str, list[str]]:
    current = url
    redirects = 0
    resolved: list[str] = []
    while redirects <= MAX_REDIRECTS:
        parsed = urlparse(current)
        if not parsed.hostname:
            return None, current, resolved
        try:
            resolved = await _resolve_public(parsed.hostname)
        except Exception:
            return None, current, resolved
        try:
            response = await client.get(current, follow_redirects=False)
        except Exception:
            return None, current, resolved
        if response.status_code not in {301, 302, 303, 307, 308}:
            return response, current, resolved
        location = response.headers.get("location")
        if not location:
            return response, current, resolved
        redirects += 1
        current = urljoin(current, location)
    return None, current, resolved


def _technology_detect(body: str, headers: dict[str, str]) -> list[str]:
    haystack = body[:MAX_BODY]
    header_text = "\n".join(f"{k}: {v}" for k, v in headers.items())
    result: list[str] = []
    for tech, patterns in TECH_SIGNATURES.items():
        if any(pattern.search(haystack) or pattern.search(header_text) for pattern in patterns):
            result.append(tech)
    server = headers.get("server")
    powered = headers.get("x-powered-by")
    if server:
        result.append(f"Server: {server}")
    if powered:
        result.append(f"X-Powered-By: {powered}")
    return sorted(set(result))


async def _fetch_text_file(client: httpx.AsyncClient, base_url: str, path: str) -> str:
    target = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
    parsed = urlparse(target)
    try:
        await _resolve_public(parsed.hostname or "")
        response = await client.get(target, follow_redirects=False)
        if response.status_code == 200:
            return response.text[:100_000]
    except Exception:
        pass
    return ""


async def audit_url(value: str) -> dict[str, Any]:
    url = _validate_url(value)
    if not url:
        return {"ok": False, "error": "Enter a valid http:// or https:// URL without embedded credentials."}

    try:
        timeout = httpx.Timeout(9.0, connect=5.0, read=8.0)
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,application/xhtml+xml"}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, verify=True) as client:
            response, final_url, resolved_ips = await _safe_request(client, url)
            if response is None:
                return {"ok": False, "error": "Target could not be safely fetched or resolved to a public address."}

            body = response.text[:MAX_BODY]
            response_headers = {k.lower(): v for k, v in response.headers.items()}
            missing_headers = [label for key, label in SECURITY_HEADERS.items() if key not in response_headers]
            present_headers = {label: response_headers[key] for key, label in SECURITY_HEADERS.items() if key in response_headers}

            parser = PageParser()
            try:
                parser.feed(body)
            except Exception:
                pass
            meta = parser.meta[:50]
            meta_map = {
                (item.get("name") or item.get("property") or "").lower(): item.get("content", "")
                for item in meta
                if item.get("name") or item.get("property")
            }

            base = f"{urlparse(final_url).scheme}://{urlparse(final_url).netloc}/"
            robots, sitemap = await asyncio.gather(
                _fetch_text_file(client, base, "/robots.txt"),
                _fetch_text_file(client, base, "/sitemap.xml"),
            )

        return {
            "ok": True,
            "data": {
                "requested_url": url,
                "final_url": final_url,
                "status_code": response.status_code,
                "resolved_ips": resolved_ips,
                "content_type": response_headers.get("content-type"),
                "server": response_headers.get("server"),
                "security_headers": {"present": present_headers, "missing": missing_headers},
                "technology": _technology_detect(body, response_headers),
                "page": {
                    "title": parser.title,
                    "meta": meta_map,
                    "links_sample": parser.links[:50],
                },
                "robots": {
                    "found": bool(robots),
                    "preview": robots[:5000],
                },
                "sitemap": {
                    "found": bool(sitemap),
                    "preview": sitemap[:5000],
                },
            },
        }
    except Exception as exc:
        return {"ok": False, "error": f"URL audit failed safely: {type(exc).__name__}"}
