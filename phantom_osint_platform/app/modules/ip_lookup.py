"""Network and IP intelligence helpers.

All external calls are public/keyless and bounded by timeouts. Errors are returned
as structured data instead of being raised into the FastAPI layer.
"""

from __future__ import annotations

import asyncio
import ipaddress
import time
from typing import Any

import httpx

IP_API_URL = "http://ip-api.com/json/{ip}"
IPINFO_URL = "https://ipinfo.io/{ip}/json"
TOR_EXIT_LIST_URL = "https://check.torproject.org/torbulkexitlist"

_TOR_CACHE: dict[str, Any] = {"expires": 0.0, "entries": set()}
_TOR_LOCK = asyncio.Lock()


def _safe_ip(value: str) -> str | None:
    try:
        obj = ipaddress.ip_address(value.strip())
        return str(obj)
    except ValueError:
        return None


async def _get_json(client: httpx.AsyncClient, url: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
    try:
        response = await client.get(url, params=params)
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else {"_raw": data}
    except Exception as exc:
        return {"_error": f"request_failed: {type(exc).__name__}"}


async def _fetch_tor_exits(client: httpx.AsyncClient) -> set[str]:
    now = time.monotonic()
    if _TOR_CACHE["expires"] > now:
        return _TOR_CACHE["entries"]

    async with _TOR_LOCK:
        now = time.monotonic()
        if _TOR_CACHE["expires"] > now:
            return _TOR_CACHE["entries"]
        try:
            response = await client.get(TOR_EXIT_LIST_URL)
            response.raise_for_status()
            entries = {
                line.strip()
                for line in response.text.splitlines()
                if line.strip() and not line.strip().startswith("#")
            }
            _TOR_CACHE["entries"] = entries
            _TOR_CACHE["expires"] = time.monotonic() + 900
            return entries
        except Exception:
            _TOR_CACHE["entries"] = set()
            _TOR_CACHE["expires"] = time.monotonic() + 120
            return set()


def _classify_risk(data: dict[str, Any], ip: str, tor_entries: set[str]) -> dict[str, Any]:
    flags: list[str] = []
    if ip in tor_entries:
        flags.append("tor_exit_node")
    if data.get("proxy") is True:
        flags.append("proxy_or_vpn")
    if data.get("hosting") is True:
        flags.append("hosting_or_datacenter")

    special = ipaddress.ip_address(ip)
    if special.is_private:
        flags.append("private_address")
    elif special.is_loopback:
        flags.append("loopback")
    elif special.is_reserved:
        flags.append("reserved_address")
    elif special.is_multicast:
        flags.append("multicast")

    score = min(100, len(flags) * 25)
    label = "low"
    if score >= 75:
        label = "high"
    elif score >= 50:
        label = "medium"
    return {"score": score, "label": label, "flags": flags}


async def lookup_ip(target: str) -> dict[str, Any]:
    """Return geolocation, ASN/ISP and coarse proxy/hosting/Tor risk data."""
    ip = _safe_ip(target)
    if not ip:
        return {"ok": False, "error": "Enter a valid IPv4 or IPv6 address."}

    try:
        timeout = httpx.Timeout(6.0, connect=4.0)
        headers = {"User-Agent": "Phantom-OSINT/1.0"}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=False) as client:
            primary_task = _get_json(
                client,
                IP_API_URL.format(ip=ip),
                {"fields": "status,message,country,countryCode,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,reverse,proxy,hosting,query"},
            )
            fallback_task = _get_json(client, IPINFO_URL.format(ip))
            tor_task = _fetch_tor_exits(client)
            primary, fallback, tor_entries = await asyncio.gather(primary_task, fallback_task, tor_task)

        using_fallback = primary.get("status") != "success"
        if not using_fallback:
            payload = {
                "ip": ip,
                "country": primary.get("country"),
                "country_code": primary.get("countryCode"),
                "region": primary.get("regionName"),
                "city": primary.get("city"),
                "postal": primary.get("zip"),
                "latitude": primary.get("lat"),
                "longitude": primary.get("lon"),
                "timezone": primary.get("timezone"),
                "isp": primary.get("isp"),
                "organization": primary.get("org"),
                "asn": primary.get("as"),
                "asn_name": primary.get("asname"),
                "reverse_dns": primary.get("reverse"),
                "proxy": bool(primary.get("proxy")),
                "hosting": bool(primary.get("hosting")),
                "provider": "ip-api.com",
            }
            risk_source = primary
        else:
            payload = {
                "ip": ip,
                "country": fallback.get("country"),
                "country_code": fallback.get("country"),
                "region": fallback.get("region"),
                "city": fallback.get("city"),
                "postal": fallback.get("postal"),
                "latitude": fallback.get("loc", ",").split(",")[0] if fallback.get("loc") else None,
                "longitude": fallback.get("loc", ",").split(",")[1] if fallback.get("loc") and "," in fallback.get("loc", "") else None,
                "timezone": fallback.get("timezone"),
                "isp": fallback.get("org"),
                "organization": fallback.get("org"),
                "asn": fallback.get("org"),
                "asn_name": fallback.get("org"),
                "reverse_dns": None,
                "proxy": False,
                "hosting": False,
                "provider": "ipinfo.io (fallback)",
            }
            risk_source = {}

        payload["risk"] = _classify_risk(risk_source, ip, tor_entries)
        return {"ok": True, "data": payload}
    except Exception as exc:
        return {"ok": False, "error": f"IP lookup failed safely: {type(exc).__name__}"}
