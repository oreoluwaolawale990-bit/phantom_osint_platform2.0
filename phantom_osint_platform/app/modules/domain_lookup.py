"""Domain, DNS, SSL/TLS and WHOIS intelligence."""

from __future__ import annotations

import asyncio
import re
import socket
import ssl
from datetime import date, datetime
from typing import Any
from urllib.parse import quote

import dns.exception
import dns.resolver
import httpx
import whois

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$")
DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA")


def normalize_domain(value: str) -> str | None:
    candidate = value.strip().lower().rstrip(".")
    if candidate.startswith("http://") or candidate.startswith("https://"):
        candidate = candidate.split("://", 1)[1].split("/", 1)[0]
    if ":" in candidate and candidate.count(":") == 1:
        candidate = candidate.split(":", 1)[0]
    return candidate if DOMAIN_RE.fullmatch(candidate) else None


def _stringify(value: Any) -> Any:
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, (list, tuple, set)):
        return [_stringify(item) for item in value]
    if isinstance(value, dict):
        return {str(k): _stringify(v) for k, v in value.items()}
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    return str(value)


def _lookup_record(resolver: dns.resolver.Resolver, domain: str, record_type: str) -> list[str]:
    try:
        answers = resolver.resolve(domain, record_type, lifetime=4.0)
        results: list[str] = []
        for answer in answers:
            if record_type == "MX":
                results.append(f"{answer.preference} {answer.exchange.to_text().rstrip('.')}")
            elif record_type == "SOA":
                results.append(answer.to_text())
            elif record_type == "TXT":
                chunks = getattr(answer, "strings", None)
                if chunks:
                    results.append("".join(chunk.decode("utf-8", errors="replace") for chunk in chunks))
                else:
                    results.append(answer.to_text().strip('"'))
            else:
                results.append(answer.to_text().rstrip("."))
        return results
    except (dns.exception.DNSException, OSError, TimeoutError):
        return []
    except Exception:
        return []


def _dns_lookup_sync(domain: str) -> dict[str, list[str]]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 3.0
    resolver.lifetime = 4.0
    return {record: _lookup_record(resolver, domain, record) for record in DNS_TYPES}


def _ssl_lookup_sync(domain: str) -> dict[str, Any]:
    context = ssl.create_default_context()
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    with socket.create_connection((domain, 443), timeout=5) as raw_socket:
        with context.wrap_socket(raw_socket, server_hostname=domain) as tls_socket:
            cert = tls_socket.getpeercert()
            cipher = tls_socket.cipher()
            version = tls_socket.version()
    subject = {key: value for part in cert.get("subject", ()) for key, value in part}
    issuer = {key: value for part in cert.get("issuer", ()) for key, value in part}
    san = [value for key, value in cert.get("subjectAltName", ()) if key == "DNS"]
    return {
        "subject": subject,
        "issuer": issuer,
        "serial_number": cert.get("serialNumber"),
        "version": cert.get("version"),
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
        "subject_alt_names": san[:100],
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
    }


def _whois_lookup_sync(domain: str) -> dict[str, Any]:
    record = whois.whois(domain)
    data: dict[str, Any] = {}
    for key in (
        "domain_name",
        "registrar",
        "creation_date",
        "updated_date",
        "expiration_date",
        "name_servers",
        "status",
        "emails",
        "org",
        "country",
        "state",
        "city",
    ):
        try:
            data[key] = _stringify(getattr(record, key, None))
        except Exception:
            data[key] = None
    return data


async def _ct_lookup(client: httpx.AsyncClient, domain: str) -> list[str]:
    try:
        url = f"https://crt.sh/?q={quote('%.' + domain)}&output=json"
        response = await client.get(url)
        response.raise_for_status()
        rows = response.json()
        names: set[str] = set()
        if isinstance(rows, list):
            for row in rows[:2000]:
                for name in str(row.get("name_value", "")).splitlines():
                    clean = name.strip().lower().lstrip("*.")
                    if clean == domain or clean.endswith("." + domain):
                        names.add(clean)
        return sorted(names)[:500]
    except Exception:
        return []


async def lookup_domain(value: str) -> dict[str, Any]:
    domain = normalize_domain(value)
    if not domain:
        return {"ok": False, "error": "Enter a valid domain such as example.com."}

    try:
        dns_result, ssl_result, whois_result = await asyncio.gather(
            asyncio.wait_for(asyncio.to_thread(_dns_lookup_sync, domain), timeout=12),
            asyncio.wait_for(asyncio.to_thread(_ssl_lookup_sync, domain), timeout=10),
            asyncio.wait_for(asyncio.to_thread(_whois_lookup_sync, domain), timeout=15),
            return_exceptions=True,
        )
        timeout = httpx.Timeout(8.0, connect=5.0)
        headers = {"User-Agent": "Phantom-OSINT/1.0"}
        async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=False) as client:
            subdomains = await _ct_lookup(client, domain)

        def normalize_result(value: Any, default: Any) -> Any:
            if isinstance(value, Exception):
                return default
            return value

        return {
            "ok": True,
            "data": {
                "domain": domain,
                "dns": normalize_result(dns_result, {}),
                "ssl": normalize_result(ssl_result, {"error": "TLS certificate could not be retrieved."}),
                "whois": normalize_result(whois_result, {"error": "WHOIS lookup failed or is unsupported for this TLD."}),
                "certificate_transparency": subdomains,
            },
        }
    except Exception as exc:
        return {"ok": False, "error": f"Domain lookup failed safely: {type(exc).__name__}"}
