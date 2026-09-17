"""Local defensive cybersecurity utilities.

Includes hash identification/generation, safe search-query builders, CIDR math,
a benign webhook payload generator, and password entropy estimation.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import secrets
from collections import Counter
from typing import Any
from urllib.parse import quote_plus

HASH_PATTERNS = (
    ("bcrypt", re.compile(r"^\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("MD5", re.compile(r"^[a-fA-F0-9]{32}$")),
    ("SHA-1", re.compile(r"^[a-fA-F0-9]{40}$")),
    ("SHA-256", re.compile(r"^[a-fA-F0-9]{64}$")),
    ("SHA-512", re.compile(r"^[a-fA-F0-9]{128}$")),
    ("NTLM (possible; same 32-hex shape as MD5)", re.compile(r"^[a-fA-F0-9]{32}$")),
)

DORK_TEMPLATES = {
    "exposure": [
        'site:{target} "index of /"',
        'site:{target} ext:log "error"',
        'site:{target} ext:txt "password"',
    ],
    "documents": [
        'site:{target} filetype:pdf',
        'site:{target} filetype:docx',
        'site:{target} filetype:xlsx',
    ],
    "admin": [
        'site:{target} inurl:admin',
        'site:{target} inurl:login',
    ],
    "backup": [
        'site:{target} ext:bak',
        'site:{target} ext:old',
        'site:{target} ext:zip backup',
    ],
}


def identify_hash(value: str) -> dict[str, Any]:
    candidate = value.strip()
    matches = [name for name, pattern in HASH_PATTERNS if pattern.fullmatch(candidate)]
    unique: list[str] = []
    for match in matches:
        if match not in unique:
            unique.append(match)
    if candidate.startswith("$2") and "bcrypt" in unique:
        confidence = "high"
    elif len(unique) == 1:
        confidence = "medium"
    elif unique:
        confidence = "ambiguous"
    else:
        confidence = "unknown"
    return {
        "input_length": len(candidate),
        "possible_types": unique,
        "confidence": confidence,
        "note": "Hash identification by shape is heuristic; MD5 and NTLM are intentionally ambiguous when represented as 32 hex characters.",
    }


def hash_text(value: str, algorithm: str) -> dict[str, str]:
    allowed = {"md5", "sha1", "sha256", "sha512", "sha3_256", "sha3_512", "blake2b", "blake2s"}
    algorithm = algorithm.lower().replace("-", "")
    if algorithm not in allowed:
        raise ValueError("Unsupported algorithm.")
    digest = hashlib.new(algorithm, value.encode("utf-8")).hexdigest()
    return {"algorithm": algorithm, "hex": digest}


def generate_dorks(target: str, kind: str, keyword: str = "", extension: str = "") -> list[str]:
    clean = target.strip().replace("https://", "").replace("http://", "").split("/", 1)[0]
    if not re.fullmatch(r"[A-Za-z0-9.-]{1,253}", clean):
        raise ValueError("Target must be a domain or hostname.")
    templates = DORK_TEMPLATES.get(kind, DORK_TEMPLATES["exposure"])
    queries = [t.format(target=clean) for t in templates]
    if keyword.strip():
        queries = [f'{query} "{keyword.strip()[:80]}"' for query in queries]
    if extension.strip():
        ext = re.sub(r"[^A-Za-z0-9]", "", extension)[:10]
        queries.append(f"site:{clean} filetype:{ext}")
    return queries[:20]


def cidr_calculate(cidr: str) -> dict[str, Any]:
    network = ipaddress.ip_network(cidr.strip(), strict=False)
    hosts = network.num_addresses
    if network.version == 4:
        usable = 0 if network.prefixlen >= 31 else max(0, hosts - 2)
        first = str(network.network_address) if network.prefixlen >= 31 else str(network.network_address + 1)
        last = str(network.broadcast_address) if network.prefixlen >= 31 else str(network.broadcast_address - 1)
        broadcast = str(network.broadcast_address)
    else:
        usable = max(0, hosts - 1)
        first = str(network.network_address + 1)
        last = str(network.network_address + hosts - 1) if hosts > 1 else str(network.network_address)
        broadcast = None
    return {
        "network": str(network.network_address),
        "prefix_length": network.prefixlen,
        "netmask": str(network.netmask) if network.version == 4 else None,
        "broadcast": broadcast,
        "total_addresses": hosts,
        "usable_hosts": usable,
        "first_usable": first,
        "last_usable": last,
        "version": network.version,
    }


def webhook_payload(event: str = "test") -> dict[str, Any]:
    # Deliberately generates data only; it never sends requests or executes a payload.
    token = secrets.token_hex(8)
    return {
        "event": event.strip()[:64] or "test",
        "message": "Phantom benign webhook test payload",
        "request_id": token,
        "timestamp": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat(),
        "safe": True,
    }


def password_entropy(password: str) -> dict[str, Any]:
    value = password
    if not value:
        return {"length": 0, "entropy_bits": 0.0, "score": 0, "label": "empty", "feedback": ["Use a long, unique passphrase rather than a short reusable password."]}

    alphabet = 0
    groups: dict[str, int] = {
        "lower": bool(re.search(r"[a-z]", value)),
        "upper": bool(re.search(r"[A-Z]", value)),
        "digits": bool(re.search(r"\d", value)),
        "symbols": bool(re.search(r"[^A-Za-z0-9]", value)),
    }
    if groups["lower"]:
        alphabet += 26
    if groups["upper"]:
        alphabet += 26
    if groups["digits"]:
        alphabet += 10
    if groups["symbols"]:
        alphabet += 32
    entropy = len(value) * math.log2(max(alphabet, 1))

    repeats = sum(count - 1 for count in Counter(value).values() if count > 1)
    if repeats:
        entropy -= min(entropy * 0.25, repeats * 1.5)
    if re.search(r"(1234|password|qwerty|letmein|admin|welcome|iloveyou)", value.lower()):
        entropy *= 0.55

    entropy = max(0.0, round(entropy, 1))
    score = 0
    if entropy >= 80:
        score = 4
        label = "very strong"
    elif entropy >= 60:
        score = 3
        label = "strong"
    elif entropy >= 40:
        score = 2
        label = "moderate"
    elif entropy >= 25:
        score = 1
        label = "weak"
    else:
        label = "very weak"

    feedback: list[str] = []
    if len(value) < 12:
        feedback.append("Aim for 12+ characters; longer is generally better.")
    if not groups["upper"] or not groups["lower"]:
        feedback.append("Mixing character classes can help when it does not reduce memorability.")
    if value.lower() in {"password", "password123", "admin", "letmein", "welcome"}:
        feedback.append("Avoid common dictionary and default passwords.")
    if repeats >= max(2, len(value) // 3):
        feedback.append("Avoid long runs of repeated characters.")
    if not feedback:
        feedback.append("Use this password only for one service and store it in a trusted password manager.")

    return {"length": len(value), "entropy_bits": entropy, "score": score, "label": label, "character_classes": groups, "feedback": feedback}


def webhook_security_notes(url: str) -> list[str]:
    return [
        "Only send benign test data to endpoints you own or have permission to test.",
        "Keep webhook secrets out of browser code and public repositories.",
        f"Validated helper target: {quote_plus(url.strip())[:120]}" if url.strip() else "No target supplied; payload generation is local only.",
    ]
