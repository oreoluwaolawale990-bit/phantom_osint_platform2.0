"""FastAPI entry point for Phantom OSINT & Cybersecurity Intelligence Platform."""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque
from pathlib import Path
from typing import Any

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.status import HTTP_404_NOT_FOUND

from app.modules.cyber_utils import (
    cidr_calculate,
    generate_dorks,
    hash_text,
    identify_hash,
    password_entropy,
    webhook_payload,
    webhook_security_notes,
)
from app.modules.domain_lookup import lookup_domain
from app.modules.email_lookup import lookup_email
from app.modules.ip_lookup import lookup_ip
from app.modules.url_auditor import audit_url
from app.modules.username_lookup import lookup_username

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"

app = FastAPI(
    title="Phantom OSINT & Cybersecurity Intelligence Platform",
    version="1.0.0"
)

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
_rate_buckets: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = asyncio.Lock()
RATE_LIMIT = 80
RATE_WINDOW = 60.0


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        try:
            response = await call_next(request)
        except Exception:
            raise
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "same-origin")
        response.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
        response.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        response.headers.setdefault("Cache-Control", "no-store")
        return response


app.add_middleware(SecurityHeadersMiddleware)


async def _allow_request(client_ip: str) -> bool:
    now = time.monotonic()
    async with _rate_lock:
        bucket = _rate_buckets[client_ip]
        while bucket and now - bucket[0] > RATE_WINDOW:
            bucket.popleft()
        if len(bucket) >= RATE_LIMIT:
            return False
        bucket.append(now)
        if len(_rate_buckets) > 5000:
            stale = [key for key, values in _rate_buckets.items() if not values or now - values[-1] > RATE_WINDOW * 2]
            for key in stale[:1000]:
                _rate_buckets.pop(key, None)
        return True


@app.middleware("http")
async def request_guard(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    if not await _allow_request(client_ip):
        return JSONResponse({"ok": False, "error": "Rate limit reached. Please slow down and retry shortly."}, status_code=429)
    try:
        return await call_next(request)
    except Exception as exc:
        return JSONResponse({"ok": False, "error": "Unexpected server error handled safely."}, status_code=500)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(_: Request, exc: RequestValidationError):
    return JSONResponse({"ok": False, "error": "Invalid request.", "details": exc.errors()}, status_code=422)


@app.exception_handler(Exception)
async def generic_exception_handler(_: Request, exc: Exception):
    return JSONResponse({"ok": False, "error": "Unexpected server error handled safely.", "type": type(exc).__name__}, status_code=500)


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, Any]:
    return {"ok": True, "service": "phantom-osint", "version": app.version, "status": "online"}


@app.get("/api/ip")
async def api_ip(target: str = "") -> dict[str, Any]:
    return await lookup_ip(target)


@app.get("/api/domain")
async def api_domain(domain: str = "") -> dict[str, Any]:
    return await lookup_domain(domain)


@app.get("/api/username")
async def api_username(username: str = "") -> dict[str, Any]:
    return await lookup_username(username)


@app.get("/api/email")
async def api_email(email: str = "") -> dict[str, Any]:
    return await lookup_email(email)


@app.get("/api/url")
async def api_url(url: str = "") -> dict[str, Any]:
    return await audit_url(url)


@app.post("/api/hash")
async def api_hash(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        value = str(payload.get("value", ""))
        if not value or len(value) > 100_000:
            return {"ok": False, "error": "Provide 1-100000 characters."}
        result: dict[str, Any] = {"identifier": identify_hash(value)}
        if payload.get("algorithm"):
            result["generated"] = hash_text(value, str(payload.get("algorithm")))
        return {"ok": True, "data": result}
    except Exception as exc:
        return {"ok": False, "error": f"Hash utility failed safely: {type(exc).__name__}"}


@app.get("/api/dorks")
async def api_dorks(target: str = "", kind: str = "exposure", keyword: str = "", extension: str = "") -> dict[str, Any]:
    try:
        return {"ok": True, "data": {"queries": generate_dorks(target, kind, keyword, extension)}}
    except Exception as exc:
        return {"ok": False, "error": f"Dork generator failed safely: {type(exc).__name__}"}


@app.get("/api/cidr")
async def api_cidr(cidr: str = "") -> dict[str, Any]:
    try:
        return {"ok": True, "data": cidr_calculate(cidr)}
    except Exception as exc:
        return {"ok": False, "error": f"CIDR calculator failed safely: {type(exc).__name__}"}


@app.post("/api/webhook")
async def api_webhook(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        event = str(payload.get("event", "test"))[:64]
        target = str(payload.get("url", ""))[:500]
        return {"ok": True, "data": {"payload": webhook_payload(event), "notes": webhook_security_notes(target)}}
    except Exception as exc:
        return {"ok": False, "error": f"Webhook helper failed safely: {type(exc).__name__}"}


@app.post("/api/entropy")
async def api_entropy(payload: dict[str, Any]) -> dict[str, Any]:
    try:
        password = str(payload.get("password", ""))
        if len(password) > 512:
            return {"ok": False, "error": "Password input is limited to 512 characters."}
        return {"ok": True, "data": password_entropy(password)}
    except Exception as exc:
        return {"ok": False, "error": f"Entropy evaluator failed safely: {type(exc).__name__}"}


@app.get("/{path:path}", include_in_schema=False)
async def spa_fallback(path: str):
    # Never expose arbitrary filesystem content. Unknown paths receive a JSON 404.
    return JSONResponse({"ok": False, "error": "Route not found.", "path": f"/{path}"}, status_code=HTTP_404_NOT_FOUND)
