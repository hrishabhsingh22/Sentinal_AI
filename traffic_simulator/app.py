"""
SENTINEL AI — Local HTTP Traffic Simulator (Stage 1)

A lightweight FastAPI application that serves as a target HTTP server.
Every incoming request is automatically logged to a structured JSON Lines
access log via middleware.  The server provides multiple endpoints that
simulate realistic web-application traffic patterns for later security
analysis.

Run:
    cd traffic_simulator
    uvicorn app:app --host 127.0.0.1 --port 8001 --reload
"""

from __future__ import annotations

import json
import os
import secrets
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote

from fastapi import FastAPI, Form, Query, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates

try:
    from traffic_simulator.parser import (
        RE_CMD_INJECTION,
        RE_LFI,
        RE_SQLI,
        RE_TRAVERSAL,
        RE_XSS,
    )
except ImportError:
    from parser import (
        RE_CMD_INJECTION,
        RE_LFI,
        RE_SQLI,
        RE_TRAVERSAL,
        RE_XSS,
    )

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent
LOG_DIR = BASE_DIR / "logs"
LOG_FILE = LOG_DIR / "access.log"
TEMPLATES_DIR = BASE_DIR / "templates"

# Session configuration
SESSION_COOKIE_NAME = "sentinel_session"
SESSION_INACTIVITY_TIMEOUT = 1800.0  # 30 minutes in seconds
SESSION_MAX_LIFETIME = 86400.0       # 24 hours in seconds
MAX_BODY_INSPECT_BYTES = 65536       # 64 KB in-memory payload inspection limit

# Ensure the logs directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)

# Query-parameter and payload keys whose values must be redacted
SENSITIVE_PARAMS = frozenset({
    "password", "passwd", "pwd", "pass",
    "token", "access_token", "refresh_token",
    "api_key", "apikey", "api-key",
    "secret", "client_secret",
    "authorization", "auth",
    "cookie", "session_id", "sessionid",
    "credit_card", "cc", "cvv", "ssn",
})

# Thread lock for safe concurrent log writes
_log_lock = threading.Lock()

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SENTINEL AI — HTTP Traffic Simulator",
    description=(
        "Stage 1 local traffic generator.  Every request is recorded in a "
        "structured JSON Lines access log for later security analysis."
    ),
    version="1.0.0",
)

templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

# ---------------------------------------------------------------------------
# Sample data
# ---------------------------------------------------------------------------
PRODUCTS = [
    {"id": 1, "name": "Enterprise Firewall Pro", "category": "Network Security", "price": 2499.99, "in_stock": True},
    {"id": 2, "name": "Endpoint Detection Suite", "category": "Endpoint", "price": 899.50, "in_stock": True},
    {"id": 3, "name": "SIEM Analytics Platform", "category": "SIEM", "price": 5200.00, "in_stock": False},
    {"id": 4, "name": "WAF Cloud Shield", "category": "Web Security", "price": 1350.00, "in_stock": True},
    {"id": 5, "name": "Zero-Trust Gateway", "category": "Network Security", "price": 3100.00, "in_stock": True},
    {"id": 6, "name": "Threat Intel Feed", "category": "Intelligence", "price": 750.00, "in_stock": True},
    {"id": 7, "name": "SOC Automation Toolkit", "category": "SIEM", "price": 1800.00, "in_stock": True},
    {"id": 8, "name": "Vulnerability Scanner X", "category": "Scanning", "price": 620.00, "in_stock": False},
]

SEARCH_CORPUS = [
    {"title": "SQL Injection Prevention Guide", "type": "article", "relevance": 0.95},
    {"title": "XSS Attack Vectors 2026", "type": "whitepaper", "relevance": 0.91},
    {"title": "Network Intrusion Detection Best Practices", "type": "article", "relevance": 0.88},
    {"title": "OWASP Top 10 — Latest Edition", "type": "reference", "relevance": 0.97},
    {"title": "WAF Rule Tuning Handbook", "type": "guide", "relevance": 0.84},
    {"title": "Incident Response Playbook", "type": "playbook", "relevance": 0.90},
    {"title": "Container Security Hardening", "type": "guide", "relevance": 0.82},
    {"title": "API Security Testing Methodology", "type": "article", "relevance": 0.86},
]


# ---------------------------------------------------------------------------
# Helpers & Session Management
# ---------------------------------------------------------------------------
@dataclass
class SessionData:
    """Server-side session record for authentic application traffic."""

    session_id: str
    created_at: float
    last_activity: float
    client_ip: str
    user_agent: str
    metadata: dict[str, Any] = field(default_factory=dict)


class SessionStore:
    """Thread-safe server-side store for authentic application sessions.

    Guarantees that session IDs are cryptographically random, never
    accepted blindly from client input, and expire after inactivity or
    maximum lifetime.
    """

    def __init__(
        self,
        inactivity_timeout: float = SESSION_INACTIVITY_TIMEOUT,
        max_lifetime: float = SESSION_MAX_LIFETIME,
    ):
        self.inactivity_timeout = inactivity_timeout
        self.max_lifetime = max_lifetime
        self._sessions: dict[str, SessionData] = {}
        self._lock = threading.Lock()

    def create_session(self, client_ip: str = "", user_agent: str = "") -> str:
        """Generate a cryptographically secure random session ID and register it."""
        with self._lock:
            token = secrets.token_urlsafe(32)
            session_id = f"sess_{token}"
            now = time.time()
            self._sessions[session_id] = SessionData(
                session_id=session_id,
                created_at=now,
                last_activity=now,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            return session_id

    def validate_session(self, session_id: str | None) -> Optional[SessionData]:
        """Validate session ID against expiration and inactivity timeout."""
        if not session_id or not isinstance(session_id, str):
            return None
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            now = time.time()
            # Check maximum lifetime (24 hours)
            if (now - session.created_at) > self.max_lifetime:
                del self._sessions[session_id]
                return None
            # Check inactivity timeout (30 minutes)
            if (now - session.last_activity) > self.inactivity_timeout:
                del self._sessions[session_id]
                return None
            # Session is valid: update last activity
            session.last_activity = now
            return session

    def get_session(self, session_id: str) -> Optional[SessionData]:
        """Read-only session lookup without refreshing activity."""
        with self._lock:
            return self._sessions.get(session_id)

    def cleanup_expired(self) -> int:
        """Prune expired and timed-out sessions from the store."""
        with self._lock:
            now = time.time()
            expired_ids = [
                sid for sid, s in self._sessions.items()
                if (now - s.created_at) > self.max_lifetime
                or (now - s.last_activity) > self.inactivity_timeout
            ]
            for sid in expired_ids:
                del self._sessions[sid]
            return len(expired_ids)

    def reset(self) -> None:
        """Clear all active sessions (for test isolation)."""
        with self._lock:
            self._sessions.clear()

    def __len__(self) -> int:
        with self._lock:
            return len(self._sessions)


# Application session store instance
session_store = SessionStore()
app.state.session_store = session_store


def _inspect_body_in_memory(body_bytes: bytes, content_type: str) -> dict[str, int]:
    """Inspect up to 64KB of body bytes in memory for known attack indicators.

    Strictly sanitizes and ignores sensitive parameters (passwords, tokens).
    Never stores or returns raw body.
    """
    if not body_bytes:
        return {
            "has_sqli": 0,
            "has_xss": 0,
            "has_cmd": 0,
            "has_lfi": 0,
            "has_traversal": 0,
        }

    inspect_slice = body_bytes[:MAX_BODY_INSPECT_BYTES]
    ct_lower = content_type.lower() if content_type else ""

    try:
        raw_text = inspect_slice.decode("utf-8", errors="replace")
    except Exception:
        raw_text = ""

    if not raw_text:
        return {
            "has_sqli": 0,
            "has_xss": 0,
            "has_cmd": 0,
            "has_lfi": 0,
            "has_traversal": 0,
        }

    text_to_scan = ""
    if "application/json" in ct_lower:
        try:
            parsed = json.loads(raw_text)
            extracted: list[str] = []

            def _extract_safe(val: Any) -> None:
                if isinstance(val, dict):
                    for k, v in val.items():
                        if str(k).lower().strip() in SENSITIVE_PARAMS:
                            continue
                        extracted.append(str(k))
                        _extract_safe(v)
                elif isinstance(val, list):
                    for item in val:
                        _extract_safe(item)
                else:
                    extracted.append(str(val))

            _extract_safe(parsed)
            text_to_scan = " ".join(extracted)
        except Exception:
            text_to_scan = raw_text
    elif "application/x-www-form-urlencoded" in ct_lower:
        try:
            pairs = parse_qsl(raw_text, keep_blank_values=True)
            safe_pairs = [
                f"{k}={v}" for k, v in pairs
                if k.lower().strip() not in SENSITIVE_PARAMS
            ]
            text_to_scan = "&".join(safe_pairs)
        except Exception:
            text_to_scan = raw_text
    else:
        text_to_scan = raw_text

    decoded_text = unquote(text_to_scan)
    combined = f"{text_to_scan} {decoded_text}"

    return {
        "has_sqli": int(bool(RE_SQLI.search(combined))),
        "has_xss": int(bool(RE_XSS.search(combined))),
        "has_cmd": int(bool(RE_CMD_INJECTION.search(combined))),
        "has_lfi": int(bool(RE_LFI.search(combined))),
        "has_traversal": int(bool(RE_TRAVERSAL.search(combined))),
    }


def _redact_params(raw_query: str) -> dict[str, str]:
    """Parse query string, redacting values whose keys are sensitive."""
    if not raw_query:
        return {}
    pairs: dict[str, str] = {}
    for segment in raw_query.split("&"):
        if "=" not in segment:
            pairs[segment] = ""
            continue
        key, _, value = segment.partition("=")
        if key.lower().strip() in SENSITIVE_PARAMS:
            pairs[key] = "***REDACTED***"
        else:
            pairs[key] = value
    return pairs


def _write_log_entry(entry: dict[str, Any]) -> None:
    """Append a single JSON object as one line to the access log (thread-safe)."""
    line = json.dumps(entry, default=str) + "\n"
    with _log_lock:
        with open(LOG_FILE, "a", encoding="utf-8") as fh:
            fh.write(line)


# ---------------------------------------------------------------------------
# Middleware — automatic structured access logging & session management
# ---------------------------------------------------------------------------
@app.middleware("http")
async def access_log_middleware(request: Request, call_next) -> Response:
    """
    Records one structured JSON log entry per request.
    Enforces server-side session management and safe in-memory body inspection.
    """
    request_id = str(uuid.uuid4())
    start_time = time.monotonic()
    timestamp = datetime.now(timezone.utc).isoformat()

    # Capture request metadata (before calling the endpoint)
    method = request.method
    path = request.url.path
    raw_query = request.url.query or ""
    client_ip = request.client.host if request.client else "unknown"
    user_agent = request.headers.get("user-agent", "")

    # In-memory inspection of POST/PUT/PATCH bodies (up to 64KB)
    body_size_bytes = 0
    body_indicators = {
        "has_sqli": 0,
        "has_xss": 0,
        "has_cmd": 0,
        "has_lfi": 0,
        "has_traversal": 0,
    }
    if method in ("POST", "PUT", "PATCH"):
        try:
            body_bytes = await request.body()
            body_size_bytes = len(body_bytes)
            if body_bytes:
                content_type = request.headers.get("content-type", "")
                body_indicators = _inspect_body_in_memory(body_bytes, content_type)
        except Exception:
            pass

    # Server-side genuine session resolution
    cookie_session_id = request.cookies.get(SESSION_COOKIE_NAME)
    session_data = session_store.validate_session(cookie_session_id)
    if session_data is not None:
        session_id = session_data.session_id
        session_verified = True
    else:
        # Create fresh cryptographically secure session
        session_id = session_store.create_session(client_ip=client_ip, user_agent=user_agent)
        session_verified = True

    # Attach session to request state for downstream handlers if needed
    request.state.session_id = session_id
    request.state.session_verified = session_verified

    # Call the actual endpoint
    status_code = 500  # default if something explodes
    response_size: int | None = None
    error_detail: str | None = None
    try:
        response: Response = await call_next(request)
        status_code = response.status_code

        # Try to capture content-length if set
        cl = response.headers.get("content-length")
        if cl is not None:
            try:
                response_size = int(cl)
            except (ValueError, TypeError):
                pass
    except Exception as exc:
        error_detail = f"{type(exc).__name__}: {exc}"
        response = JSONResponse(
            status_code=500,
            content={"detail": "Internal server error"},
        )
        status_code = 500

    duration_ms = round((time.monotonic() - start_time) * 1000, 3)

    # Set HttpOnly, SameSite=lax session cookie on response
    is_https = (
        request.url.scheme == "https"
        or request.headers.get("x-forwarded-proto", "").lower() == "https"
    )
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_id,
        max_age=int(SESSION_MAX_LIFETIME),
        httponly=True,
        samesite="lax",
        secure=is_https,
        path="/",
    )

    # Build structured log entry
    log_entry: dict[str, Any] = {
        "timestamp": timestamp,
        "request_id": request_id,
        "session_id": session_id,
        "session_verified": session_verified,
        "method": method,
        "path": path,
        "query_params": _redact_params(raw_query),
        "status_code": status_code,
        "client_ip": client_ip,
        "user_agent": user_agent,
        "body_size_bytes": body_size_bytes,
        "body_indicators": body_indicators,
        "response_size_bytes": response_size,
        "duration_ms": duration_ms,
    }
    if error_detail:
        log_entry["error"] = error_detail

    _write_log_entry(log_entry)

    return response


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@app.get("/", response_class=HTMLResponse)
async def homepage(request: Request):
    """Render the traffic simulator dashboard."""
    return templates.TemplateResponse(request, "index.html")


@app.get("/health")
async def health_check():
    """Simple liveness probe."""
    log_exists = LOG_FILE.exists()
    log_size = LOG_FILE.stat().st_size if log_exists else 0
    line_count = 0
    if log_exists and log_size > 0:
        with open(LOG_FILE, "r", encoding="utf-8") as fh:
            line_count = sum(1 for _ in fh)
    return {
        "status": "healthy",
        "service": "SENTINEL AI Traffic Simulator",
        "version": "1.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "log_file": str(LOG_FILE),
        "log_entries": line_count,
        "log_size_bytes": log_size,
    }


@app.get("/products")
async def list_products(
    category: str | None = Query(default=None, description="Filter by product category"),
    in_stock: bool | None = Query(default=None, description="Filter by stock availability"),
):
    """Return sample product catalog, optionally filtered."""
    results = PRODUCTS
    if category:
        results = [p for p in results if p["category"].lower() == category.lower()]
    if in_stock is not None:
        results = [p for p in results if p["in_stock"] == in_stock]
    return {
        "products": results,
        "total": len(results),
        "filters_applied": {
            "category": category,
            "in_stock": in_stock,
        },
    }


@app.get("/search")
async def search(
    q: str = Query(default="", description="Search query"),
    limit: int = Query(default=5, ge=1, le=50, description="Max results"),
):
    """Simulate keyword search across a knowledge base."""
    if not q.strip():
        return {"query": q, "results": [], "total": 0, "message": "Empty query"}

    query_lower = q.strip().lower()
    matches = [
        item for item in SEARCH_CORPUS
        if query_lower in item["title"].lower()
    ]
    # If no exact match, return items sorted by relevance as "suggestions"
    if not matches:
        matches = sorted(SEARCH_CORPUS, key=lambda x: x["relevance"], reverse=True)

    return {
        "query": q,
        "results": matches[:limit],
        "total": len(matches[:limit]),
    }


@app.post("/login")
async def login(
    username: str = Form(default=""),
    password: str = Form(default=""),
):
    """
    Simulate a login endpoint.  NEVER stores or logs credentials.
    Always returns a fixed response for simulation purposes.
    The authentic session ID is strictly conveyed via HttpOnly cookie.
    """
    # Intentionally do NOT log or use the actual password value
    if not username:
        return JSONResponse(
            status_code=400,
            content={"detail": "Username is required", "authenticated": False},
        )
    # Simulated auth (always succeeds for non-empty usernames)
    return {
        "authenticated": True,
        "username": username,
        "message": "Simulated login — no real authentication performed",
    }


@app.post("/api/data")
async def receive_data(request: Request):
    """Accept arbitrary JSON data and echo it back with metadata."""
    try:
        body = await request.json()
    except Exception:
        return JSONResponse(
            status_code=400,
            content={"detail": "Invalid JSON body"},
        )
    return {
        "received": True,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "payload_keys": list(body.keys()) if isinstance(body, dict) else None,
        "payload_type": type(body).__name__,
        "echo": body,
    }


# ---------------------------------------------------------------------------
# Additional endpoints for richer traffic variety
# ---------------------------------------------------------------------------

@app.get("/api/status/{service_name}")
async def service_status(service_name: str):
    """Check the status of a named sub-service."""
    known = {"detector", "aggregator", "dashboard", "database", "cache"}
    if service_name.lower() in known:
        return {"service": service_name, "status": "operational", "uptime_hours": 142.5}
    return JSONResponse(
        status_code=404,
        content={"detail": f"Unknown service: {service_name}"},
    )


@app.get("/api/metrics")
async def metrics():
    """Return simulated system metrics."""
    return {
        "cpu_percent": 23.4,
        "memory_used_mb": 512,
        "memory_total_mb": 8192,
        "active_connections": 17,
        "requests_per_second": 48.2,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Entry point (for `python app.py`)
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "app:app",
        host="127.0.0.1",
        port=8001,
        reload=True,
    )
