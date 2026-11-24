"""
SENTINEL AI — Stateful Traffic Feature Parser (Stage 2B)

Transforms raw, structured HTTP access-log records from the traffic simulator
into validated, schema-compliant feature dictionaries for the SENTINEL AI
detection pipeline.

Key Design Principles:
1. Reproduces exact SOC-MLD and CSIC feature definitions from the existing models.
2. Extracts 11 payload attack signatures from method, path, query params, and User-Agent.
3. Maintains in-memory sliding windows (1s, 10s, 60s) for the 10 time-window features.
4. Distinguishes client-IP behavioral tracking from verified application session tracking.
   (client_ip is NOT claimed to be a genuine session identifier).
5. Only generates genuine session and sequence history when a verified session_id is provided.
6. Explicitly marks unavailable detectors (Autoencoder, Network, or uninstrumented Session/Sequence).
7. Never fabricates missing feature values or substitutes zero for unmeasured signals.
"""

from __future__ import annotations

import math
import re
import threading
from collections import deque
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from urllib.parse import unquote, parse_qsl, urlsplit

# ---------------------------------------------------------------------------
# Detector Feature Schemas (mirrors src/detection/ modules)
# ---------------------------------------------------------------------------
PAYLOAD_FEATURE_NAMES: List[str] = [
    "f_has_sqli",
    "f_has_xss",
    "f_has_lfi",
    "f_has_cmd",
    "f_has_ssrf",
    "f_has_traversal",
    "f_is_scanner_ua",
    "f_query_len",
    "f_path_depth",
    "f_has_encoded",
    "f_has_sql_comment",
]

TIME_FEATURE_NAMES: List[str] = [
    "f_req_count_1s",
    "f_req_rate_1s",
    "f_req_count_10s",
    "f_req_rate_10s",
    "f_req_count_60s",
    "f_req_rate_60s",
    "f_error_ratio_10s",
    "f_unique_paths_10s",
    "f_404_count_10s",
    "f_404_count_60s",
]

SESSION_FEATURE_NAMES: List[str] = [
    "f_session_req_count",
    "f_session_duration",
    "f_session_unique_paths",
    "f_session_error_count",
    "f_session_req_rate",
]

# Combined feature schemas
HTTP_FEATURE_NAMES: List[str] = PAYLOAD_FEATURE_NAMES + TIME_FEATURE_NAMES + SESSION_FEATURE_NAMES  # 26 features
SESSION_DETECTOR_FEATURES: List[str] = TIME_FEATURE_NAMES + SESSION_FEATURE_NAMES                   # 15 features
SEQUENCE_FEATURE_NAMES: List[str] = list(PAYLOAD_FEATURE_NAMES)                                    # 11 features

AUTOENCODER_FEATURE_NAMES: List[str] = [
    "method_code",
    "path_length",
    "path_depth",
    "query_length",
    "query_param_count",
    "body_size",
    "payload_entropy",
    "special_char_ratio",
    "has_cookie",
    "content_length_header",
    "traversal_flag",
    "sql_marker_flag",
]

MAX_SEQUENCE_HISTORY_LENGTH = 99
REDACTION_PLACEHOLDER = "***REDACTED***"

# ---------------------------------------------------------------------------
# Compiled Attack Pattern Signatures
# ---------------------------------------------------------------------------
# SQL Injection Patterns
RE_SQLI = re.compile(
    r"("
    r"(\b(select|union(\s+all)?|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|alter\s+table)\b)|"
    r"('|\")?\s*\bor\b\s*('|\")?(\d+|true)('|\")?\s*=\s*('|\")?(\d+|true)('|\")?|"
    r"('|\")\s*\bor\s+''='|"
    r"\bexec(\s+|\()|\bexecute(\s+|\()|"
    r"\bwaitfor\s+delay\b|\bsleep\s*\(\s*\d+\s*\)|\bbenchmark\s*\("
    r")",
    re.IGNORECASE,
)

# SQL Comments
RE_SQL_COMMENT = re.compile(r"(--|/\*|\*/|#)", re.IGNORECASE)

# Cross-Site Scripting (XSS) Patterns
RE_XSS = re.compile(
    r"("
    r"<\s*script\b[^>]*>|<\s*/\s*script\s*>|"
    r"\bjavascript\s*:|\bvbscript\s*:|"
    r"\bon(load|error|click|mouseover|mouseenter|focus|blur|submit|keydown|keyup)\s*=|"
    r"<\s*img\b[^>]*\bonerror\s*=|"
    r"<\s*svg\b[^>]*\bonload\s*=|"
    r"<\s*iframe\b|"
    r"\balert\s*\(|\bprompt\s*\(|\bconfirm\s*\(|"
    r"document\s*\.\s*(cookie|location|domain)"
    r")",
    re.IGNORECASE,
)

# Local File Inclusion (LFI) Patterns
RE_LFI = re.compile(
    r"("
    r"/etc/(passwd|shadow|group|hosts|issue|motd)|"
    r"/proc/(self|version|cpuinfo|cmdline)|"
    r"(win|boot)\.ini|system32|"
    r"\b(file|php|data|zip|glob|expect)://"
    r")",
    re.IGNORECASE,
)

# Path Traversal Patterns
RE_TRAVERSAL = re.compile(
    r"(\.\./|\.\.\\|\.\.%2f|\.\.%5c|%2e%2e|%252e%252e)",
    re.IGNORECASE,
)

# Command Injection Patterns
RE_CMD_INJECTION = re.compile(
    r"("
    r"(;|\||&&|`|\$\()\s*(cat|ls|id|whoami|sh|bash|curl|wget|nc|uname|pwd)\b|"
    r"\b(cat|type)\s+(/etc/|c:\\)|"
    r"/bin/(sh|bash|zsh)"
    r")",
    re.IGNORECASE,
)

# Server-Side Request Forgery (SSRF) Patterns
RE_SSRF = re.compile(
    r"("
    r"169\.254\.169\.254|"
    r"metadata\.google\.internal|"
    r"https?://(localhost|127\.0\.0\.1|0\.0\.0\.0)|"
    r"https?://(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3})|"
    r"\b(gopher|dict|ldap)://"
    r")",
    re.IGNORECASE,
)

# URL-Encoding Pattern (% followed by 2 hex digits)
RE_ENCODED = re.compile(r"%[0-9a-fA-F]{2}")

# Scanner & Automated Tool User-Agent Signatures
RE_SCANNER_UA = re.compile(
    r"("
    r"sqlmap|nikto|nmap|masscan|wpscan|gobuster|dirbuster|ffuf|"
    r"nuclei|acunetix|nessus|metasploit|burp(suite)?|hydra|zaproxy|"
    r"arachni|openvas|havij|netsparker|qualys|w3af"
    r")",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Output Data Structures
# ---------------------------------------------------------------------------
@dataclass
class ParsedTrafficRecord:
    """Standardized parsed traffic event containing all extracted features,

    behavioral metrics, verified session features, and detector availability.
    """

    timestamp: float
    raw_timestamp: str
    request_id: str
    client_ip: str
    method: str
    path: str
    status_code: int
    user_agent: str
    response_size_bytes: Optional[int]
    duration_ms: float

    # Extracted feature sets
    payload_features: Dict[str, Union[int, float]]
    time_window_features: Dict[str, float]

    # Explicitly distinguish approximate IP tracking from verified sessions
    client_ip_metrics: Dict[str, Any]
    session_features: Optional[Dict[str, float]]
    sequence_history: Optional[List[Dict[str, Any]]]

    # Complete event payload for backend POST /evaluate (if eligible)
    event_features: Dict[str, Any]

    # Availability & diagnostic reporting
    detector_availability: Dict[str, bool]
    unavailable_reasons: Dict[str, str]

    # Validation status
    is_valid: bool = True
    validation_errors: List[str] = field(default_factory=list)
    body_size_bytes: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert parsed record to a clean JSON-serializable dictionary."""
        return asdict(self)


# ---------------------------------------------------------------------------
# Helper Extraction & Sanitization Functions
# ---------------------------------------------------------------------------
def _parse_timestamp(raw: Any) -> float:
    """Parse raw timestamp into a float UTC epoch timestamp in seconds.

    Supports ISO-8601 strings and numeric seconds.
    Rejects malformed, NaN, or non-finite timestamps.
    """
    if raw is None:
        raise ValueError("Timestamp cannot be None")

    if isinstance(raw, (int, float)):
        ts = float(raw)
        if not math.isfinite(ts):
            raise ValueError(f"Non-finite numeric timestamp: {raw}")
        return ts

    if isinstance(raw, str):
        cleaned = raw.strip()
        if not cleaned:
            raise ValueError("Timestamp string cannot be empty")

        # ISO format: normalize Z to +00:00
        if cleaned.endswith("Z") or cleaned.endswith("z"):
            cleaned = cleaned[:-1] + "+00:00"

        try:
            dt = datetime.fromisoformat(cleaned)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.timestamp()
        except ValueError:
            # Try float conversion as fallback
            try:
                ts = float(cleaned)
                if not math.isfinite(ts):
                    raise ValueError(f"Non-finite timestamp value: {raw}")
                return ts
            except ValueError as exc:
                raise ValueError(f"Invalid timestamp format: {raw}") from exc

    raise TypeError(f"Unsupported timestamp type: {type(raw)}")


def _extract_query_text(query_params: Any, raw_query: Optional[str] = None) -> Tuple[str, str]:
    """Reconstruct query text while carefully excluding sensitive redactions.

    Returns (clean_raw_query, clean_decoded_query).
    Redaction placeholders (e.g. '***REDACTED***') are stripped to prevent
    them from being falsely counted as query length or attack patterns.
    """
    if raw_query:
        # If raw query string was provided, strip redactions
        clean_raw = raw_query.replace(REDACTION_PLACEHOLDER, "")
        clean_decoded = unquote(clean_raw)
        return clean_raw, clean_decoded

    if isinstance(query_params, dict):
        parts = []
        for k, v in query_params.items():
            str_k = str(k).strip()
            str_v = str(v).strip()
            # If value was redacted, omit the placeholder text
            if str_v == REDACTION_PLACEHOLDER or str_v == "***":
                parts.append(str_k)
            else:
                parts.append(f"{str_k}={str_v}")
        clean_raw = "&".join(parts)
        clean_decoded = unquote(clean_raw)
        return clean_raw, clean_decoded

    if isinstance(query_params, str):
        clean_raw = query_params.replace(REDACTION_PLACEHOLDER, "")
        clean_decoded = unquote(clean_raw)
        return clean_raw, clean_decoded

    return "", ""


def extract_payload_features(
    method: str,
    path: str,
    query_params: Any,
    user_agent: str,
    raw_query: Optional[str] = None,
    body_indicators: Optional[Dict[str, int]] = None,
) -> Dict[str, Union[int, float]]:
    """Extract the 11 SOC-MLD payload attack features from request metadata.

    Features:
    1. f_has_sqli
    2. f_has_xss
    3. f_has_lfi
    4. f_has_cmd
    5. f_has_ssrf
    6. f_has_traversal
    7. f_is_scanner_ua
    8. f_query_len
    9. f_path_depth
    10. f_has_encoded
    11. f_has_sql_comment
    """
    clean_raw_query, clean_decoded_query = _extract_query_text(query_params, raw_query)
    decoded_path = unquote(path or "/")

    # Text corpus for attack pattern scanning (path + query string)
    target_corpus = f"{decoded_path}?{clean_decoded_query}" if clean_decoded_query else decoded_path
    raw_corpus = f"{path}?{clean_raw_query}" if clean_raw_query else path

    # 1. SQL Injection
    has_sqli = int(bool(RE_SQLI.search(target_corpus)))

    # 2. XSS
    has_xss = int(bool(RE_XSS.search(target_corpus)))

    # 3. LFI
    has_lfi = int(bool(RE_LFI.search(target_corpus)))

    # 4. Command Injection
    has_cmd = int(bool(RE_CMD_INJECTION.search(target_corpus)))

    # 5. SSRF
    has_ssrf = int(bool(RE_SSRF.search(target_corpus)))

    # 6. Path Traversal
    has_traversal = int(bool(RE_TRAVERSAL.search(target_corpus) or RE_TRAVERSAL.search(raw_corpus)))

    # Integrate safe in-memory body indicators (from POST body inspection)
    if body_indicators and isinstance(body_indicators, dict):
        if body_indicators.get("has_sqli"):
            has_sqli = 1
        if body_indicators.get("has_xss"):
            has_xss = 1
        if body_indicators.get("has_lfi"):
            has_lfi = 1
        if body_indicators.get("has_cmd"):
            has_cmd = 1
        if body_indicators.get("has_traversal"):
            has_traversal = 1

    # 7. Scanner User-Agent
    has_scanner_ua = int(bool(RE_SCANNER_UA.search(user_agent or "")))

    # 8. Query Length (characters in non-redacted query)
    query_len = len(clean_raw_query)

    # 9. Path Depth (count of path segments, minimum 1)
    segments = [s for s in path.split("/") if s]
    path_depth = max(1, len(segments))

    # 10. URL Encoding presence
    has_encoded = int(bool(RE_ENCODED.search(raw_corpus)))

    # 11. SQL Comments
    has_sql_comment = int(bool(RE_SQL_COMMENT.search(target_corpus)))

    return {
        "f_has_sqli": has_sqli,
        "f_has_xss": has_xss,
        "f_has_lfi": has_lfi,
        "f_has_cmd": has_cmd,
        "f_has_ssrf": has_ssrf,
        "f_has_traversal": has_traversal,
        "f_is_scanner_ua": has_scanner_ua,
        "f_query_len": query_len,
        "f_path_depth": path_depth,
        "f_has_encoded": has_encoded,
        "f_has_sql_comment": has_sql_comment,
    }


# ---------------------------------------------------------------------------
# Stateful Time-Window Tracker (1s, 10s, 60s)
# ---------------------------------------------------------------------------
class TimeWindowTracker:
    """Tracks sliding time-windows (1s, 10s, 60s) for request rates, error ratios,

    unique paths, and 404 counts using event timestamps as the clock.
    """

    def __init__(self, max_retention_seconds: float = 60.0):
        self.max_retention = max_retention_seconds
        # Deque of tuples: (timestamp: float, path: str, status_code: int)
        self._history: deque[Tuple[float, str, int]] = deque()
        self._lock = threading.Lock()
        self._last_timestamp: float = -1.0

    def record_and_evaluate(
        self,
        timestamp: float,
        path: str,
        status_code: int,
    ) -> Dict[str, float]:
        """Record an incoming event and return exact 10 time-window metrics."""
        with self._lock:
            # Handle out-of-order timestamps
            if self._last_timestamp > 0 and timestamp < self._last_timestamp:
                # Insert in sorted order if out-of-order within the retention window
                inserted = False
                for idx in range(len(self._history) - 1, -1, -1):
                    if self._history[idx][0] <= timestamp:
                        self._history.insert(idx + 1, (timestamp, path, status_code))
                        inserted = True
                        break
                if not inserted:
                    self._history.appendleft((timestamp, path, status_code))
            else:
                self._history.append((timestamp, path, status_code))
                self._last_timestamp = timestamp

            # Evict events older than t - 60s
            cutoff_60s = timestamp - 60.0
            while self._history and self._history[0][0] < cutoff_60s:
                self._history.popleft()

            # Windows relative to current event timestamp
            cutoff_1s = timestamp - 1.0
            cutoff_10s = timestamp - 10.0

            # Count metrics
            count_1s = 0
            count_10s = 0
            count_60s = 0

            errors_10s = 0
            paths_10s: Set[str] = set()
            count_404_10s = 0
            count_404_60s = 0

            for t, p, s in self._history:
                # 60s window (all surviving elements in history are within 60s)
                count_60s += 1
                if s == 404:
                    count_404_60s += 1

                # 10s window
                if t >= cutoff_10s:
                    count_10s += 1
                    paths_10s.add(p)
                    if s >= 400:
                        errors_10s += 1
                    if s == 404:
                        count_404_10s += 1

                # 1s window
                if t >= cutoff_1s:
                    count_1s += 1

            # Compute rates (requests / window_length)
            rate_1s = round(float(count_1s) / 1.0, 4)
            rate_10s = round(float(count_10s) / 10.0, 4)
            rate_60s = round(float(count_60s) / 60.0, 4)

            error_ratio_10s = round(float(errors_10s) / float(count_10s), 4) if count_10s > 0 else 0.0
            unique_paths_10s = len(paths_10s)

            return {
                "f_req_count_1s": count_1s,
                "f_req_rate_1s": rate_1s,
                "f_req_count_10s": count_10s,
                "f_req_rate_10s": rate_10s,
                "f_req_count_60s": count_60s,
                "f_req_rate_60s": rate_60s,
                "f_error_ratio_10s": error_ratio_10s,
                "f_unique_paths_10s": unique_paths_10s,
                "f_404_count_10s": count_404_10s,
                "f_404_count_60s": count_404_60s,
            }

    def reset(self):
        """Clear all time window history."""
        with self._lock:
            self._history.clear()
            self._last_timestamp = -1.0


# ---------------------------------------------------------------------------
# Client-IP Activity Tracker (Approximate Behavioral Metrics Only)
# ---------------------------------------------------------------------------
class ClientIPTracker:
    """Maintains behavioral metrics grouped by client_ip.

    NOTE: client_ip is NOT an application session ID (NAT, proxies, shared IPs).
    These metrics are approximate and strictly kept distinct from true session features.
    """

    def __init__(self, session_timeout_seconds: float = 1800.0):
        self.session_timeout = session_timeout_seconds
        self._ip_states: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def record_and_evaluate(
        self,
        client_ip: str,
        timestamp: float,
        path: str,
        status_code: int,
    ) -> Dict[str, Any]:
        """Update and return approximate behavioral metrics for this client IP."""
        with self._lock:
            state = self._ip_states.get(client_ip)

            # Check if this IP is new or exceeded inactivity timeout
            if state is None or (timestamp - state["last_seen"]) > self.session_timeout:
                state = {
                    "client_ip": client_ip,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "req_count": 0,
                    "paths": set(),
                    "error_count": 0,
                }
                self._ip_states[client_ip] = state

            state["req_count"] += 1
            state["last_seen"] = timestamp
            state["paths"].add(path)
            if status_code >= 400:
                state["error_count"] += 1

            duration = max(0.0, timestamp - state["first_seen"])
            duration_secs = round(duration, 3)
            req_rate = round(float(state["req_count"]) / max(1.0, duration), 4)

            return {
                "client_ip": client_ip,
                "client_ip_req_count": state["req_count"],
                "client_ip_duration": duration_secs,
                "client_ip_unique_paths": len(state["paths"]),
                "client_ip_error_count": state["error_count"],
                "client_ip_req_rate": req_rate,
                "is_genuine_session": False,
                "note": "Approximate behavioral tracking; client_ip is not a verified session ID",
            }

    def reset(self):
        """Clear all client IP tracking history."""
        with self._lock:
            self._ip_states.clear()


# ---------------------------------------------------------------------------
# Verified Application Session Tracker (Genuine Session Features Only)
# ---------------------------------------------------------------------------
class VerifiedSessionTracker:
    """Tracks genuine application session features when an authentic session_id

    is provided through application instrumentation.
    Never activated for unverified client IPs.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def record_and_evaluate(
        self,
        session_id: str,
        timestamp: float,
        path: str,
        status_code: int,
        payload_features: Dict[str, Any],
    ) -> Tuple[Dict[str, float], List[Dict[str, Any]]]:
        """Update and return exact 5 session features + chronological sequence history."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                session = {
                    "session_id": session_id,
                    "first_seen": timestamp,
                    "last_seen": timestamp,
                    "req_count": 0,
                    "paths": set(),
                    "error_count": 0,
                    "history": [],
                }
                self._sessions[session_id] = session

            session["req_count"] += 1
            session["last_seen"] = timestamp
            session["paths"].add(path)
            if status_code >= 400:
                session["error_count"] += 1

            duration = max(0.0, timestamp - session["first_seen"])
            duration_secs = round(duration, 3)
            req_rate = round(float(session["req_count"]) / max(1.0, duration), 4)

            session_features = {
                "f_session_req_count": session["req_count"],
                "f_session_duration": duration_secs,
                "f_session_unique_paths": len(session["paths"]),
                "f_session_error_count": session["error_count"],
                "f_session_req_rate": req_rate,
            }

            # Append to chronological sequence history
            history_step = {
                "timestamp": timestamp,
                "session_id": session_id,
                **payload_features,
            }
            session["history"].append(history_step)

            # Cap sequence length to model limit
            if len(session["history"]) > MAX_SEQUENCE_HISTORY_LENGTH:
                session["history"] = session["history"][-MAX_SEQUENCE_HISTORY_LENGTH:]

            return session_features, list(session["history"])

    def reset(self):
        """Clear all verified session states."""
        with self._lock:
            self._sessions.clear()


# ---------------------------------------------------------------------------
# Main Stateful Traffic Feature Parser
# ---------------------------------------------------------------------------
class TrafficFeatureParser:
    """Stateful parser transforming simulator access-log records into verified

    features for SENTINEL AI multi-domain detectors.
    """

    def __init__(self):
        self.time_tracker = TimeWindowTracker()
        self.ip_tracker = ClientIPTracker()
        self.session_tracker = VerifiedSessionTracker()

    def reset(self):
        """Reset all in-memory trackers."""
        self.time_tracker.reset()
        self.ip_tracker.reset()
        self.session_tracker.reset()

    def parse_log_entry(self, record: Dict[str, Any]) -> ParsedTrafficRecord:
        """Parse a single structured access-log entry into a ParsedTrafficRecord."""
        errors: List[str] = []

        if not isinstance(record, dict):
            return self._create_invalid_record(
                record, ["Log entry must be a dictionary"]
            )

        # 1. Validate required fields
        required_fields = ["timestamp", "method", "path", "status_code", "client_ip"]
        missing = [f for f in required_fields if f not in record]
        if missing:
            errors.append(f"Missing required log fields: {missing}")

        # 2. Parse & validate timestamp
        raw_ts = record.get("timestamp")
        ts = 0.0
        try:
            ts = _parse_timestamp(raw_ts)
        except Exception as exc:
            errors.append(f"Invalid timestamp: {exc}")

        # 3. Validate types
        method = str(record.get("method", "GET")).upper().strip()
        path = str(record.get("path", "/")).strip()
        client_ip = str(record.get("client_ip", "unknown")).strip()
        user_agent = str(record.get("user_agent", "")).strip()

        try:
            status_code = int(record.get("status_code", 200))
            if not (100 <= status_code <= 599):
                errors.append(f"Invalid status_code range: {status_code}")
        except (ValueError, TypeError):
            status_code = 500
            errors.append("status_code must be an integer")

        query_params = record.get("query_params", {})
        raw_query = record.get("raw_query")  # optional if simulator provides it

        # Response size & duration
        resp_size = record.get("response_size_bytes")
        if resp_size is not None:
            try:
                resp_size = int(resp_size)
            except (ValueError, TypeError):
                resp_size = None

        duration_ms = 0.0
        raw_dur = record.get("duration_ms")
        if raw_dur is not None:
            try:
                duration_ms = float(raw_dur)
                if not math.isfinite(duration_ms):
                    duration_ms = 0.0
            except (ValueError, TypeError):
                duration_ms = 0.0

        req_id = str(record.get("request_id") or f"sim-{int(ts * 1000)}")

        # Check for verified application session ID (optional instrumentation)
        raw_session_id = record.get("session_id")
        session_verified_flag = record.get("session_verified", True)
        has_verified_session = bool(
            raw_session_id
            and isinstance(raw_session_id, str)
            and raw_session_id.strip()
            and session_verified_flag is True
        )
        verified_session_id = raw_session_id.strip() if has_verified_session else None

        # Check for safe body indicators and size from access log
        body_indicators = record.get("body_indicators")
        body_size_bytes = record.get("body_size_bytes")
        if body_size_bytes is not None:
            try:
                body_size_bytes = int(body_size_bytes)
            except (ValueError, TypeError):
                body_size_bytes = None

        if errors:
            return self._create_invalid_record(record, errors)

        # 4. Extract Payload Features (11 features)
        payload_features = extract_payload_features(
            method=method,
            path=path,
            query_params=query_params,
            user_agent=user_agent,
            raw_query=raw_query,
            body_indicators=body_indicators,
        )

        # 5. Extract Time-Window Features (10 features)
        time_features = self.time_tracker.record_and_evaluate(
            timestamp=ts,
            path=path,
            status_code=status_code,
        )

        # 6. Extract Client-IP Behavioral Tracking (Approximate)
        client_ip_metrics = self.ip_tracker.record_and_evaluate(
            client_ip=client_ip,
            timestamp=ts,
            path=path,
            status_code=status_code,
        )

        # 7. Extract Verified Session Features & Sequence History (if session_id present)
        session_features: Optional[Dict[str, float]] = None
        sequence_history: Optional[List[Dict[str, Any]]] = None

        if has_verified_session:
            session_features, sequence_history = self.session_tracker.record_and_evaluate(
                session_id=str(verified_session_id).strip(),
                timestamp=ts,
                path=path,
                status_code=status_code,
                payload_features=payload_features,
            )

        # 8. Determine Detector Availability & Diagnostic Reasons
        detector_availability: Dict[str, bool] = {
            "http": False,
            "session": False,
            "sequence": False,
            "network": False,
            "autoencoder": False,
        }
        unavailable_reasons: Dict[str, str] = {}

        # Network: Always UNAVAILABLE for HTTP access logs
        detector_availability["network"] = False
        unavailable_reasons["network"] = (
            "Access logs do not contain transport-layer flow telemetry, TCP packet flags (SYN/FIN/RST), "
            "or Suricata IDS signatures required by Network Random Forest."
        )

        # Autoencoder: UNAVAILABLE unless full 12 CSIC features (body & headers) are provided
        detector_availability["autoencoder"] = False
        unavailable_reasons["autoencoder"] = (
            "Autoencoder requires 12 CSIC features including request body and HTTP headers (Cookie, Content-Length); "
            "access logs record response size and URL path/query only."
        )

        # Session & Sequence Detectors:
        if has_verified_session and session_features is not None:
            detector_availability["session"] = True
            detector_availability["sequence"] = bool(sequence_history and len(sequence_history) >= 1)
            # HTTP Random Forest requires all 26 features (11 payload + 10 time + 5 session)
            detector_availability["http"] = True
        else:
            detector_availability["session"] = False
            unavailable_reasons["session"] = (
                "Session Random Forest requires verified session features; access log contains client_ip only "
                "or session is unverified."
            )
            detector_availability["sequence"] = False
            unavailable_reasons["sequence"] = (
                "Sequence LSTM requires genuine chronological session history; client_ip is not a genuine "
                "session identifier and unverified session cannot be substituted."
            )
            detector_availability["http"] = False
            unavailable_reasons["http"] = (
                "HTTP Random Forest requires all 26 features including 5 session features; genuine verified session ID "
                "not present in access log."
            )

        # 9. Build Event Features Dictionary
        # Assemble available features into a single dictionary
        event_features: Dict[str, Any] = {
            "source": "nginx",
            "request_id": req_id,
            "client_ip": client_ip,
            "method": method,
            "path": path,
            "status_code": status_code,
            **payload_features,
            **time_features,
        }
        if session_features:
            event_features.update(session_features)
        if has_verified_session:
            event_features["session_id"] = verified_session_id

        return ParsedTrafficRecord(
            timestamp=ts,
            raw_timestamp=str(raw_ts),
            request_id=req_id,
            client_ip=client_ip,
            method=method,
            path=path,
            status_code=status_code,
            user_agent=user_agent,
            response_size_bytes=resp_size,
            duration_ms=duration_ms,
            payload_features=payload_features,
            time_window_features=time_features,
            client_ip_metrics=client_ip_metrics,
            session_features=session_features,
            sequence_history=sequence_history,
            event_features=event_features,
            detector_availability=detector_availability,
            unavailable_reasons=unavailable_reasons,
            is_valid=True,
            validation_errors=[],
            body_size_bytes=body_size_bytes,
        )

    def _create_invalid_record(
        self, record: Any, errors: List[str]
    ) -> ParsedTrafficRecord:
        """Create a placeholder ParsedTrafficRecord representing a rejected/invalid log entry."""
        return ParsedTrafficRecord(
            timestamp=0.0,
            raw_timestamp=str(record.get("timestamp") if isinstance(record, dict) else ""),
            request_id="invalid",
            client_ip=str(record.get("client_ip", "") if isinstance(record, dict) else ""),
            method="",
            path="",
            status_code=0,
            user_agent="",
            response_size_bytes=None,
            duration_ms=0.0,
            payload_features={},
            time_window_features={},
            client_ip_metrics={},
            session_features=None,
            sequence_history=None,
            event_features={},
            detector_availability={
                "http": False,
                "session": False,
                "sequence": False,
                "network": False,
                "autoencoder": False,
            },
            unavailable_reasons={"all": "Log record validation failed: " + "; ".join(errors)},
            is_valid=False,
            validation_errors=errors,
        )
