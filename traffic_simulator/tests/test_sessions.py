"""
SENTINEL AI — Stage 2C Genuine Session Instrumentation Tests

Verifies:
1. New visitor receives server-generated sentinel_session cookie (HttpOnly, SameSite=lax).
2. Subsequent requests retain the same session ID.
3. Different visitors receive distinct session IDs.
4. Client-supplied forged session IDs are rejected and replaced.
5. Session expiration (max lifetime 24h).
6. Session inactivity timeout (30 min).
7. Multiple clients sharing an IP receive distinct sessions.
8. Correct session feature calculation (f_session_req_count, f_session_duration, etc.).
9. Correct chronological sequence history for Sequence LSTM (capped at 99 steps).
10. Session IDs are not exposed in frontend responses (HTML or JSON bodies, e.g. /login).
11. Passwords and secrets are never stored in access logs.
12. In-memory POST body attack detection (SQLi, XSS, etc.) triggers indicators without raw body logging.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Ensure KERAS_HOME and MPLCONFIGDIR point to writable sandbox locations
os.environ.setdefault("KERAS_HOME", "/tmp")
os.environ.setdefault("MPLCONFIGDIR", "/tmp")

from traffic_simulator.app import (
    app,
    session_store,
    SessionStore,
    SESSION_COOKIE_NAME,
    SESSION_INACTIVITY_TIMEOUT,
    SESSION_MAX_LIFETIME,
)
from traffic_simulator.parser import (
    TrafficFeatureParser,
    PAYLOAD_FEATURE_NAMES,
    MAX_SEQUENCE_HISTORY_LENGTH,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture
def temp_log(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Isolate access.log to a temporary directory for test cleanliness."""
    log_file = tmp_path / "access.log"
    monkeypatch.setattr("traffic_simulator.app.LOG_FILE", log_file)
    session_store.reset()
    yield log_file
    session_store.reset()


@pytest.fixture
def client(temp_log: Path) -> TestClient:
    """TestClient configured with isolated log file and clean session store."""
    return TestClient(app)


@pytest.fixture
def parser() -> TrafficFeatureParser:
    """Fresh TrafficFeatureParser instance with reset in-memory state."""
    p = TrafficFeatureParser()
    p.reset()
    return p


def _read_log_entries(log_file: Path) -> List[Dict[str, Any]]:
    """Read all JSON lines from the access log."""
    if not log_file.exists():
        return []
    entries = []
    with open(log_file, "r", encoding="utf-8") as f:
        for line in f:
            line_str = line.strip()
            if line_str:
                entries.append(json.loads(line_str))
    return entries


# ---------------------------------------------------------------------------
# Test 1: New visitor receives server-generated sentinel_session cookie
# ---------------------------------------------------------------------------
def test_1_new_visitor_receives_server_generated_cookie(client: TestClient):
    response = client.get("/health")
    assert response.status_code == 200

    # Cookie jar should have sentinel_session
    cookie_val = response.cookies.get(SESSION_COOKIE_NAME)
    assert cookie_val is not None
    assert cookie_val.startswith("sess_")
    assert len(cookie_val) > 20

    # Verify Set-Cookie header flags
    set_cookie_headers = response.headers.get_list("set-cookie")
    assert len(set_cookie_headers) > 0
    sc = set_cookie_headers[0]
    assert "HttpOnly" in sc
    assert "SameSite=lax" in sc
    assert "Path=/" in sc

    # Verify session is registered in server-side session store
    session_data = session_store.get_session(cookie_val)
    assert session_data is not None
    assert session_data.session_id == cookie_val


# ---------------------------------------------------------------------------
# Test 2: Subsequent requests retain the same session ID
# ---------------------------------------------------------------------------
def test_2_subsequent_requests_retain_same_session(client: TestClient, temp_log: Path):
    # First request
    res1 = client.get("/products")
    assert res1.status_code == 200
    sid1 = res1.cookies.get(SESSION_COOKIE_NAME)
    assert sid1 is not None

    # Second request (TestClient automatically sends back received cookies)
    res2 = client.get("/search?q=firewall")
    assert res2.status_code == 200
    sid2 = res2.cookies.get(SESSION_COOKIE_NAME)

    assert sid1 == sid2

    # Check access log entries
    entries = _read_log_entries(temp_log)
    assert len(entries) >= 2
    assert entries[0]["session_id"] == sid1
    assert entries[0]["session_verified"] is True
    assert entries[1]["session_id"] == sid1
    assert entries[1]["session_verified"] is True


# ---------------------------------------------------------------------------
# Test 3: Different visitors receive distinct sessions
# ---------------------------------------------------------------------------
def test_3_different_visitors_receive_distinct_sessions(temp_log: Path):
    client1 = TestClient(app)
    client2 = TestClient(app)

    res1 = client1.get("/products")
    res2 = client2.get("/products")

    sid1 = res1.cookies.get(SESSION_COOKIE_NAME)
    sid2 = res2.cookies.get(SESSION_COOKIE_NAME)

    assert sid1 is not None
    assert sid2 is not None
    assert sid1 != sid2

    assert session_store.get_session(sid1) is not None
    assert session_store.get_session(sid2) is not None


# ---------------------------------------------------------------------------
# Test 4: Client-supplied forged session IDs are rejected and replaced
# ---------------------------------------------------------------------------
def test_4_forged_session_id_rejected_and_replaced(temp_log: Path):
    forged_client = TestClient(app)
    forged_sid = "attacker_forged_sid_666"

    # Send request with forged cookie
    response = forged_client.get(
        "/products",
        cookies={SESSION_COOKIE_NAME: forged_sid},
    )
    assert response.status_code == 200

    # The returned cookie must NOT be the forged one
    new_sid = response.cookies.get(SESSION_COOKIE_NAME)
    assert new_sid is not None
    assert new_sid != forged_sid
    assert new_sid.startswith("sess_")

    # The forged ID must NOT exist in session store
    assert session_store.get_session(forged_sid) is None

    # The log must record the new authentic session ID, NOT the forged ID
    entries = _read_log_entries(temp_log)
    assert len(entries) == 1
    assert entries[0]["session_id"] == new_sid
    assert entries[0]["session_verified"] is True


# ---------------------------------------------------------------------------
# Test 5: Session expiration (max lifetime)
# ---------------------------------------------------------------------------
def test_5_session_expiration_max_lifetime(client: TestClient):
    # Establish session
    res1 = client.get("/products")
    sid1 = res1.cookies.get(SESSION_COOKIE_NAME)
    assert sid1 is not None

    # Artificially age the session past MAX_LIFETIME (24h)
    sdata = session_store.get_session(sid1)
    assert sdata is not None
    sdata.created_at = time.time() - (SESSION_MAX_LIFETIME + 10.0)

    # Next request with this cookie should see it expired and issue a new one
    res2 = client.get("/products")
    sid2 = res2.cookies.get(SESSION_COOKIE_NAME)
    assert sid2 is not None
    assert sid1 != sid2

    # Old session should be gone from store
    assert session_store.get_session(sid1) is None
    assert session_store.get_session(sid2) is not None


# ---------------------------------------------------------------------------
# Test 6: Session inactivity timeout (30 min)
# ---------------------------------------------------------------------------
def test_6_session_inactivity_timeout(client: TestClient):
    # Establish session
    res1 = client.get("/products")
    sid1 = res1.cookies.get(SESSION_COOKIE_NAME)
    assert sid1 is not None

    # Artificially age last_activity past INACTIVITY_TIMEOUT (30 min)
    sdata = session_store.get_session(sid1)
    assert sdata is not None
    sdata.last_activity = time.time() - (SESSION_INACTIVITY_TIMEOUT + 10.0)

    # Next request with this cookie should see timeout and issue new session
    res2 = client.get("/products")
    sid2 = res2.cookies.get(SESSION_COOKIE_NAME)
    assert sid2 is not None
    assert sid1 != sid2

    # Old session should be removed
    assert session_store.get_session(sid1) is None
    assert session_store.get_session(sid2) is not None


# ---------------------------------------------------------------------------
# Test 7: Multiple clients sharing an IP receive distinct sessions
# ---------------------------------------------------------------------------
def test_7_multiple_clients_sharing_ip_distinct_sessions(parser: TrafficFeatureParser):
    shared_ip = "192.168.1.100"

    rec_client_a = {
        "timestamp": 100.0,
        "request_id": "req-a-1",
        "method": "GET",
        "path": "/products",
        "client_ip": shared_ip,
        "session_id": "sess_client_a",
        "session_verified": True,
        "status_code": 200,
    }
    rec_client_b = {
        "timestamp": 102.0,
        "request_id": "req-b-1",
        "method": "GET",
        "path": "/search",
        "client_ip": shared_ip,
        "session_id": "sess_client_b",
        "session_verified": True,
        "status_code": 200,
    }

    res_a = parser.parse_log_entry(rec_client_a)
    res_b = parser.parse_log_entry(rec_client_b)

    # IP tracker tracks aggregate activity for the shared IP
    assert res_b.client_ip_metrics["client_ip_req_count"] == 2

    # Verified sessions remain strictly separated!
    assert res_a.session_features["f_session_req_count"] == 1
    assert res_b.session_features["f_session_req_count"] == 1

    # Sequence histories are isolated per session
    assert len(res_a.sequence_history) == 1
    assert res_a.sequence_history[0]["session_id"] == "sess_client_a"
    assert len(res_b.sequence_history) == 1
    assert res_b.sequence_history[0]["session_id"] == "sess_client_b"


# ---------------------------------------------------------------------------
# Test 8: Session feature calculation
# ---------------------------------------------------------------------------
def test_8_session_feature_calculation(parser: TrafficFeatureParser):
    sid = "sess_feature_test"

    # Request 1: t=10.0, /products, 200 OK
    r1 = parser.parse_log_entry({
        "timestamp": 10.0,
        "method": "GET",
        "path": "/products",
        "status_code": 200,
        "client_ip": "10.0.0.1",
        "session_id": sid,
        "session_verified": True,
    })
    sf1 = r1.session_features
    assert sf1["f_session_req_count"] == 1
    assert sf1["f_session_duration"] == 0.0
    assert sf1["f_session_unique_paths"] == 1
    assert sf1["f_session_error_count"] == 0

    # Request 2: t=15.0, /search, 200 OK
    r2 = parser.parse_log_entry({
        "timestamp": 15.0,
        "method": "GET",
        "path": "/search",
        "status_code": 200,
        "client_ip": "10.0.0.1",
        "session_id": sid,
        "session_verified": True,
    })
    sf2 = r2.session_features
    assert sf2["f_session_req_count"] == 2
    assert sf2["f_session_duration"] == 5.0
    assert sf2["f_session_unique_paths"] == 2
    assert sf2["f_session_error_count"] == 0

    # Request 3: t=20.0, /missing, 404 Not Found
    r3 = parser.parse_log_entry({
        "timestamp": 20.0,
        "method": "GET",
        "path": "/missing",
        "status_code": 404,
        "client_ip": "10.0.0.1",
        "session_id": sid,
        "session_verified": True,
    })
    sf3 = r3.session_features
    assert sf3["f_session_req_count"] == 3
    assert sf3["f_session_duration"] == 10.0
    assert sf3["f_session_unique_paths"] == 3
    assert sf3["f_session_error_count"] == 1
    assert sf3["f_session_req_rate"] == 0.3  # 3 reqs / 10s


# ---------------------------------------------------------------------------
# Test 9: Correct chronological sequence history for Sequence LSTM
# ---------------------------------------------------------------------------
def test_9_chronological_sequence_history_and_capped_length(parser: TrafficFeatureParser):
    sid = "sess_lstm_test"

    # Send 105 requests to verify chronological order and cap at 99
    last_res = None
    for i in range(105):
        rec = {
            "timestamp": 1000.0 + float(i),
            "method": "GET",
            "path": f"/step/{i}",
            "status_code": 200,
            "client_ip": "10.0.0.2",
            "session_id": sid,
            "session_verified": True,
        }
        last_res = parser.parse_log_entry(rec)

    assert last_res is not None
    seq = last_res.sequence_history
    assert seq is not None

    # Length must be capped at MAX_SEQUENCE_HISTORY_LENGTH (99)
    assert len(seq) == MAX_SEQUENCE_HISTORY_LENGTH

    # Timestamps in sequence must be chronological
    timestamps = [step["timestamp"] for step in seq]
    assert timestamps == sorted(timestamps)

    # First element in capped history should be i = 105 - 99 = 6
    assert timestamps[0] == 1006.0
    assert timestamps[-1] == 1104.0

    # Every step must contain exact 11 payload features
    for step in seq:
        assert step["session_id"] == sid
        for fname in PAYLOAD_FEATURE_NAMES:
            assert fname in step


# ---------------------------------------------------------------------------
# Test 10: Session IDs are not exposed in frontend responses
# ---------------------------------------------------------------------------
def test_10_session_id_not_exposed_in_response_bodies(client: TestClient):
    endpoints = [
        ("GET", "/"),
        ("GET", "/products"),
        ("GET", "/search?q=test"),
        ("GET", "/api/metrics"),
    ]

    for meth, path in endpoints:
        res = client.request(meth, path)
        assert res.status_code == 200
        sid = res.cookies.get(SESSION_COOKIE_NAME)
        assert sid is not None
        # Body text must not leak the session ID
        assert sid not in res.text

    # Specifically test /login POST response
    login_res = client.post("/login", data={"username": "alice", "password": "secure_pass_123"})
    assert login_res.status_code == 200
    login_data = login_res.json()

    login_sid = login_res.cookies.get(SESSION_COOKIE_NAME)
    assert login_sid is not None

    # No session_id or session_token in body
    assert "session_token" not in login_data
    assert "session_id" not in login_data
    assert login_sid not in json.dumps(login_data)
    assert login_data["authenticated"] is True
    assert login_data["username"] == "alice"


# ---------------------------------------------------------------------------
# Test 11: Passwords and secrets are never stored in access logs
# ---------------------------------------------------------------------------
def test_11_passwords_and_secrets_never_stored_in_logs(client: TestClient, temp_log: Path):
    secret_pwd = "MySuperSecretPassword#2026!"
    secret_token = "VeryConfidentialAuthTokenXYZ"
    secret_key = "TopSecretApiKey777"

    # POST /login with secret password
    r1 = client.post("/login", data={"username": "admin", "password": secret_pwd})
    assert r1.status_code == 200

    # GET /search with sensitive query params
    r2 = client.get(f"/search?q=waf&token={secret_token}&api_key={secret_key}")
    assert r2.status_code == 200

    # Read the written log file as raw text
    log_text = temp_log.read_text(encoding="utf-8")

    # Assert secret credentials are NEVER recorded in access.log
    assert secret_pwd not in log_text
    assert secret_token not in log_text
    assert secret_key not in log_text

    # Redaction placeholders should be present
    entries = _read_log_entries(temp_log)
    assert len(entries) >= 2
    search_entry = next(e for e in entries if e["path"] == "/search")
    assert search_entry["query_params"]["token"] == "***REDACTED***"
    assert search_entry["query_params"]["api_key"] == "***REDACTED***"


# ---------------------------------------------------------------------------
# Test 12: In-memory POST body attack detection & model compatibility
# ---------------------------------------------------------------------------
def test_12_in_memory_post_body_attack_detection_and_model_compatibility(
    client: TestClient,
    temp_log: Path,
    parser: TrafficFeatureParser,
):
    sqli_payload = "1' OR '1'='1 --"

    # Send POST with SQLi in JSON payload
    res = client.post(
        "/api/data",
        json={"search_filter": sqli_payload, "category": "sec"},
    )
    assert res.status_code == 200

    # Read access log entry
    entries = _read_log_entries(temp_log)
    assert len(entries) == 1
    log_entry = entries[0]

    # Verify body indicators
    assert log_entry["body_size_bytes"] > 0
    assert log_entry["body_indicators"]["has_sqli"] == 1
    assert log_entry["body_indicators"]["has_xss"] == 0

    # Raw SQL injection payload must NOT be stored in log entry
    assert sqli_payload not in json.dumps(log_entry["body_indicators"])
    assert "body" not in log_entry  # Raw body is not logged

    # Parse log entry with TrafficFeatureParser
    parsed = parser.parse_log_entry(log_entry)
    assert parsed.is_valid is True
    assert parsed.payload_features["f_has_sqli"] == 1

    # Verify detector availability with authentic session
    assert parsed.detector_availability["http"] is True
    assert parsed.detector_availability["session"] is True
    assert parsed.detector_availability["sequence"] is True
    assert parsed.detector_availability["network"] is False
    assert parsed.detector_availability["autoencoder"] is False

    # End-to-end model evaluation compatibility check
    from src.detection.http_detector import predict_http
    from src.detection.session_detector import predict_session
    from src.detection.sentinel_adapter import predict_sequence
    from src.detection.aggregator import aggregate_event

    # Evaluate HTTP Random Forest
    http_res = predict_http(parsed.event_features)
    assert "predicted_class" in http_res
    assert "confidence" in http_res
    assert "class_probabilities" in http_res

    # Evaluate Session Random Forest
    session_res = predict_session(parsed.event_features)
    assert "predicted_class" in session_res
    assert "confidence" in session_res
    assert "class_probabilities" in session_res

    # Evaluate Sequence LSTM
    seq_res = predict_sequence(parsed.sequence_history)
    assert "attack_probability" in seq_res
    assert "predicted_class" in seq_res
    assert "session_length" in seq_res

    # Evaluate Hybrid Risk Aggregator
    agg_res = aggregate_event(
        event=parsed.event_features,
        session_history=parsed.sequence_history,
    )
    assert "overall_risk_score" in agg_res
    assert "evaluated_detectors" in agg_res
    assert "http" in agg_res["evaluated_detectors"]
    assert "session" in agg_res["evaluated_detectors"]
    assert "sequence" in agg_res["evaluated_detectors"]
    assert "network" not in agg_res["evaluated_detectors"]
    assert "autoencoder" not in agg_res["evaluated_detectors"]
