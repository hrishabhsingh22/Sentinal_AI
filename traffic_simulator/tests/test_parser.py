"""
Unit & Integration Tests for SENTINEL AI Stateful Traffic Feature Parser (Stage 2B)

Verifies:
1. Normal GET requests.
2. SQL injection-style query parameters.
3. XSS-style parameters.
4. Path traversal.
5. Command injection patterns.
6. Encoded payloads.
7. Scanner user agents.
8. Redacted sensitive parameters.
9. Multiple requests inside time windows.
10. Expired time windows.
11. Out-of-order timestamps.
12. Malformed log records.
13. Missing request fields.
14. Multiple clients sharing an IP.
15. No genuine session ID means no verified LSTM history.
16. Missing body or network features means those detectors remain unavailable.
"""

import sys
from pathlib import Path

# Ensure project root is on sys.path
PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest
from traffic_simulator.parser import (
    TrafficFeatureParser,
    extract_payload_features,
    PAYLOAD_FEATURE_NAMES,
    TIME_FEATURE_NAMES,
    SESSION_FEATURE_NAMES,
    HTTP_FEATURE_NAMES,
    SESSION_DETECTOR_FEATURES,
    SEQUENCE_FEATURE_NAMES,
)


@pytest.fixture
def parser():
    """Provides a fresh TrafficFeatureParser with clean in-memory state."""
    p = TrafficFeatureParser()
    p.reset()
    return p


# ---------------------------------------------------------------------------
# Test 1: Normal GET requests
# ---------------------------------------------------------------------------
def test_normal_get_request(parser):
    record = {
        "timestamp": "2026-11-17T10:00:00.000000+00:00",
        "request_id": "req-001",
        "method": "GET",
        "path": "/products",
        "query_params": {"category": "Network Security"},
        "status_code": 200,
        "client_ip": "192.168.1.10",
        "user_agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)",
        "response_size_bytes": 834,
        "duration_ms": 1.25,
    }
    result = parser.parse_log_entry(record)

    assert result.is_valid is True
    assert result.validation_errors == []

    # Verify all attack flags are strictly 0
    payload = result.payload_features
    assert payload["f_has_sqli"] == 0
    assert payload["f_has_xss"] == 0
    assert payload["f_has_lfi"] == 0
    assert payload["f_has_cmd"] == 0
    assert payload["f_has_ssrf"] == 0
    assert payload["f_has_traversal"] == 0
    assert payload["f_is_scanner_ua"] == 0
    assert payload["f_has_encoded"] == 0
    assert payload["f_has_sql_comment"] == 0

    assert payload["f_path_depth"] == 1
    assert payload["f_query_len"] > 0


# ---------------------------------------------------------------------------
# Test 2: SQL injection-style query parameters
# ---------------------------------------------------------------------------
def test_sqli_query_parameters(parser):
    sqli_samples = [
        {"q": "1' OR '1'='1"},
        {"q": "admin' OR 1=1--"},
        {"q": "UNION SELECT username, password FROM users"},
        {"q": "'; DROP TABLE accounts;--"},
        {"q": "1; WAITFOR DELAY '0:0:5'"},
    ]
    for sample in sqli_samples:
        record = {
            "timestamp": "2026-11-17T10:00:01.000000+00:00",
            "method": "GET",
            "path": "/search",
            "query_params": sample,
            "status_code": 200,
            "client_ip": "10.0.0.5",
        }
        result = parser.parse_log_entry(record)
        assert result.payload_features["f_has_sqli"] == 1, f"Failed for {sample}"


# ---------------------------------------------------------------------------
# Test 3: XSS-style parameters
# ---------------------------------------------------------------------------
def test_xss_query_parameters(parser):
    xss_samples = [
        {"q": "<script>alert(1)</script>"},
        {"q": "<img src=x onerror=alert('XSS')>"},
        {"q": "javascript:alert(document.cookie)"},
        {"q": "<svg/onload=confirm(1)>"},
        {"q": "<iframe src='javascript:alert(1)'>"},
    ]
    for sample in xss_samples:
        record = {
            "timestamp": "2026-11-17T10:00:02.000000+00:00",
            "method": "GET",
            "path": "/search",
            "query_params": sample,
            "status_code": 200,
            "client_ip": "10.0.0.6",
        }
        result = parser.parse_log_entry(record)
        assert result.payload_features["f_has_xss"] == 1, f"Failed for {sample}"


# ---------------------------------------------------------------------------
# Test 4: Path traversal
# ---------------------------------------------------------------------------
def test_path_traversal(parser):
    traversal_samples = [
        {"path": "/../../etc/passwd", "query": {}},
        {"path": "/files/..%2f..%2fetc/passwd", "query": {}},
        {"path": "/download", "query": {"file": "../../etc/shadow"}},
        {"path": "/images", "query": {"path": "..\\..\\windows\\win.ini"}},
    ]
    for sample in traversal_samples:
        record = {
            "timestamp": "2026-11-17T10:00:03.000000+00:00",
            "method": "GET",
            "path": sample["path"],
            "query_params": sample["query"],
            "status_code": 404,
            "client_ip": "10.0.0.7",
        }
        result = parser.parse_log_entry(record)
        assert result.payload_features["f_has_traversal"] == 1, f"Failed for {sample}"


# ---------------------------------------------------------------------------
# Test 5: Command injection patterns
# ---------------------------------------------------------------------------
def test_command_injection_patterns(parser):
    cmd_samples = [
        {"q": "; cat /etc/passwd"},
        {"q": "| whoami"},
        {"q": "&& ls -la /"},
        {"q": "$(id)"},
        {"q": "`cat /etc/shadow`"},
    ]
    for sample in cmd_samples:
        record = {
            "timestamp": "2026-11-17T10:00:04.000000+00:00",
            "method": "GET",
            "path": "/search",
            "query_params": sample,
            "status_code": 200,
            "client_ip": "10.0.0.8",
        }
        result = parser.parse_log_entry(record)
        assert result.payload_features["f_has_cmd"] == 1, f"Failed for {sample}"


# ---------------------------------------------------------------------------
# Test 6: Encoded payloads
# ---------------------------------------------------------------------------
def test_encoded_payloads(parser):
    record = {
        "timestamp": "2026-11-17T10:00:05.000000+00:00",
        "method": "GET",
        "path": "/search",
        "query_params": {"q": "%3Cscript%3Ealert%281%29%3C%2Fscript%3E"},
        "status_code": 200,
        "client_ip": "10.0.0.9",
    }
    result = parser.parse_log_entry(record)
    assert result.payload_features["f_has_encoded"] == 1
    assert result.payload_features["f_has_xss"] == 1


# ---------------------------------------------------------------------------
# Test 7: Scanner user agents
# ---------------------------------------------------------------------------
def test_scanner_user_agents(parser):
    scanners = [
        "sqlmap/1.7#stable",
        "Mozilla/5.0 (compatible; Nikto/2.1.6)",
        "Nmap Scripting Engine",
        "Gobuster/3.1.0",
        "Wget/1.21",  # Not scanner regex
    ]
    for ua in scanners[:-1]:
        record = {
            "timestamp": "2026-11-17T10:00:06.000000+00:00",
            "method": "GET",
            "path": "/products",
            "user_agent": ua,
            "status_code": 200,
            "client_ip": "10.0.0.10",
        }
        result = parser.parse_log_entry(record)
        assert result.payload_features["f_is_scanner_ua"] == 1, f"Failed for {ua}"

    # Normal browser User-Agent
    normal_record = {
        "timestamp": "2026-11-17T10:00:07.000000+00:00",
        "method": "GET",
        "path": "/products",
        "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "status_code": 200,
        "client_ip": "10.0.0.10",
    }
    normal_result = parser.parse_log_entry(normal_record)
    assert normal_result.payload_features["f_is_scanner_ua"] == 0


# ---------------------------------------------------------------------------
# Test 8: Redacted sensitive parameters
# ---------------------------------------------------------------------------
def test_redacted_sensitive_parameters(parser):
    # A log entry where sensitive keys were redacted to ***REDACTED***
    record = {
        "timestamp": "2026-11-17T10:00:08.000000+00:00",
        "method": "GET",
        "path": "/search",
        "query_params": {
            "q": "safe query",
            "password": "***REDACTED***",
            "api_key": "***REDACTED***",
            "token": "***REDACTED***",
        },
        "status_code": 200,
        "client_ip": "10.0.0.11",
    }
    result = parser.parse_log_entry(record)

    # Redaction placeholders must NOT trigger any attack flags
    assert result.payload_features["f_has_sqli"] == 0
    assert result.payload_features["f_has_xss"] == 0
    assert result.payload_features["f_has_cmd"] == 0
    assert result.payload_features["f_has_sql_comment"] == 0

    # Query length should measure the genuine query ("q=safe query"), not "***REDACTED***"
    assert result.payload_features["f_query_len"] < 40


# ---------------------------------------------------------------------------
# Test 9: Multiple requests inside time windows
# ---------------------------------------------------------------------------
def test_multiple_requests_inside_time_windows(parser):
    # Send 5 requests spaced 0.1s apart at t = 100.0, 100.1, 100.2, 100.3, 100.4
    results = []
    base_t = 100.0
    paths = ["/a", "/b", "/c", "/d", "/e"]
    statuses = [200, 200, 404, 500, 200]

    for i in range(5):
        rec = {
            "timestamp": base_t + i * 0.1,
            "method": "GET",
            "path": paths[i],
            "status_code": statuses[i],
            "client_ip": "192.168.1.100",
        }
        results.append(parser.parse_log_entry(rec))

    latest = results[-1]
    time_feat = latest.time_window_features

    # All 5 events are within trailing 1s
    assert time_feat["f_req_count_1s"] == 5
    assert time_feat["f_req_rate_1s"] == 5.0

    # All 5 events are within trailing 10s and 60s
    assert time_feat["f_req_count_10s"] == 5
    assert time_feat["f_req_rate_10s"] == 0.5  # 5 / 10s
    assert time_feat["f_req_count_60s"] == 5
    assert time_feat["f_req_rate_60s"] == round(5.0 / 60.0, 4)

    # Status breakdown in 10s window: 5 events total, 2 errors (404, 500), 1 404
    assert time_feat["f_404_count_10s"] == 1
    assert time_feat["f_404_count_60s"] == 1
    assert time_feat["f_error_ratio_10s"] == 0.4  # 2 errors / 5 requests
    assert time_feat["f_unique_paths_10s"] == 5


# ---------------------------------------------------------------------------
# Test 10: Expired time windows
# ---------------------------------------------------------------------------
def test_expired_time_windows(parser):
    # Event 1 at t = 10.0
    r1 = parser.parse_log_entry({
        "timestamp": 10.0,
        "method": "GET",
        "path": "/old",
        "status_code": 200,
        "client_ip": "10.0.0.1",
    })
    assert r1.time_window_features["f_req_count_1s"] == 1

    # Event 2 at t = 75.0 (65 seconds later -> outside 60s window)
    r2 = parser.parse_log_entry({
        "timestamp": 75.0,
        "method": "GET",
        "path": "/new",
        "status_code": 200,
        "client_ip": "10.0.0.1",
    })

    # The event at t=10.0 has expired and should not be counted
    assert r2.time_window_features["f_req_count_1s"] == 1
    assert r2.time_window_features["f_req_count_10s"] == 1
    assert r2.time_window_features["f_req_count_60s"] == 1


# ---------------------------------------------------------------------------
# Test 11: Out-of-order timestamps
# ---------------------------------------------------------------------------
def test_out_of_order_timestamps(parser):
    # Events arrive as: t=10.0, t=12.0, then out-of-order t=11.0
    parser.parse_log_entry({
        "timestamp": 10.0, "method": "GET", "path": "/1", "status_code": 200, "client_ip": "1.1.1.1"
    })
    parser.parse_log_entry({
        "timestamp": 12.0, "method": "GET", "path": "/3", "status_code": 200, "client_ip": "1.1.1.1"
    })
    r_ooo = parser.parse_log_entry({
        "timestamp": 11.0, "method": "GET", "path": "/2", "status_code": 200, "client_ip": "1.1.1.1"
    })

    # Does not crash, handles insertion, produces finite non-negative rates
    assert r_ooo.is_valid is True
    assert r_ooo.time_window_features["f_req_count_10s"] == 3
    assert r_ooo.time_window_features["f_req_rate_10s"] > 0


# ---------------------------------------------------------------------------
# Test 12: Malformed log records
# ---------------------------------------------------------------------------
def test_malformed_log_records(parser):
    # Non-dictionary record
    r_bad_type = parser.parse_log_entry("not a dict")
    assert r_bad_type.is_valid is False
    assert len(r_bad_type.validation_errors) > 0

    # Malformed timestamp string
    r_bad_ts = parser.parse_log_entry({
        "timestamp": "unparseable-date-string",
        "method": "GET",
        "path": "/test",
        "status_code": 200,
        "client_ip": "127.0.0.1",
    })
    assert r_bad_ts.is_valid is False
    assert any("timestamp" in err.lower() for err in r_bad_ts.validation_errors)

    # Invalid status code
    r_bad_status = parser.parse_log_entry({
        "timestamp": "2026-11-17T10:00:00Z",
        "method": "GET",
        "path": "/test",
        "status_code": "not-an-int",
        "client_ip": "127.0.0.1",
    })
    assert r_bad_status.is_valid is False


# ---------------------------------------------------------------------------
# Test 13: Missing request fields
# ---------------------------------------------------------------------------
def test_missing_request_fields(parser):
    # Missing required field: path & client_ip
    r = parser.parse_log_entry({
        "timestamp": "2026-11-17T10:00:00Z",
        "method": "GET",
        "status_code": 200,
    })
    assert r.is_valid is False
    assert any("missing required" in err.lower() for err in r.validation_errors)


# ---------------------------------------------------------------------------
# Test 14: Multiple clients sharing an IP
# ---------------------------------------------------------------------------
def test_multiple_clients_sharing_ip(parser):
    shared_ip = "192.168.10.50"

    # Client A requests /index
    r1 = parser.parse_log_entry({
        "timestamp": 100.0,
        "method": "GET",
        "path": "/index",
        "status_code": 200,
        "client_ip": shared_ip,
        "user_agent": "ClientA-Browser",
    })

    # Client B requests /api from same NAT/proxy IP
    r2 = parser.parse_log_entry({
        "timestamp": 102.0,
        "method": "GET",
        "path": "/api",
        "status_code": 200,
        "client_ip": shared_ip,
        "user_agent": "ClientB-Mobile",
    })

    # client_ip_metrics aggregates across the IP
    assert r2.client_ip_metrics["client_ip"] == shared_ip
    assert r2.client_ip_metrics["client_ip_req_count"] == 2
    assert r2.client_ip_metrics["client_ip_unique_paths"] == 2
    assert r2.client_ip_metrics["is_genuine_session"] is False

    # Crucial: session features remain None because client_ip is not a genuine session ID
    assert r2.session_features is None
    assert r2.detector_availability["session"] is False


# ---------------------------------------------------------------------------
# Test 15: No genuine session ID means no verified LSTM history
# ---------------------------------------------------------------------------
def test_no_genuine_session_id_means_no_verified_lstm_history(parser):
    # Uninstrumented entry (no session_id)
    rec_uninstrumented = {
        "timestamp": 10.0,
        "method": "GET",
        "path": "/search",
        "query_params": {"q": "test"},
        "status_code": 200,
        "client_ip": "1.2.3.4",
    }
    r_uninst = parser.parse_log_entry(rec_uninstrumented)
    assert r_uninst.session_features is None
    assert r_uninst.sequence_history is None
    assert r_uninst.detector_availability["session"] is False
    assert r_uninst.detector_availability["sequence"] is False
    assert r_uninst.detector_availability["http"] is False

    # Instrumented entry (verified session_id provided)
    rec_instrumented_1 = {
        "timestamp": 10.0,
        "session_id": "sess-uuid-9999",
        "method": "GET",
        "path": "/login",
        "status_code": 200,
        "client_ip": "1.2.3.4",
    }
    r_inst_1 = parser.parse_log_entry(rec_instrumented_1)
    assert r_inst_1.session_features is not None
    assert r_inst_1.sequence_history is not None
    assert len(r_inst_1.sequence_history) == 1
    assert r_inst_1.detector_availability["session"] is True
    assert r_inst_1.detector_availability["sequence"] is True
    assert r_inst_1.detector_availability["http"] is True

    # Second request in the same verified session
    rec_instrumented_2 = {
        "timestamp": 11.5,
        "session_id": "sess-uuid-9999",
        "method": "GET",
        "path": "/dashboard",
        "status_code": 200,
        "client_ip": "1.2.3.4",
    }
    r_inst_2 = parser.parse_log_entry(rec_instrumented_2)
    assert r_inst_2.session_features["f_session_req_count"] == 2
    assert r_inst_2.session_features["f_session_duration"] == 1.5
    assert len(r_inst_2.sequence_history) == 2


# ---------------------------------------------------------------------------
# Test 16: Missing body or network features means those detectors remain unavailable
# ---------------------------------------------------------------------------
def test_missing_body_or_network_features_means_unavailable(parser):
    rec = {
        "timestamp": 10.0,
        "method": "POST",
        "path": "/api/data",
        "status_code": 200,
        "client_ip": "1.2.3.4",
        "response_size_bytes": 128,
    }
    r = parser.parse_log_entry(rec)

    # Network is ALWAYS False for web access logs
    assert r.detector_availability["network"] is False
    assert "network" in r.unavailable_reasons
    assert "telemetry" in r.unavailable_reasons["network"].lower()

    # Autoencoder is False because body & headers are missing
    assert r.detector_availability["autoencoder"] is False
    assert "autoencoder" in r.unavailable_reasons
    assert "body" in r.unavailable_reasons["autoencoder"].lower()

    # Verify no fake zero-filled network or autoencoder features are generated in event_features
    for net_col in ["f_flow_pkts_total", "f_tcp_syn", "f_suricata_alerts_60s"]:
        assert net_col not in r.event_features
    for ae_col in ["body_size", "payload_entropy", "has_cookie", "content_length_header"]:
        assert ae_col not in r.event_features
