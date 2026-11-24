"""API Integration Tests for SENTINEL AI FastAPI backend.

Verifies:
1. Health and Root endpoints.
2. Evaluation of known benign HTTP events.
3. Evaluation of known attack HTTP events.
4. Evaluation with multi-request chronological session history.
5. Robust input validation and schema error handling (422).
6. Graceful handling of unavailable detectors without API crashes.
7. Flat and nested request schema flexibility.
"""

from pathlib import Path
from typing import Any, Dict
import numpy as np
import pandas as pd
from fastapi.testclient import TestClient

from src.api.app import app

ROOT = Path(__file__).resolve().parents[1]
SOC_TEST_PATH = ROOT / "data/processed/soc_mld/test.csv"
NETWORK_TEST_PATH = ROOT / "data/processed/soc_mld/network_test.csv"
AE_NORMAL_PATH = ROOT / "data/processed/test_features.csv"

client = TestClient(app)


def _clean_record(d: Dict[str, Any]) -> Dict[str, Any]:
    """Convert NaN values to None for standard JSON serialization."""
    return {
        k: (None if (isinstance(v, float) and np.isnan(v)) else v)
        for k, v in d.items()
    }


# ---------------------------------------------------------------------------
# 1. Health & Root Info Endpoints
# ---------------------------------------------------------------------------
def test_root_endpoint():
    """Verify service information endpoint."""
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "running"
    assert "version" in data
    assert data["docs_url"] == "/docs"


def test_health_endpoint():
    """Verify health check endpoint and detector artifact availability."""
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["service"] == "sentinel-ai-backend"
    assert "detectors" in data
    for det in ["http", "session", "sequence", "network", "autoencoder"]:
        assert det in data["detectors"]
        assert data["detectors"][det] is True


# ---------------------------------------------------------------------------
# 2. Benign HTTP Input Evaluation
# ---------------------------------------------------------------------------
def test_evaluate_benign_http_input():
    """Verify benign HTTP event returns low risk score and is_threat=False."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    raw_benign = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "NORMAL")].iloc[0].to_dict()
    benign_event = _clean_record(raw_benign)

    response = client.post("/evaluate", json={"event": benign_event})
    assert response.status_code == 200
    data = response.json()

    assert "http" in data["evaluated_detectors"]
    assert "session" in data["evaluated_detectors"]
    assert data["overall_risk_score"] < 0.50
    assert data["is_threat"] is False
    assert data["primary_threat_type"] == "NORMAL"
    assert data["contributing_detectors"] == []
    assert data["risk_level"] in ("LOW", "INFORMATIONAL")

    # Also test the convenience /evaluate/http endpoint
    http_resp = client.post("/evaluate/http", json={"event": benign_event})
    assert http_resp.status_code == 200
    assert http_resp.json()["primary_threat_type"] == "NORMAL"


def test_evaluate_flat_event_payload():
    """Verify flat event payload without explicit 'event' wrapper is supported."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    raw_benign = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "NORMAL")].iloc[0].to_dict()
    benign_event = _clean_record(raw_benign)

    # Pass directly as top-level JSON object
    response = client.post("/evaluate", json=benign_event)
    assert response.status_code == 200
    data = response.json()
    assert "http" in data["evaluated_detectors"]
    assert data["is_threat"] is False


# ---------------------------------------------------------------------------
# 3. Attack HTTP Input Evaluation
# ---------------------------------------------------------------------------
def test_evaluate_attack_http_input():
    """Verify attack HTTP event returns high risk score and is_threat=True."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    raw_attack = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "SQLI_ATTEMPT")].iloc[0].to_dict()
    attack_event = _clean_record(raw_attack)

    response = client.post("/evaluate", json={"event": attack_event})
    assert response.status_code == 200
    data = response.json()

    assert "http" in data["evaluated_detectors"]
    assert data["overall_risk_score"] >= 0.50
    assert data["is_threat"] is True
    assert data["primary_threat_type"] == "SQLI_ATTEMPT"
    assert "http" in data["contributing_detectors"]
    assert data["risk_level"] in ("HIGH", "CRITICAL")


# ---------------------------------------------------------------------------
# 4. Session History Integration
# ---------------------------------------------------------------------------
def test_evaluate_with_session_history():
    """Verify chronological session history triggers sequence LSTM evaluation."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    session_id = "S_192.168.70.132_59682380"
    session_rows = soc_df[(soc_df["source"] == "nginx") & (soc_df["session_id"] == session_id)]
    session_rows = session_rows.sort_values(["timestamp", "request_id"])

    latest_event = _clean_record(session_rows.iloc[-1].to_dict())
    history_records = [_clean_record(r) for r in session_rows.to_dict(orient="records")]

    payload = {
        "event": latest_event,
        "session_history": history_records,
    }

    response = client.post("/evaluate", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert "sequence" in data["evaluated_detectors"]
    seq_result = data["detector_results"]["sequence"]
    assert seq_result["available"] is True
    assert seq_result["threat_score"] is not None
    assert 0.0 <= seq_result["threat_score"] <= 1.0


# ---------------------------------------------------------------------------
# 5. Invalid Input & Schema Validation Errors
# ---------------------------------------------------------------------------
def test_invalid_input_handling():
    """Verify invalid payloads produce meaningful 422 validation errors."""
    # Empty body
    r1 = client.post("/evaluate", json={})
    assert r1.status_code == 422
    assert "cannot be empty" in str(r1.json()).lower()

    # Empty event dictionary explicitly
    r2 = client.post("/evaluate", json={"event": {}})
    assert r2.status_code == 422
    assert "cannot be empty" in str(r2.json()).lower()

    # Invalid event type
    r3 = client.post("/evaluate", json={"event": "not-a-dict"})
    assert r3.status_code == 422

    # Invalid session history type
    r4 = client.post("/evaluate", json={"event": {"f_has_sqli": 1}, "session_history": "not-a-list"})
    assert r4.status_code == 422

    # Invalid session history records (contains non-dict item)
    r5 = client.post("/evaluate", json={"event": {"f_has_sqli": 1}, "session_history": ["not-a-dict"]})
    assert r5.status_code == 422

    # Invalid aggregator configuration override (negative weight)
    r6 = client.post(
        "/evaluate",
        json={"event": {"f_has_sqli": 1}, "config": {"weight_http": -0.5}},
    )
    assert r6.status_code == 422


# ---------------------------------------------------------------------------
# 6. Unavailable Detectors Handling
# ---------------------------------------------------------------------------
def test_unavailable_detectors_handling():
    """Verify missing features and unavailable detectors do not crash the API."""
    # A. Payload-only event (Autoencoder features only)
    ae_df = pd.read_csv(AE_NORMAL_PATH, nrows=1)
    ae_sample = _clean_record(ae_df.iloc[0].to_dict())

    r_ae = client.post("/evaluate", json={"event": ae_sample})
    assert r_ae.status_code == 200
    data_ae = r_ae.json()
    assert data_ae["evaluated_detectors"] == ["autoencoder"]
    for d in ["http", "session", "sequence", "network"]:
        assert d in data_ae["unavailable_detectors"]
        assert data_ae["detector_results"][d]["available"] is False
        assert data_ae["detector_results"][d]["threat_score"] is None

    # B. Network event without benign class
    net_df = pd.read_csv(NETWORK_TEST_PATH, nrows=1)
    net_sample = _clean_record(net_df.iloc[0].to_dict())

    r_net = client.post("/evaluate", json={"event": net_sample})
    assert r_net.status_code == 200
    data_net = r_net.json()
    # Network detector should be unavailable rather than inventing a score
    assert data_net["detector_results"]["network"]["available"] is False
    assert data_net["detector_results"]["network"]["threat_score"] is None
    assert data_net["detector_results"]["network"]["threat_type"] == "UNAVAILABLE"

    # C. Event with completely unrecognized feature keys
    r_unknown = client.post("/evaluate", json={"event": {"irrelevant_field": 12345}})
    assert r_unknown.status_code == 200
    data_unknown = r_unknown.json()
    assert data_unknown["evaluated_detectors"] == []
    assert data_unknown["overall_risk_score"] == 0.0
    assert data_unknown["risk_level"] == "UNKNOWN"
    assert data_unknown["is_threat"] is False
