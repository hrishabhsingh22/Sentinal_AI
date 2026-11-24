"""Comprehensive test suite for the SENTINEL AI Hybrid Risk Aggregator.

Verifies:
1. Known benign HTTP event handling (NORMAL).
2. Known attack HTTP event handling (SQLI_ATTEMPT).
3. Known benign network event check (confirm none in SOC-MLD; test schema if benign class present).
4. Known network attack event (verify threat scoring is unavailable when no benign class exists in model).
5. Genuine multi-request session (11-feature validation per record, sequence execution, correlation dampening).
6. Unavailable detectors handling (omitted from denominator, not treated as zero).
7. Unexpected class-probability schema (missing NORMAL does not default to 0.0; marks detector unavailable).
8. Configuration validation (rejects invalid/negative/non-finite weights and inverted thresholds).
9. Cross-domain corroboration boost.
10. Empty/invalid input safety.
"""

from pathlib import Path
from unittest.mock import patch
import math
import pytest
import numpy as np
import pandas as pd

from src.detection.aggregator import (
    HybridRiskAggregator,
    AggregatorConfig,
    aggregate_event,
    is_benign_label,
    BENIGN_LABELS,
)

ROOT = Path(__file__).resolve().parents[1]
SOC_TEST_PATH = ROOT / "data/processed/soc_mld/test.csv"
NETWORK_TEST_PATH = ROOT / "data/processed/soc_mld/network_test.csv"
NETWORK_TRAIN_PATH = ROOT / "data/processed/soc_mld/network_train.csv"
AE_NORMAL_PATH = ROOT / "data/processed/test_features.csv"
AE_ATTACK_PATH = ROOT / "data/processed/attack_features.csv"


# ---------------------------------------------------------------------------
# 1. Known Benign HTTP Event
# ---------------------------------------------------------------------------
def test_known_benign_http_event():
    """Verify known benign HTTP event produces low risk, non-threat, NORMAL type."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    benign_rows = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "NORMAL")]
    assert len(benign_rows) > 0, "No benign HTTP records found in test dataset"

    benign_event = benign_rows.iloc[0].to_dict()
    result = aggregate_event(benign_event)

    assert "http" in result["evaluated_detectors"]
    assert "session" in result["evaluated_detectors"]
    assert "sequence" in result["unavailable_detectors"]  # No session_history passed

    # Check threat scores are below threshold
    assert result["detector_results"]["http"]["threat_score"] < 0.50
    assert result["detector_results"]["http"]["threat_type"] == "NORMAL"
    assert result["detector_results"]["session"]["threat_score"] < 0.50
    assert result["detector_results"]["session"]["threat_type"] == "NORMAL"

    # Benign events must NOT contribute to threats
    assert result["contributing_detectors"] == []
    assert result["is_threat"] is False
    assert result["primary_threat_type"] == "NORMAL"
    assert result["overall_risk_score"] < 0.50
    assert result["risk_level"] in ("LOW", "INFORMATIONAL")


# ---------------------------------------------------------------------------
# 2. Known Attack HTTP Event
# ---------------------------------------------------------------------------
def test_known_attack_http_event():
    """Verify known attack HTTP event produces high risk, is_threat=True, correct threat type."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    attack_rows = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "SQLI_ATTEMPT")]
    assert len(attack_rows) > 0, "No SQLI_ATTEMPT records found in test dataset"

    attack_event = attack_rows.iloc[0].to_dict()
    result = aggregate_event(attack_event)

    assert "http" in result["evaluated_detectors"]
    assert "session" in result["evaluated_detectors"]

    # At least one web detector must detect the attack
    assert len(result["contributing_detectors"]) > 0
    assert result["is_threat"] is True
    assert result["primary_threat_type"] == "SQLI_ATTEMPT"
    assert result["overall_risk_score"] >= 0.50
    assert result["risk_level"] in ("CRITICAL", "HIGH")


# ---------------------------------------------------------------------------
# 3. Known Benign Network Event (Dataset Inspection & Graceful Handling)
# ---------------------------------------------------------------------------
def test_known_benign_network_event():
    """Inspect dataset for benign network events and test handling when benign class exists."""
    net_train = pd.read_csv(NETWORK_TRAIN_PATH)
    net_test = pd.read_csv(NETWORK_TEST_PATH)

    # Verify that in SOC-MLD, all network records are attack classes (no benign records exist)
    train_benign = [lbl for lbl in net_train["label"].unique() if is_benign_label(lbl)]
    test_benign = [lbl for lbl in net_test["label"].unique() if is_benign_label(lbl)]
    assert train_benign == [], "Unexpected benign labels found in network train"
    assert test_benign == [], "Unexpected benign labels found in network test"

    # Verify that IF a network classifier produces a calibrated benign probability,
    # the aggregator calculates the network threat score reliably as 1 - P(benign)
    sample_net = net_test.iloc[0].to_dict()
    with patch("src.detection.aggregator.predict_network") as mock_net:
        mock_net.return_value = {
            "predicted_class": "NORMAL",
            "confidence": 0.96,
            "class_probabilities": {"NORMAL": 0.96, "SYN_SCAN": 0.04},
        }
        res = aggregate_event(sample_net)
        assert res["evaluated_detectors"] == ["network"]
        assert res["detector_results"]["network"]["available"] is True
        assert np.isclose(res["detector_results"]["network"]["threat_score"], 0.04, atol=1e-3)
        assert res["detector_results"]["network"]["threat_type"] == "NORMAL"
        assert res["is_threat"] is False
        assert res["contributing_detectors"] == []
        assert res["primary_threat_type"] == "NORMAL"


# ---------------------------------------------------------------------------
# 4. Known Network Attack Event (Unavailable Threat Scoring)
# ---------------------------------------------------------------------------
def test_known_network_attack_event():
    """Verify network threat score is marked unavailable because model has no benign class."""
    net_df = pd.read_csv(NETWORK_TEST_PATH)
    net_sample = net_df.iloc[0].to_dict()

    result = aggregate_event(net_sample)

    # Network model predicted an attack (e.g. WEB_SCAN), but because its class_probabilities
    # contains only attack classes, benign probability cannot be established reliably.
    # Therefore, threat scoring must be marked unavailable rather than inventing a score.
    net_res = result["detector_results"]["network"]
    assert net_res["available"] is False
    assert net_res["threat_score"] is None
    assert net_res["threat_type"] == "UNAVAILABLE"
    assert "no benign class found" in net_res["details"]["reason"]
    assert net_res["prediction"] == "WEB_SCAN"

    # Because no detector could establish threat score, overall evaluated_detectors is empty
    assert result["evaluated_detectors"] == []
    assert result["contributing_detectors"] == []
    assert result["is_threat"] is False
    assert result["primary_threat_type"] == "UNKNOWN"
    assert result["risk_level"] == "UNKNOWN"


# ---------------------------------------------------------------------------
# 5. Genuine Multi-Request Session (Sequence Validation & Execution)
# ---------------------------------------------------------------------------
def test_genuine_multi_request_session():
    """Verify 11-feature validation, sequence LSTM execution, and correlation dampening."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    session_id = "S_192.168.70.132_59682380"
    session_rows = soc_df[(soc_df["source"] == "nginx") & (soc_df["session_id"] == session_id)]
    session_rows = session_rows.sort_values(["timestamp", "request_id"])
    assert len(session_rows) >= 2, "Session should have multiple requests"

    latest_event = session_rows.iloc[-1].to_dict()

    # Case A: Without session_history -> sequence detector MUST NOT run
    res_no_seq = aggregate_event(latest_event, session_history=None)
    assert "sequence" in res_no_seq["unavailable_detectors"]
    assert res_no_seq["detector_results"]["sequence"]["available"] is False
    assert res_no_seq["detector_results"]["sequence"]["threat_score"] is None

    # Case B: With valid chronological session_history -> sequence detector MUST run
    res_with_seq = aggregate_event(latest_event, session_history=session_rows)
    assert "sequence" in res_with_seq["evaluated_detectors"]
    seq_res = res_with_seq["detector_results"]["sequence"]
    assert seq_res["available"] is True
    assert seq_res["threat_score"] is not None
    assert 0.0 <= seq_res["threat_score"] <= 1.0

    # Correlation dampening check: web_channel_score must lie between weighted mean and peak
    scores = [
        res_with_seq["detector_results"][d]["threat_score"]
        for d in ["http", "session", "sequence"]
        if res_with_seq["detector_results"][d]["threat_score"] is not None
    ]
    peak = max(scores)
    mean = sum(scores) / len(scores)
    web_score = res_with_seq["aggregation_metadata"]["web_channel_score"]
    assert min(peak, mean) <= web_score <= max(peak, mean)

    # Case C: History missing required sequence feature -> sequence must reject safely
    invalid_rows = session_rows.copy().drop(columns=["f_has_sqli"])
    res_invalid = aggregate_event(latest_event, session_history=invalid_rows)
    assert "sequence" in res_invalid["unavailable_detectors"]
    assert res_invalid["detector_results"]["sequence"]["available"] is False


# ---------------------------------------------------------------------------
# 6. Unavailable Detectors Handling
# ---------------------------------------------------------------------------
def test_unavailable_detectors_handling():
    """Verify unavailable detectors are omitted from denominator, not treated as zero."""
    ae_df = pd.read_csv(AE_NORMAL_PATH, nrows=1)
    ae_sample = ae_df.iloc[0].to_dict()

    result = aggregate_event(ae_sample)

    # Only Autoencoder is available; http, session, sequence, network are unavailable
    assert result["evaluated_detectors"] == ["autoencoder"]
    for det in ["http", "session", "sequence", "network"]:
        assert det in result["unavailable_detectors"]
        assert result["detector_results"][det]["available"] is False
        assert result["detector_results"][det]["threat_score"] is None

    # Overall risk must equal Autoencoder score exactly without dilution
    ae_score = result["detector_results"]["autoencoder"]["threat_score"]
    assert np.isclose(result["overall_risk_score"], ae_score, atol=1e-4)
    assert result["aggregation_metadata"]["web_channel_score"] == round(ae_score, 4)


# ---------------------------------------------------------------------------
# 7. Unexpected Class-Probability Schema
# ---------------------------------------------------------------------------
def test_unexpected_class_probability_schema():
    """Verify missing NORMAL/benign class does not default to 0.0 and marks detector unavailable."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    sample = soc_df[soc_df["source"] == "nginx"].iloc[0].to_dict()

    # Mock predict_http with an unexpected schema missing NORMAL
    with patch("src.detection.aggregator.predict_http") as mock_http:
        mock_http.return_value = {
            "predicted_class": "SQLI_ATTEMPT",
            "confidence": 0.95,
            "class_probabilities": {"SQLI_ATTEMPT": 0.85, "XSS_ATTEMPT": 0.15},  # No NORMAL
        }
        res = aggregate_event(sample)

        # HTTP detector must be marked unavailable, NOT default to 0.0 benign probability
        http_res = res["detector_results"]["http"]
        assert http_res["available"] is False
        assert http_res["threat_score"] is None
        assert http_res["threat_type"] == "UNAVAILABLE"
        assert "Expected benign class (NORMAL/BENIGN) missing" in http_res["details"]["error"]

        # Must not be listed in contributing detectors
        assert "http" not in res["contributing_detectors"]


# ---------------------------------------------------------------------------
# 8. Aggregator Configuration Validation
# ---------------------------------------------------------------------------
def test_config_validation():
    """Verify configuration validation rejects invalid, negative, or non-monotonic parameters."""
    # Valid config passes
    valid_cfg = AggregatorConfig()
    assert valid_cfg.threat_threshold == 0.50

    # Negative weight
    with pytest.raises(ValueError, match="must be non-negative"):
        AggregatorConfig(weight_http=-0.1)

    # Non-finite weight
    with pytest.raises(ValueError, match="must be a finite number"):
        AggregatorConfig(channel_weight_web=float("nan"))

    # Zero web weights sum
    with pytest.raises(ValueError, match="Sum of web detector weights must be positive"):
        AggregatorConfig(weight_http=0, weight_session=0, weight_sequence=0, weight_autoencoder=0)

    # Inverted thresholds (low > high)
    with pytest.raises(ValueError, match="Thresholds must be monotonically non-decreasing"):
        AggregatorConfig(low_threshold=0.8, high_threshold=0.2)

    # Threshold out of bounds [0, 1]
    with pytest.raises(ValueError, match="must be in"):
        AggregatorConfig(threat_threshold=1.5)


# ---------------------------------------------------------------------------
# 9. Cross-Domain Corroboration Fusion
# ---------------------------------------------------------------------------
def test_cross_domain_corroboration():
    """Verify cross-domain boost is applied when both Web and Network independently detect attacks."""
    soc_df = pd.read_csv(SOC_TEST_PATH)
    web_attack = soc_df[(soc_df["source"] == "nginx") & (soc_df["label"] == "SQLI_ATTEMPT")].iloc[0].to_dict()
    net_df = pd.read_csv(NETWORK_TEST_PATH)
    net_attack = net_df.iloc[0].to_dict()

    fused_event = dict(web_attack)
    fused_event.update(net_attack)
    fused_event["source"] = "hybrid"

    # Mock network prediction with a known benign class present to provide a calibrated network threat score
    with patch("src.detection.aggregator.predict_network") as mock_net:
        mock_net.return_value = {
            "predicted_class": "WEB_SCAN",
            "confidence": 0.85,
            "class_probabilities": {"NORMAL": 0.10, "WEB_SCAN": 0.85, "TCP_SCAN": 0.05},
        }
        res = aggregate_event(fused_event)

        assert "http" in res["evaluated_detectors"]
        assert "network" in res["evaluated_detectors"]
        web_score = res["aggregation_metadata"]["web_channel_score"]
        net_score = res["aggregation_metadata"]["network_channel_score"]
        assert web_score >= 0.50
        assert net_score >= 0.50
        assert res["aggregation_metadata"]["cross_domain_boost_applied"] is True


# ---------------------------------------------------------------------------
# 10. Empty Input Safety
# ---------------------------------------------------------------------------
def test_empty_input_safety():
    """Verify empty dictionary or DataFrame returns safe default response without crashing."""
    result = aggregate_event({})
    assert result["overall_risk_score"] == 0.0
    assert result["risk_level"] == "UNKNOWN"
    assert result["is_threat"] is False
    assert result["primary_threat_type"] == "UNKNOWN"
    assert result["contributing_detectors"] == []
    assert result["evaluated_detectors"] == []
    assert len(result["unavailable_detectors"]) == 5


def main():
    print("============================================================")
    print("SENTINEL AI: HYBRID RISK AGGREGATOR TEST SUITE")
    print("============================================================")

    test_known_benign_http_event()
    print("  [PASS] 1. Known benign HTTP event")

    test_known_attack_http_event()
    print("  [PASS] 2. Known attack HTTP event")

    test_known_benign_network_event()
    print("  [PASS] 3. Known benign network event check")

    test_known_network_attack_event()
    print("  [PASS] 4. Known network attack event")

    test_genuine_multi_request_session()
    print("  [PASS] 5. Genuine multi-request session")

    test_unavailable_detectors_handling()
    print("  [PASS] 6. Unavailable detectors handling")

    test_unexpected_class_probability_schema()
    print("  [PASS] 7. Unexpected class-probability schema")

    test_config_validation()
    print("  [PASS] 8. Aggregator configuration validation")

    test_cross_domain_corroboration()
    print("  [PASS] 9. Cross-domain corroboration fusion")

    test_empty_input_safety()
    print("  [PASS] 10. Empty input safety")

    print("\nALL HYBRID RISK AGGREGATOR TESTS PASSED SUCCESSFULLY!")


if __name__ == "__main__":
    main()
