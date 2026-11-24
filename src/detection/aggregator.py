"""Hybrid Risk Aggregator for SENTINEL AI.

Integrates heterogeneous outputs from HTTP, Session, Sequence LSTM, Network,
and Autoencoder detection components into a unified threat assessment.

Features:
- Telemetry source and schema-aware routing (no incompatible feature passing).
- True missing-detector handling (omitted from denominator, never treated as zero).
- Explicit identification of benign labels (NORMAL, BENIGN, CLEAN, LEGITIMATE).
- Reliable network threat scoring requiring calibrated benign probability.
- Schema validation for class probabilities (no defaulting missing NORMAL to zero).
- Strict validation of chronological session history for Sequence LSTM.
- Finite, non-negative configuration validation.
- Consistent threat triage (contributing detectors, primary threat type, is_threat).
- Cross-detector correlation dampening (avoids double-counting co-occurring web signals).
- Cross-domain corroboration boost when application and transport layers independently flag threats.
- Configurable weighted-risk architecture.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Set, Union
import math
import numpy as np
import pandas as pd

from src.detection.http_detector import (
    predict_http,
    FEATURE_NAMES as HTTP_FEATURE_NAMES,
)
from src.detection.session_detector import (
    predict_session,
    FEATURE_NAMES as SESSION_FEATURE_NAMES,
)
from src.detection.network_detector import (
    predict_network,
    BASE_FEATURES as NETWORK_BASE_FEATURES,
    FEATURES as NETWORK_FEATURES,
)
from src.detection.sentinel_adapter import (
    predict_sequence,
    predict_autoencoder,
    AUTOENCODER_FEATURES,
    SEQUENCE_FEATURES,
)


# ---------------------------------------------------------------------------
# Benign Labels Specification
# ---------------------------------------------------------------------------
BENIGN_LABELS: frozenset = frozenset({
    "NORMAL",
    "BENIGN",
    "CLEAN",
    "LEGITIMATE",
})


def is_benign_label(label: Optional[str]) -> bool:
    """Check if label explicitly indicates benign / non-attack traffic.

    Never treats unknown or non-NORMAL labels as attacks without checking.
    """
    if label is None:
        return False
    return str(label).strip().upper() in BENIGN_LABELS


# ---------------------------------------------------------------------------
# Configuration & Data Structures
# ---------------------------------------------------------------------------
@dataclass
class AggregatorConfig:
    """Configurable weights, thresholds, and correlation parameters."""

    # Weights for detectors within Web/Application Channel (renormalized over available detectors)
    weight_http: float = 0.35
    weight_session: float = 0.20
    weight_sequence: float = 0.30
    weight_autoencoder: float = 0.15

    # Weights across operational channels
    channel_weight_web: float = 0.60
    channel_weight_net: float = 0.40

    # Correlation dampening factor within Web Channel:
    # 0.0 = pure peak score (most suspicious web signal dominates)
    # 1.0 = pure weighted average (independent detector assumption)
    web_correlation_dampening: float = 0.35

    # Cross-domain corroboration boost: added when both Web and Network channels independently flag threat >= 0.50
    cross_domain_boost: float = 0.05

    # Operational risk classification thresholds
    threat_threshold: float = 0.50
    critical_threshold: float = 0.80
    high_threshold: float = 0.60
    medium_threshold: float = 0.40
    low_threshold: float = 0.20

    def __post_init__(self):
        self.validate()

    def validate(self):
        """Validate aggregator configuration weights and thresholds.

        Rejects invalid, non-finite, negative, or inconsistently ordered values clearly.
        """
        weights = {
            "weight_http": self.weight_http,
            "weight_session": self.weight_session,
            "weight_sequence": self.weight_sequence,
            "weight_autoencoder": self.weight_autoencoder,
            "channel_weight_web": self.channel_weight_web,
            "channel_weight_net": self.channel_weight_net,
            "web_correlation_dampening": self.web_correlation_dampening,
            "cross_domain_boost": self.cross_domain_boost,
        }
        for name, val in weights.items():
            if not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(
                    f"Configuration parameter '{name}' must be a finite number, got {val}"
                )
            if val < 0.0:
                raise ValueError(
                    f"Configuration parameter '{name}' must be non-negative, got {val}"
                )

        web_sum = (
            self.weight_http
            + self.weight_session
            + self.weight_sequence
            + self.weight_autoencoder
        )
        if web_sum <= 0.0:
            raise ValueError(
                f"Sum of web detector weights must be positive, got {web_sum}"
            )

        channel_sum = self.channel_weight_web + self.channel_weight_net
        if channel_sum <= 0.0:
            raise ValueError(
                f"Sum of channel weights must be positive, got {channel_sum}"
            )

        if not (0.0 <= self.web_correlation_dampening <= 1.0):
            raise ValueError(
                f"web_correlation_dampening must be in [0.0, 1.0], got {self.web_correlation_dampening}"
            )
        if not (0.0 <= self.cross_domain_boost <= 1.0):
            raise ValueError(
                f"cross_domain_boost must be in [0.0, 1.0], got {self.cross_domain_boost}"
            )

        thresholds = {
            "threat_threshold": self.threat_threshold,
            "critical_threshold": self.critical_threshold,
            "high_threshold": self.high_threshold,
            "medium_threshold": self.medium_threshold,
            "low_threshold": self.low_threshold,
        }
        for name, val in thresholds.items():
            if not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(
                    f"Threshold '{name}' must be a finite number, got {val}"
                )
            if not (0.0 <= val <= 1.0):
                raise ValueError(
                    f"Threshold '{name}' must be in [0.0, 1.0], got {val}"
                )

        if not (
            self.low_threshold
            <= self.medium_threshold
            <= self.high_threshold
            <= self.critical_threshold
        ):
            raise ValueError(
                f"Thresholds must be monotonically non-decreasing: "
                f"low ({self.low_threshold}) <= medium ({self.medium_threshold}) <= "
                f"high ({self.high_threshold}) <= critical ({self.critical_threshold})"
            )


@dataclass
class DetectorResult:
    """Standardized result structure for an individual detector evaluation."""

    detector_name: str
    available: bool
    threat_score: Optional[float] = None
    threat_type: str = "UNAVAILABLE"
    prediction: Optional[str] = None
    confidence: Optional[float] = None
    details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AggregatedRisk:
    """Unified threat evaluation output across all contributing detectors."""

    overall_risk_score: float
    risk_level: str
    is_threat: bool
    primary_threat_type: str
    contributing_detectors: List[str]
    evaluated_detectors: List[str]
    unavailable_detectors: List[str]
    detector_results: Dict[str, Dict[str, Any]]
    aggregation_metadata: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helper Extraction & Routing Functions
# ---------------------------------------------------------------------------
def _to_record_dict(event: Any) -> Dict[str, Any]:
    """Convert input event to a standard Python dictionary."""
    if isinstance(event, pd.Series):
        return event.to_dict()
    elif isinstance(event, pd.DataFrame):
        if event.empty:
            return {}
        return event.iloc[0].to_dict()
    elif isinstance(event, dict):
        return dict(event)
    raise TypeError(f"Unsupported event type: {type(event)}")


def _can_run_http(event: Dict[str, Any]) -> bool:
    """Verify if event belongs to HTTP web domain and has required features."""
    if event.get("source") == "suricata":
        return False
    return all(feature in event for feature in HTTP_FEATURE_NAMES)


def _can_run_session(event: Dict[str, Any]) -> bool:
    """Verify if event has valid session-level metrics and belongs to web domain."""
    if event.get("source") == "suricata":
        return False
    return all(feature in event for feature in SESSION_FEATURE_NAMES)


def _can_run_network(event: Dict[str, Any]) -> bool:
    """Verify if event has network flow/Suricata features."""
    if event.get("source") == "nginx":
        return False
    has_base = all(feature in event for feature in NETWORK_BASE_FEATURES)
    has_full = all(feature in event for feature in NETWORK_FEATURES)
    return has_base or has_full


def _validate_session_history(session_history: Any) -> bool:
    """Validate genuine chronological session history against all 11 sequence features.

    Returns True only when non-empty history is provided and every record
    strictly contains all 11 sequence features with finite numeric values.
    """
    if session_history is None:
        return False

    if isinstance(session_history, pd.DataFrame):
        if session_history.empty or len(session_history) < 1:
            return False
        if not all(col in session_history.columns for col in SEQUENCE_FEATURES):
            return False
        sub = session_history[SEQUENCE_FEATURES].apply(pd.to_numeric, errors="coerce")
        if sub.isna().any().any():
            return False
        if not np.isfinite(sub.to_numpy(dtype=float)).all():
            return False
        return True

    elif isinstance(session_history, list):
        if len(session_history) < 1:
            return False
        for record in session_history:
            if not isinstance(record, (dict, pd.Series)):
                return False
            for feat in SEQUENCE_FEATURES:
                if feat not in record:
                    return False
                val = record[feat]
                try:
                    num_val = float(val)
                    if not math.isfinite(num_val):
                        return False
                except (TypeError, ValueError):
                    return False
        return True

    return False


def _can_run_autoencoder(event: Dict[str, Any]) -> bool:
    """Verify if raw HTTP payload or pre-extracted Autoencoder features exist."""
    has_raw = "path" in event and "query" in event and "body" in event
    has_features = all(feature in event for feature in AUTOENCODER_FEATURES)
    return has_raw or has_features


# ---------------------------------------------------------------------------
# Probability Calibration & Normalization Helpers
# ---------------------------------------------------------------------------
def _calibrate_autoencoder_score(error: float, threshold: float) -> float:
    """Calibrate continuous MSE into a smooth normalized threat score in [0, 1].

    - error <= threshold: maps smoothly from 0.0 to 0.5 (normal region)
    - error > threshold: maps smoothly from 0.5 to 1.0 (anomalous region)
    """
    if threshold <= 0:
        return 1.0 if error > 0 else 0.0
    if error <= threshold:
        return float(np.clip(0.5 * (error / threshold), 0.0, 0.5))
    else:
        # Asymptotic exponential approach toward 1.0
        delta = error - threshold
        scaled = 0.5 + 0.5 * (1.0 - math.exp(-delta / (2.0 * threshold)))
        return float(np.clip(scaled, 0.5, 1.0))


def _score_to_risk_level(score: float, config: AggregatorConfig, has_eval: bool) -> str:
    """Map numeric risk score to categorical severity level."""
    if not has_eval:
        return "UNKNOWN"
    if score >= config.critical_threshold:
        return "CRITICAL"
    elif score >= config.high_threshold:
        return "HIGH"
    elif score >= config.medium_threshold:
        return "MEDIUM"
    elif score >= config.low_threshold:
        return "LOW"
    else:
        return "INFORMATIONAL"


# ---------------------------------------------------------------------------
# Main Hybrid Aggregator
# ---------------------------------------------------------------------------
class HybridRiskAggregator:
    """Orchestrates multi-domain detectors and performs correlation-aware aggregation."""

    def __init__(self, config: Optional[AggregatorConfig] = None):
        self.config = config or AggregatorConfig()

    def evaluate_event(
        self,
        event: Any,
        session_history: Optional[Any] = None,
    ) -> AggregatedRisk:
        """Evaluate a single telemetry event or unified incident record.

        Parameters
        ----------
        event : dict, pd.Series, or pd.DataFrame (1 row)
            Telemetry observation (Nginx web, Suricata network, or raw HTTP).
        session_history : pd.DataFrame, list[dict], optional
            Chronological session requests for sequence LSTM evaluation.
            Sequence detector runs ONLY when valid history is supplied.

        Returns
        -------
        AggregatedRisk
            Standardized evaluation including overall risk, risk level, contributing
            detectors, and normalized per-detector outputs.
        """
        record = _to_record_dict(event)
        if not record:
            return AggregatedRisk(
                overall_risk_score=0.0,
                risk_level="UNKNOWN",
                is_threat=False,
                primary_threat_type="UNKNOWN",
                contributing_detectors=[],
                evaluated_detectors=[],
                unavailable_detectors=[
                    "http", "session", "sequence", "network", "autoencoder"
                ],
                detector_results={},
                aggregation_metadata={"error": "Empty input event"},
            )

        results: Dict[str, DetectorResult] = {}

        # ------------------------------------------------------------------
        # 1. HTTP Classifier Evaluation
        # ------------------------------------------------------------------
        if _can_run_http(record):
            try:
                raw_http = predict_http(record)
                pred_class = raw_http["predicted_class"]
                conf = float(raw_http["confidence"])
                class_probs = raw_http.get("class_probabilities", {})

                # Validate expected benign class exists in class_probabilities
                benign_keys = [k for k in class_probs if is_benign_label(k)]
                if not benign_keys:
                    # Do not default missing NORMAL probability to zero
                    results["http"] = DetectorResult(
                        detector_name="http",
                        available=False,
                        threat_score=None,
                        threat_type="UNAVAILABLE",
                        prediction=pred_class,
                        confidence=conf,
                        details={
                            "error": "Expected benign class (NORMAL/BENIGN) missing from class_probabilities",
                            "raw_output": raw_http,
                        },
                    )
                else:
                    p_benign = float(sum(class_probs[k] for k in benign_keys))
                    if is_benign_label(pred_class):
                        threat_score = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_type = "NORMAL"
                    else:
                        p_attack = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_score = float(np.clip(max(conf, p_attack), 0.0, 1.0))
                        threat_type = pred_class

                    results["http"] = DetectorResult(
                        detector_name="http",
                        available=True,
                        threat_score=threat_score,
                        threat_type=threat_type,
                        prediction=pred_class,
                        confidence=conf,
                        details=raw_http,
                    )
            except Exception as exc:
                results["http"] = DetectorResult(
                    detector_name="http",
                    available=False,
                    threat_score=None,
                    threat_type="UNAVAILABLE",
                    details={"error": str(exc)},
                )
        else:
            results["http"] = DetectorResult(
                detector_name="http", available=False, threat_score=None, threat_type="UNAVAILABLE"
            )

        # ------------------------------------------------------------------
        # 2. Session Classifier Evaluation
        # ------------------------------------------------------------------
        if _can_run_session(record):
            try:
                raw_session = predict_session(record)
                pred_class = raw_session["predicted_class"]
                conf = float(raw_session["confidence"])
                class_probs = raw_session.get("class_probabilities", {})

                # Validate expected benign class exists in class_probabilities
                benign_keys = [k for k in class_probs if is_benign_label(k)]
                if not benign_keys:
                    # Do not default missing NORMAL probability to zero
                    results["session"] = DetectorResult(
                        detector_name="session",
                        available=False,
                        threat_score=None,
                        threat_type="UNAVAILABLE",
                        prediction=pred_class,
                        confidence=conf,
                        details={
                            "error": "Expected benign class (NORMAL/BENIGN) missing from class_probabilities",
                            "raw_output": raw_session,
                        },
                    )
                else:
                    p_benign = float(sum(class_probs[k] for k in benign_keys))
                    if is_benign_label(pred_class):
                        threat_score = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_type = "NORMAL"
                    else:
                        p_attack = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_score = float(np.clip(max(conf, p_attack), 0.0, 1.0))
                        threat_type = pred_class

                    results["session"] = DetectorResult(
                        detector_name="session",
                        available=True,
                        threat_score=threat_score,
                        threat_type=threat_type,
                        prediction=pred_class,
                        confidence=conf,
                        details=raw_session,
                    )
            except Exception as exc:
                results["session"] = DetectorResult(
                    detector_name="session",
                    available=False,
                    threat_score=None,
                    threat_type="UNAVAILABLE",
                    details={"error": str(exc)},
                )
        else:
            results["session"] = DetectorResult(
                detector_name="session", available=False, threat_score=None, threat_type="UNAVAILABLE"
            )

        # ------------------------------------------------------------------
        # 3. Sequence LSTM Evaluation
        # ------------------------------------------------------------------
        # Run the sequence detector ONLY when genuine chronological session history is supplied
        if _validate_session_history(session_history):
            try:
                raw_seq = predict_sequence(session_history)
                prob = float(raw_seq["attack_probability"])
                is_attack = bool(raw_seq["is_attack"])
                pred_class = raw_seq["predicted_class"]

                results["sequence"] = DetectorResult(
                    detector_name="sequence",
                    available=True,
                    threat_score=float(np.clip(prob, 0.0, 1.0)),
                    threat_type="SEQUENTIAL_ATTACK" if is_attack else "NORMAL",
                    prediction=pred_class,
                    confidence=prob if is_attack else (1.0 - prob),
                    details=raw_seq,
                )
            except Exception as exc:
                results["sequence"] = DetectorResult(
                    detector_name="sequence",
                    available=False,
                    threat_score=None,
                    threat_type="UNAVAILABLE",
                    details={"error": str(exc)},
                )
        else:
            results["sequence"] = DetectorResult(
                detector_name="sequence",
                available=False,
                threat_score=None,
                threat_type="UNAVAILABLE",
                details={"reason": "Valid chronological session history not supplied"}
                if session_history is not None
                else {},
            )

        # ------------------------------------------------------------------
        # 4. Network Classifier Evaluation
        # ------------------------------------------------------------------
        if _can_run_network(record):
            try:
                raw_net = predict_network(record)
                pred_class = raw_net["predicted_class"]
                conf = float(raw_net["confidence"])
                class_probs = raw_net.get("class_probabilities", {})

                # Calculate network threat score using predicted class and class probabilities.
                # Do NOT use predicted-class confidence directly as threat probability.
                # If benign probability cannot be established reliably, mark threat scoring unavailable.
                benign_keys = [k for k in class_probs if is_benign_label(k)]
                if not benign_keys:
                    results["network"] = DetectorResult(
                        detector_name="network",
                        available=False,
                        threat_score=None,
                        threat_type="UNAVAILABLE",
                        prediction=pred_class,
                        confidence=conf,
                        details={
                            "reason": (
                                "Benign probability cannot be established reliably from class_probabilities "
                                "(no benign class found in network model classes)"
                            ),
                            "predicted_class": pred_class,
                            "confidence": conf,
                            "class_probabilities": class_probs,
                        },
                    )
                else:
                    p_benign = float(sum(class_probs[k] for k in benign_keys))
                    if is_benign_label(pred_class):
                        threat_score = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_type = "NORMAL"
                    else:
                        p_attack = float(np.clip(1.0 - p_benign, 0.0, 1.0))
                        threat_score = float(np.clip(max(conf, p_attack), 0.0, 1.0))
                        threat_type = pred_class

                    results["network"] = DetectorResult(
                        detector_name="network",
                        available=True,
                        threat_score=threat_score,
                        threat_type=threat_type,
                        prediction=pred_class,
                        confidence=conf,
                        details=raw_net,
                    )
            except Exception as exc:
                results["network"] = DetectorResult(
                    detector_name="network",
                    available=False,
                    threat_score=None,
                    threat_type="UNAVAILABLE",
                    details={"error": str(exc)},
                )
        else:
            results["network"] = DetectorResult(
                detector_name="network", available=False, threat_score=None, threat_type="UNAVAILABLE"
            )

        # ------------------------------------------------------------------
        # 5. Autoencoder Evaluation
        # ------------------------------------------------------------------
        if _can_run_autoencoder(record):
            try:
                raw_ae = predict_autoencoder(record)
                err = float(raw_ae["reconstruction_error"])
                thresh = float(raw_ae["threshold"])
                is_anomaly = bool(raw_ae["is_anomaly"])

                if not math.isfinite(err) or not math.isfinite(thresh):
                    results["autoencoder"] = DetectorResult(
                        detector_name="autoencoder",
                        available=False,
                        threat_score=None,
                        threat_type="UNAVAILABLE",
                        details={"error": "Non-finite reconstruction error or threshold"},
                    )
                else:
                    calibrated_score = _calibrate_autoencoder_score(err, thresh)

                    results["autoencoder"] = DetectorResult(
                        detector_name="autoencoder",
                        available=True,
                        threat_score=calibrated_score,
                        threat_type="PAYLOAD_ANOMALY" if is_anomaly else "NORMAL",
                        prediction="ANOMALOUS" if is_anomaly else "NORMAL",
                        confidence=calibrated_score if is_anomaly else (1.0 - calibrated_score),
                        details=raw_ae,
                    )
            except Exception as exc:
                results["autoencoder"] = DetectorResult(
                    detector_name="autoencoder",
                    available=False,
                    threat_score=None,
                    threat_type="UNAVAILABLE",
                    details={"error": str(exc)},
                )
        else:
            results["autoencoder"] = DetectorResult(
                detector_name="autoencoder", available=False, threat_score=None, threat_type="UNAVAILABLE"
            )

        # ------------------------------------------------------------------
        # Risk Aggregation Across Operational Channels
        # ------------------------------------------------------------------
        # Evaluated detectors are those that are available AND produced a valid threat score
        evaluated_detectors = [
            k for k, r in results.items() if r.available and r.threat_score is not None
        ]
        unavailable_detectors = [
            k for k in ["http", "session", "sequence", "network", "autoencoder"]
            if k not in evaluated_detectors
        ]

        if not evaluated_detectors:
            return AggregatedRisk(
                overall_risk_score=0.0,
                risk_level="UNKNOWN",
                is_threat=False,
                primary_threat_type="UNKNOWN",
                contributing_detectors=[],
                evaluated_detectors=[],
                unavailable_detectors=unavailable_detectors,
                detector_results={k: r.to_dict() for k, r in results.items()},
                aggregation_metadata={"evaluated_channels": []},
            )

        # A. Web / Application Layer Channel Aggregation (Correlation-Dampened)
        web_channel_detectors = ["http", "session", "sequence", "autoencoder"]
        active_web = [d for d in web_channel_detectors if d in evaluated_detectors]

        web_weights = {
            "http": self.config.weight_http,
            "session": self.config.weight_session,
            "sequence": self.config.weight_sequence,
            "autoencoder": self.config.weight_autoencoder,
        }

        web_channel_score: Optional[float] = None
        if active_web:
            total_web_weight = sum(web_weights[d] for d in active_web)
            scores = [results[d].threat_score for d in active_web if results[d].threat_score is not None]

            if scores and total_web_weight > 0:
                peak_score = float(max(scores))
                weighted_mean = float(
                    sum(
                        web_weights[d] * results[d].threat_score
                        for d in active_web
                        if results[d].threat_score is not None
                    )
                    / total_web_weight
                )
                # Dampen collinear signals: peak is primary; corroborating signals confirm without additive ballooning
                gamma = self.config.web_correlation_dampening
                web_channel_score = float(
                    np.clip((1.0 - gamma) * peak_score + gamma * weighted_mean, 0.0, 1.0)
                )

        # B. Network / Transport Layer Channel Aggregation
        net_channel_score: Optional[float] = None
        if "network" in evaluated_detectors and results["network"].threat_score is not None:
            net_channel_score = results["network"].threat_score

        # C. Cross-Domain Fusion
        channel_weights: Dict[str, float] = {}
        channel_scores: Dict[str, float] = {}

        if web_channel_score is not None:
            channel_weights["web"] = self.config.channel_weight_web
            channel_scores["web"] = web_channel_score
        if net_channel_score is not None:
            channel_weights["network"] = self.config.channel_weight_net
            channel_scores["network"] = net_channel_score

        total_channel_weight = sum(channel_weights.values())
        if total_channel_weight > 0:
            overall_score = (
                sum(channel_weights[c] * channel_scores[c] for c in channel_weights)
                / total_channel_weight
            )
        else:
            overall_score = 0.0

        # Cross-domain confirmation boost: when both Application and Network layers independently detect an attack
        cross_domain_boost_applied = False
        if web_channel_score is not None and net_channel_score is not None:
            if (
                web_channel_score >= self.config.threat_threshold
                and net_channel_score >= self.config.threat_threshold
            ):
                overall_score = float(
                    np.clip(overall_score + self.config.cross_domain_boost, 0.0, 1.0)
                )
                cross_domain_boost_applied = True

        overall_score = float(np.clip(overall_score, 0.0, 1.0))
        overall_score = round(overall_score, 4)

        # ------------------------------------------------------------------
        # Threat Triage & Contributing Detectors
        # ------------------------------------------------------------------
        # Contributing detectors must be:
        # 1. Evaluated and available with valid threat score
        # 2. Meet or exceed operational threat threshold
        # 3. Predict an attack (threat_type must NOT be benign or placeholder)
        contributing_detectors: List[str] = []
        for name in evaluated_detectors:
            res = results[name]
            if res.threat_score is not None and res.threat_score >= self.config.threat_threshold:
                if (
                    not is_benign_label(res.threat_type)
                    and res.threat_type not in ("NONE", "UNAVAILABLE", "UNKNOWN")
                ):
                    contributing_detectors.append(name)

        # Primary threat type selection (highest threat score among contributing attack detectors)
        if contributing_detectors:
            highest_score = -1.0
            primary_threat = "UNKNOWN"
            for name in contributing_detectors:
                res = results[name]
                score = res.threat_score or 0.0
                if score > highest_score:
                    highest_score = score
                    primary_threat = res.threat_type
        elif evaluated_detectors:
            # Evaluated detectors were all benign
            primary_threat = "NORMAL"
        else:
            primary_threat = "UNKNOWN"

        is_threat = overall_score >= self.config.threat_threshold or len(contributing_detectors) > 0
        risk_level = _score_to_risk_level(overall_score, self.config, has_eval=bool(evaluated_detectors))

        metadata = {
            "evaluated_channels": list(channel_scores.keys()),
            "web_channel_score": round(web_channel_score, 4) if web_channel_score is not None else None,
            "network_channel_score": round(net_channel_score, 4) if net_channel_score is not None else None,
            "cross_domain_boost_applied": cross_domain_boost_applied,
            "channel_weights_applied": channel_weights,
            "web_detectors_evaluated": active_web,
        }

        return AggregatedRisk(
            overall_risk_score=overall_score,
            risk_level=risk_level,
            is_threat=is_threat,
            primary_threat_type=primary_threat,
            contributing_detectors=contributing_detectors,
            evaluated_detectors=evaluated_detectors,
            unavailable_detectors=unavailable_detectors,
            detector_results={k: r.to_dict() for k, r in results.items()},
            aggregation_metadata=metadata,
        )


# ---------------------------------------------------------------------------
# Convenience Module API
# ---------------------------------------------------------------------------
_DEFAULT_AGGREGATOR: Optional[HybridRiskAggregator] = None


def get_default_aggregator() -> HybridRiskAggregator:
    """Retrieve or create the singleton default hybrid aggregator."""
    global _DEFAULT_AGGREGATOR
    if _DEFAULT_AGGREGATOR is None:
        _DEFAULT_AGGREGATOR = HybridRiskAggregator()
    return _DEFAULT_AGGREGATOR


def aggregate_event(
    event: Any,
    session_history: Optional[Any] = None,
    config: Optional[AggregatorConfig] = None,
) -> Dict[str, Any]:
    """Evaluate and aggregate a single telemetry event.

    Parameters
    ----------
    event : dict, pd.Series, or pd.DataFrame
        Telemetry record.
    session_history : pd.DataFrame, list[dict], optional
        Session context for sequence evaluation.
    config : AggregatorConfig, optional
        Custom aggregation weights and parameters.

    Returns
    -------
    dict
        Aggregated threat assessment dictionary.
    """
    aggregator = HybridRiskAggregator(config) if config is not None else get_default_aggregator()
    result = aggregator.evaluate_event(event, session_history=session_history)
    return result.to_dict()
