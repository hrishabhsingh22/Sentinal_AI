import os
import json
import builtins
import warnings
from pathlib import Path

# Suppress harmless Keras LSTM masking UserWarnings during inference
warnings.filterwarnings("ignore", category=UserWarning, module="keras")

# Ensure writable cache directories in constrained/sandboxed environments
if "KERAS_HOME" not in os.environ:
    os.environ["KERAS_HOME"] = "/tmp/.keras"
if "MPLCONFIGDIR" not in os.environ:
    os.environ["MPLCONFIGDIR"] = "/tmp/.matplotlib"

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow import keras

# Register symbols required for Keras Lambda layer deserialization
builtins.tf = tf
builtins.PADDING_VALUE = -999.0

from src.features import extract_features

# ---------------------------------------------------------------------------
# Project Root & Artifact Paths
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).resolve().parents[2]

# Autoencoder Artifact Paths
AUTOENCODER_MODEL_PATH = PROJECT_ROOT / "models" / "autoencoder.keras"
AUTOENCODER_SCALER_PATH = PROJECT_ROOT / "models" / "scaler.joblib"
AUTOENCODER_CONFIG_PATH = PROJECT_ROOT / "models" / "autoencoder_config.joblib"

# Sequence LSTM Artifact Paths
SEQUENCE_MODEL_PATH = PROJECT_ROOT / "models" / "sequence" / "sequence_lstm_v2.keras"
SEQUENCE_SCALER_PATH = PROJECT_ROOT / "models" / "sequence" / "sequence_scaler_v2.joblib"
SEQUENCE_METRICS_PATH = PROJECT_ROOT / "models" / "sequence" / "evaluation_metrics_v2.json"

# ---------------------------------------------------------------------------
# Feature Definitions & Constants
# ---------------------------------------------------------------------------
AUTOENCODER_FEATURES = [
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

SEQUENCE_FEATURES = [
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

MAX_SEQUENCE_LENGTH = 99
PADDING_VALUE = -999.0
SEQUENCE_DECISION_THRESHOLD = 0.5

# ---------------------------------------------------------------------------
# Model Caching
# ---------------------------------------------------------------------------
_AUTOENCODER_BUNDLE = None
_SEQUENCE_BUNDLE = None


def load_autoencoder_bundle(force_reload=False):
    """Load and cache the Autoencoder model, scaler, and config."""
    global _AUTOENCODER_BUNDLE
    if _AUTOENCODER_BUNDLE is not None and not force_reload:
        return _AUTOENCODER_BUNDLE

    for path in [AUTOENCODER_MODEL_PATH, AUTOENCODER_SCALER_PATH, AUTOENCODER_CONFIG_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Autoencoder artifact not found: {path}")

    model = keras.models.load_model(AUTOENCODER_MODEL_PATH)
    scaler = joblib.load(AUTOENCODER_SCALER_PATH)
    config = joblib.load(AUTOENCODER_CONFIG_PATH)

    if "feature_names" not in config or not isinstance(config["feature_names"], list):
        raise KeyError(
            f"Autoencoder configuration {AUTOENCODER_CONFIG_PATH} is missing 'feature_names' list."
        )
    feature_names = config["feature_names"]

    if "threshold" not in config:
        raise KeyError(
            f"Autoencoder configuration {AUTOENCODER_CONFIG_PATH} is missing 'threshold'."
        )

    try:
        threshold = float(config["threshold"])
    except (TypeError, ValueError) as err:
        raise ValueError(
            f"Non-numeric threshold in {AUTOENCODER_CONFIG_PATH}: {config.get('threshold')}"
        ) from err

    if not np.isfinite(threshold) or threshold < 0:
        raise ValueError(f"Invalid autoencoder anomaly threshold: {threshold}")

    _AUTOENCODER_BUNDLE = {
        "model": model,
        "scaler": scaler,
        "feature_names": feature_names,
        "threshold": threshold,
    }
    return _AUTOENCODER_BUNDLE


def load_sequence_bundle(force_reload=False):
    """Load and cache the Sequence LSTM model, scaler, and configuration."""
    global _SEQUENCE_BUNDLE
    if _SEQUENCE_BUNDLE is not None and not force_reload:
        return _SEQUENCE_BUNDLE

    for path in [SEQUENCE_MODEL_PATH, SEQUENCE_SCALER_PATH, SEQUENCE_METRICS_PATH]:
        if not path.exists():
            raise FileNotFoundError(f"Sequence LSTM artifact not found: {path}")

    # Load LSTM model with Lambda deserialization enabled
    model = keras.models.load_model(SEQUENCE_MODEL_PATH, safe_mode=False)
    scaler = joblib.load(SEQUENCE_SCALER_PATH)

    try:
        with open(SEQUENCE_METRICS_PATH, "r") as f:
            metrics_data = json.load(f)
    except json.JSONDecodeError as err:
        raise ValueError(
            f"Failed to parse sequence metrics file {SEQUENCE_METRICS_PATH}: {err}"
        ) from err

    test_metrics = metrics_data.get("test_metrics")
    val_metrics = metrics_data.get("validation_metrics")

    if isinstance(test_metrics, dict) and "threshold" in test_metrics:
        raw_threshold = test_metrics["threshold"]
    elif isinstance(val_metrics, dict) and "threshold" in val_metrics:
        raw_threshold = val_metrics["threshold"]
    else:
        raise KeyError(
            f"Sequence metrics file {SEQUENCE_METRICS_PATH} has unexpected structure: "
            "missing 'test_metrics.threshold' or 'validation_metrics.threshold'."
        )

    try:
        threshold = float(raw_threshold)
    except (TypeError, ValueError) as err:
        raise ValueError(
            f"Invalid non-numeric sequence threshold in {SEQUENCE_METRICS_PATH}: {raw_threshold}"
        ) from err

    if not np.isfinite(threshold) or not (0.0 <= threshold <= 1.0):
        raise ValueError(
            f"Sequence threshold in {SEQUENCE_METRICS_PATH} must be finite within [0, 1], got: {threshold}"
        )

    _SEQUENCE_BUNDLE = {
        "model": model,
        "scaler": scaler,
        "feature_names": SEQUENCE_FEATURES,
        "max_sequence_length": MAX_SEQUENCE_LENGTH,
        "padding_value": PADDING_VALUE,
        "threshold": threshold,
    }
    return _SEQUENCE_BUNDLE


# ---------------------------------------------------------------------------
# Prediction Functions
# ---------------------------------------------------------------------------
def predict_autoencoder(http_features):
    """Predict reconstruction anomaly for HTTP request features.

    Parameters
    ----------
    http_features : dict, pd.Series, or pd.DataFrame
        Either a dictionary representing a raw HTTP request (with keys 'path',
        'query', 'body', 'headers', 'method'), or numerical features matching
        AUTOENCODER_FEATURES.

    Returns
    -------
    dict
        {
            "reconstruction_error": float,
            "threshold": float,
            "is_anomaly": bool,
            "predicted_anomaly": int (0 or 1)
        }
    """
    if http_features is None:
        raise ValueError("http_features cannot be None.")

    bundle = load_autoencoder_bundle()
    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]
    threshold = bundle["threshold"]

    # Convert raw request dict if passed
    if isinstance(http_features, dict):
        if "path" in http_features and "query" in http_features and "body" in http_features:
            extracted = extract_features(http_features)
            df = pd.DataFrame([extracted])
        else:
            df = pd.DataFrame([http_features])
    elif isinstance(http_features, pd.Series):
        df = pd.DataFrame([http_features.to_dict()])
    elif isinstance(http_features, pd.DataFrame):
        if http_features.empty:
            raise ValueError("http_features DataFrame cannot be empty.")
        df = http_features.copy()
    else:
        raise TypeError(f"Unsupported http_features type: {type(http_features)}")

    # Check for missing required features
    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required Autoencoder features: {missing}")

    X = df[feature_names].apply(pd.to_numeric, errors="raise").to_numpy(dtype=np.float32)
    if not np.isfinite(X).all():
        raise ValueError("Autoencoder features contain NaN or infinite values.")

    X_scaled = scaler.transform(X)
    reconstruction = model.predict(X_scaled, verbose=0)
    errors = np.mean((X_scaled - reconstruction) ** 2, axis=1)

    error = float(errors[0])
    is_anomaly = bool(error > threshold)

    return {
        "reconstruction_error": error,
        "threshold": threshold,
        "is_anomaly": is_anomaly,
        "predicted_anomaly": int(is_anomaly),
    }


def predict_sequence(session_history):
    """Predict attack probability for the latest request in a session history.

    Parameters
    ----------
    session_history : pd.DataFrame, list[dict], pd.Series, or dict
        Chronological sequence of requests belonging to a session. Each record
        must contain the 11 SEQUENCE_FEATURES.

    Returns
    -------
    dict
        {
            "attack_probability": float,
            "is_attack": bool,
            "predicted_class": str ('ATTACK' or 'NORMAL'),
            "session_length": int
        }
    """
    if session_history is None:
        raise ValueError("session_history cannot be None.")

    bundle = load_sequence_bundle()
    model = bundle["model"]
    scaler = bundle["scaler"]
    feature_names = bundle["feature_names"]
    max_length = bundle["max_sequence_length"]
    padding_value = bundle["padding_value"]
    threshold = bundle["threshold"]

    # Convert to DataFrame
    if isinstance(session_history, pd.DataFrame):
        if session_history.empty:
            raise ValueError("session_history DataFrame cannot be empty.")
        df = session_history.copy()
    elif isinstance(session_history, list):
        if len(session_history) == 0:
            raise ValueError("session_history list cannot be empty.")
        df = pd.DataFrame(session_history)
    elif isinstance(session_history, (dict, pd.Series)):
        data = session_history.to_dict() if isinstance(session_history, pd.Series) else session_history
        if not data:
            raise ValueError("session_history record cannot be empty.")
        df = pd.DataFrame([data])
    else:
        raise TypeError(f"Unsupported session_history type: {type(session_history)}")

    # Sort chronologically if timestamps are provided
    sort_cols = [c for c in ["timestamp", "request_id"] if c in df.columns]
    if sort_cols:
        df = df.sort_values(sort_cols, kind="stable").reset_index(drop=True)

    # Validate feature presence
    missing = [f for f in feature_names if f not in df.columns]
    if missing:
        raise ValueError(f"Missing required sequence features: {missing}")

    X_raw = df[feature_names].apply(pd.to_numeric, errors="raise")
    if not np.isfinite(X_raw.to_numpy(dtype=float)).all():
        raise ValueError("Sequence features contain NaN or infinite values.")

    # Slice to latest max_length requests if sequence is longer than max_length
    if len(X_raw) > max_length:
        X_raw = X_raw.iloc[-max_length:]

    seq_len = len(X_raw)

    # Scale using exact sequence scaler
    scaled_seq = scaler.transform(X_raw).astype(np.float32)

    # Build post-padded 3D tensor: (1, max_sequence_length, feature_count)
    X_tensor = np.full((1, max_length, len(feature_names)), padding_value, dtype=np.float32)
    X_tensor[0, :seq_len, :] = scaled_seq

    # Predict sequence probabilities
    probabilities = model.predict(X_tensor, verbose=0).squeeze(-1)[0]

    # Evaluate the probability of the latest real request (not padded step)
    latest_attack_prob = float(probabilities[seq_len - 1])
    is_attack = bool(latest_attack_prob >= threshold)

    return {
        "attack_probability": latest_attack_prob,
        "is_attack": is_attack,
        "predicted_class": "ATTACK" if is_attack else "NORMAL",
        "session_length": seq_len,
    }
