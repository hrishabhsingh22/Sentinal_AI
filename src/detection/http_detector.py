
from pathlib import Path
import json
import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
)

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DATA_DIR = PROJECT_ROOT / "data" / "processed" / "soc_mld"
MODEL_DIR = PROJECT_ROOT / "models" / "http"

TRAIN_PATH = DATA_DIR / "train.csv"
TEST_PATH = DATA_DIR / "test.csv"
MODEL_PATH = MODEL_DIR / "http_classifier.joblib"
METRICS_PATH = MODEL_DIR / "evaluation_metrics.json"


# HTTP payload features
PAYLOAD_FEATURES = [
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

# HTTP time-window features
TIME_FEATURES = [
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

# HTTP session features
SESSION_FEATURES = [
    "f_session_req_count",
    "f_session_duration",
    "f_session_unique_paths",
    "f_session_error_count",
    "f_session_req_rate",
]

FEATURE_NAMES = (
    PAYLOAD_FEATURES
    + TIME_FEATURES
    + SESSION_FEATURES
)


def load_http_data(path):
    df = pd.read_csv(path)

    if "source" not in df.columns or "label" not in df.columns:
        raise ValueError("Dataset is missing source or label column.")

    df = df[df["source"] == "nginx"].copy()

    missing = [
        feature for feature in FEATURE_NAMES
        if feature not in df.columns
    ]

    if missing:
        raise ValueError(f"Missing HTTP features: {missing}")

    if df.empty:
        raise ValueError(f"No HTTP records found in {path}")

    X = df[FEATURE_NAMES].apply(
        pd.to_numeric, errors="raise"
    )

    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError("HTTP features contain NaN or infinite values.")

    y = df["label"].astype(str)

    return X, y


def train_detector():
    if not TRAIN_PATH.exists() or not TEST_PATH.exists():
        raise FileNotFoundError(
            "SOC-MLD train.csv or test.csv not found. "
            "Check data/processed/soc_mld/"
        )

    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    X_train, y_train = load_http_data(TRAIN_PATH)
    X_test, y_test = load_http_data(TEST_PATH)

    missing_test_classes = sorted(
        set(y_test.unique()) - set(y_train.unique())
    )

    if missing_test_classes:
        raise ValueError(
            "Test contains classes absent from training: "
            f"{missing_test_classes}"
        )

    print("\n--- HTTP DATA ---")
    print("Training requests:", len(X_train))
    print("Testing requests:", len(X_test))
    print("Features:", len(FEATURE_NAMES))
    print("Training classes:", y_train.nunique())
    print("Testing classes:", y_test.nunique())

    model = RandomForestClassifier(
        n_estimators=400,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )

    print("\nTraining HTTP classifier...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "macro_precision": float(
            precision_score(
                y_test, predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "macro_recall": float(
            recall_score(
                y_test, predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "macro_f1": float(
            f1_score(
                y_test, predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(
                y_test, predictions,
                average="weighted",
                zero_division=0,
            )
        ),
        "training_requests": len(X_train),
        "testing_requests": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "class_count": int(y_train.nunique()),
        "split": "verified attack-instance-disjoint split",
    }

    report = classification_report(
        y_test,
        predictions,
        output_dict=True,
        zero_division=0,
    )

    bundle = {
        "model": model,
        "feature_names": FEATURE_NAMES,
        "classes": model.classes_.tolist(),
        "model_type": "RandomForestClassifier",
        "dataset": "SOC-MLD",
    }

    joblib.dump(bundle, MODEL_PATH)

    with open(METRICS_PATH, "w") as file:
        json.dump(
            {
                "metrics": metrics,
                "classification_report": report,
            },
            file,
            indent=4,
        )

    print("\n--- HTTP DETECTION RESULTS ---")

    for name, value in metrics.items():
        print(f"{name}: {value}")

    print("\n--- PER-CLASS REPORT ---")
    print(
        classification_report(
            y_test,
            predictions,
            zero_division=0,
        )
    )

    print("\nModel saved:", MODEL_PATH)
    print("Metrics saved:", METRICS_PATH)


def predict_http(request_features):
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "HTTP model not found. Train the detector first."
        )

    bundle = joblib.load(MODEL_PATH)

    model = bundle["model"]
    feature_names = bundle["feature_names"]

    if isinstance(request_features, dict):
        request_features = pd.DataFrame(
            [request_features]
        )

    missing = [
        feature for feature in feature_names
        if feature not in request_features.columns
    ]

    if missing:
        raise ValueError(
            f"Missing inference features: {missing}"
        )

    X = request_features[feature_names].apply(
        pd.to_numeric, errors="raise"
    )

    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError(
            "Inference features contain NaN or infinite values."
        )

    predicted = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    class_probabilities = {
        str(label): float(probability)
        for label, probability in zip(
            model.classes_, probabilities
        )
    }

    return {
        "predicted_class": str(predicted),
        "confidence": float(max(probabilities)),
        "class_probabilities": class_probabilities,
    }


if __name__ == "__main__":
    train_detector()
