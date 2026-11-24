
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
MODEL_DIR = PROJECT_ROOT / "models" / "session"

TRAIN_PATH = DATA_DIR / "train.csv"
TEST_PATH = DATA_DIR / "test.csv"

MODEL_PATH = MODEL_DIR / "session_classifier.joblib"
METRICS_PATH = MODEL_DIR / "evaluation_metrics.json"


FEATURE_NAMES = [
    "f_session_req_count",
    "f_session_duration",
    "f_session_unique_paths",
    "f_session_error_count",
    "f_session_req_rate",
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


def load_session_data(path):
    df = pd.read_csv(path)

    required = [
        "session_id",
        "source",
        "label",
        *FEATURE_NAMES,
    ]

    missing = [
        col for col in required
        if col not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns: {missing}"
        )

    # Retain HTTP request observations only.
    df = df[df["source"] == "nginx"].copy()

    if df.empty:
        raise ValueError("No HTTP session records found.")

    X = df[FEATURE_NAMES].apply(
        pd.to_numeric,
        errors="raise",
    )

    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError(
            "Session features contain invalid values."
        )

    y = df["label"].astype(str)

    return X, y


def train_detector():
    if not TRAIN_PATH.exists() or not TEST_PATH.exists():
        raise FileNotFoundError(
            "SOC-MLD train/test files are missing."
        )

    MODEL_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    X_train, y_train = load_session_data(TRAIN_PATH)
    X_test, y_test = load_session_data(TEST_PATH)

    missing_classes = sorted(
        set(y_test.unique()) - set(y_train.unique())
    )

    if missing_classes:
        raise ValueError(
            f"Test classes absent from training: {missing_classes}"
        )

    model = RandomForestClassifier(
        n_estimators=400,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        n_jobs=-1,
        random_state=42,
    )

    print("\n--- SESSION DETECTOR ---")
    print("Training records:", len(X_train))
    print("Testing records:", len(X_test))
    print("Features:", len(FEATURE_NAMES))
    print("Training classes:", y_train.nunique())

    print("\nTraining session classifier...")

    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    metrics = {
        "accuracy": float(
            accuracy_score(y_test, predictions)
        ),
        "macro_precision": float(
            precision_score(
                y_test,
                predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "macro_recall": float(
            recall_score(
                y_test,
                predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "macro_f1": float(
            f1_score(
                y_test,
                predictions,
                average="macro",
                zero_division=0,
            )
        ),
        "weighted_f1": float(
            f1_score(
                y_test,
                predictions,
                average="weighted",
                zero_division=0,
            )
        ),
        "training_records": len(X_train),
        "testing_records": len(X_test),
        "feature_count": len(FEATURE_NAMES),
        "class_count": int(y_train.nunique()),
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

    print("\n--- SESSION DETECTION RESULTS ---")

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


def predict_session(session_features):
    if not MODEL_PATH.exists():
        raise FileNotFoundError(
            "Session model not found. Train it first."
        )

    bundle = joblib.load(MODEL_PATH)

    model = bundle["model"]
    feature_names = bundle["feature_names"]

    if isinstance(session_features, dict):
        session_features = pd.DataFrame(
            [session_features]
        )

    missing = [
        name for name in feature_names
        if name not in session_features.columns
    ]

    if missing:
        raise ValueError(
            f"Missing session features: {missing}"
        )

    X = session_features[feature_names].apply(
        pd.to_numeric,
        errors="raise",
    )

    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError(
            "Session features contain invalid values."
        )

    predictions = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    class_probabilities = {
        str(label): float(probability)
        for label, probability in zip(
            model.classes_,
            probabilities,
        )
    }

    return {
        "predicted_class": str(predictions),
        "confidence": float(max(probabilities)),
        "class_probabilities": class_probabilities,
    }


if __name__ == "__main__":
    train_detector()
