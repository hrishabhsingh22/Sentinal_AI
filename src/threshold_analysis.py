
from pandas._config import config
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from sklearn.metrics import (
    precision_score,
    recall_score,
    f1_score,
)

MODEL_DIR = Path("models")
DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")


def load_validation_errors():
    model_config_path = MODEL_DIR / "autoencoder_config.joblib"

    if not model_config_path.exists():
        raise FileNotFoundError(
            "Autoencoder configuration not found."
        )

    config = joblib.load(model_config_path)
    validation_path = REPORT_DIR / "calibration_errors.csv"

    if not validation_path.exists():
        raise FileNotFoundError(
            "Validation errors not found. "
            "We need to generate them using a separate "
            "normal calibration dataset."
        )

    df = pd.read_csv(validation_path)

    if "reconstruction_error" not in df.columns:
        raise ValueError(
            "Validation file must contain reconstruction_error."
        )

    errors = df["reconstruction_error"].to_numpy(dtype=float)

    if len(errors) == 0 or not np.isfinite(errors).all():
        raise ValueError("Invalid validation reconstruction errors.")

    return errors, float(config["threshold"])


def analyze_thresholds(errors, current_threshold):
    thresholds = np.unique(
        np.quantile(errors, np.linspace(0.90, 0.999, 30))
    )

    rows = []

    for threshold in thresholds:
        predictions = (errors > threshold).astype(int)

        false_positive_rate = float(predictions.mean())

        rows.append({
            "threshold": float(threshold),
            "precision": np.nan,
            "recall": np.nan,
            "f1_score": np.nan,
            "false_positive_rate": false_positive_rate,
            "normal_acceptance_rate": 1 - false_positive_rate,
        })

    results = pd.DataFrame(rows)

    print("\n========== THRESHOLD ANALYSIS ==========")
    print("Calibration requests:", len(errors))
    print("Current threshold:", current_threshold)
    print("\nCandidate thresholds:")
    print(results.to_string(index=False))

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    output_path = REPORT_DIR / "threshold_analysis.csv"
    results.to_csv(output_path, index=False)

    print("\nThreshold analysis saved:", output_path)
    print(
        "\nNote: Recall, precision and F1 cannot be "
        "measured using normal-only calibration data."
    )

def select_threshold(errors, max_false_positive_rate=0.02):
    sorted_errors = np.sort(errors)

    candidates = np.unique(sorted_errors)

    valid_thresholds = []

    for threshold in candidates:
        false_positive_rate = float(
            np.mean(errors > threshold)
        )

        if false_positive_rate <= max_false_positive_rate:
            valid_thresholds.append(
                (threshold, false_positive_rate)
            )

    if not valid_thresholds:
        raise ValueError(
            "No threshold satisfies the false-positive target."
        )

    selected_threshold, selected_fpr = min(
        valid_thresholds,
        key=lambda item: item[0],
    )

    return float(selected_threshold), selected_fpr


def main():
    errors, current_threshold = load_validation_errors()
    analyze_thresholds(errors, current_threshold)
    selected_threshold, selected_fpr = select_threshold(errors)

    print("\n========== SELECTED THRESHOLD ==========")
    print("Target false-positive rate: 2%")
    print("Selected threshold:", selected_threshold)
    print("Calibration false-positive rate:", selected_fpr)
    config = joblib.load(MODEL_DIR / "autoencoder_config.joblib")

    config["threshold"] = selected_threshold

    joblib.dump(
    config,
    MODEL_DIR / "autoencoder_config.joblib"
    )

    print("Updated model configuration with selected threshold.")

if __name__ == "__main__":
    main()
