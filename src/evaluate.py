
from pathlib import Path

import numpy as np
import pandas as pd

from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    roc_auc_score,
)

from src.scoring import load_detector, score_features


DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")


def evaluate_dataset(
    name,
    file_path,
    true_label,
    model,
    scaler,
    feature_names,
    threshold,
):
    if not file_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {file_path}"
        )

    df = pd.read_csv(file_path)

    if df.empty:
        raise ValueError(
            f"{name} dataset is empty."
        )

    scores = score_features(
        df,
        model,
        scaler,
        feature_names,
        threshold,
    )

    results = scores.copy()
    results["true_label"] = true_label
    results["dataset"] = name

    return results


def main():
    print("Loading trained anomaly detector...")

    model, scaler, feature_names, threshold = load_detector()

    print("Model loaded successfully.")
    print("Threshold:", threshold)

    normal_results = evaluate_dataset(
        "Normal",
        DATA_DIR / "test_features.csv",
        0,
        model,
        scaler,
        feature_names,
        threshold,
    )

    attack_results = evaluate_dataset(
        "Attack",
        DATA_DIR / "attack_features.csv",
        1,
        model,
        scaler,
        feature_names,
        threshold,
    )

    results = pd.concat(
        [normal_results, attack_results],
        ignore_index=True,
    )

    y_true = results["true_label"].to_numpy()
    y_pred = results["predicted_anomaly"].to_numpy()
    errors = results["reconstruction_error"].to_numpy()

    tn, fp, fn, tp = confusion_matrix(
        y_true,
        y_pred,
        labels=[0, 1],
    ).ravel()

    accuracy = accuracy_score(y_true, y_pred)

    precision = precision_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    recall = recall_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    f1 = f1_score(
        y_true,
        y_pred,
        zero_division=0,
    )

    false_positive_rate = (
        fp / (fp + tn) if (fp + tn) else 0.0
    )

    roc_auc = roc_auc_score(y_true, errors)

    normal_detection_rate = (
        tn / (tn + fp) if (tn + fp) else 0.0
    )

    attack_detection_rate = recall

    print("\n========== EVALUATION RESULTS ==========")

    print("\nDataset sizes:")
    print("Normal requests:", len(normal_results))
    print("Attack requests:", len(attack_results))
    print("Total requests:", len(results))

    print("\nConfusion Matrix:")
    print("True Negatives:", tn)
    print("False Positives:", fp)
    print("False Negatives:", fn)
    print("True Positives:", tp)

    print("\nPerformance Metrics:")
    print(f"Accuracy:              {accuracy:.4f}")
    print(f"Precision:             {precision:.4f}")
    print(f"Recall:                {recall:.4f}")
    print(f"F1-score:              {f1:.4f}")
    print(f"False Positive Rate:   {false_positive_rate:.4f}")
    print(f"ROC-AUC:               {roc_auc:.4f}")

    print("\nDetection Rates:")
    print(
        f"Normal traffic accepted: {normal_detection_rate:.4f}"
    )
    print(
        f"Attack traffic detected: {attack_detection_rate:.4f}"
    )

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    results.to_csv(
        REPORT_DIR / "evaluation_scores.csv",
        index=False,
    )

    metrics = pd.DataFrame([
        {"metric": "accuracy", "value": accuracy},
        {"metric": "precision", "value": precision},
        {"metric": "recall", "value": recall},
        {"metric": "f1_score", "value": f1},
        {"metric": "false_positive_rate", "value": false_positive_rate},
        {"metric": "roc_auc", "value": roc_auc},
        {"metric": "true_negatives", "value": int(tn)},
        {"metric": "false_positives", "value": int(fp)},
        {"metric": "false_negatives", "value": int(fn)},
        {"metric": "true_positives", "value": int(tp)},
    ])

    metrics.to_csv(
        REPORT_DIR / "evaluation_metrics.csv",
        index=False,
    )

    print("\nReports saved:")
    print("reports/evaluation_scores.csv")
    print("reports/evaluation_metrics.csv")


if __name__ == "__main__":
    main()
