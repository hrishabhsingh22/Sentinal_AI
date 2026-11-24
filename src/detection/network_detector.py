
import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from sklearn.ensemble import RandomForestClassifier, ExtraTreesClassifier
from sklearn.model_selection import GroupKFold
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)

ROOT = Path(__file__).resolve().parents[2]

TRAIN_PATH = ROOT / "data/processed/soc_mld/network_train.csv"
TEST_PATH = ROOT / "data/processed/soc_mld/network_test.csv"

MODEL_DIR = ROOT / "models/network"
MODEL_DIR.mkdir(parents=True, exist_ok=True)

MODEL_PATH = MODEL_DIR / "network_classifier.joblib"
FEATURES_PATH = MODEL_DIR / "network_features.joblib"
METRICS_PATH = MODEL_DIR / "evaluation_metrics.json"

# ---------------------------------------------------------------------------
# Feature set v2
#
# Changes from v1 (15 features):
#   Removed (redundant, correlation ≥ 0.999):
#     f_tcp_ack     (= f_tcp_syn, r=1.0)
#     f_flow_bytes_out_60s (= f_flow_pkts_in_60s, r=1.0)
#     f_flow_pkts_in_60s   (= f_flow_pkts_out_60s, r=0.999)
#
#   Added from CSV:
#     dst_port              – strongest class separator (ICMP=0, TCP_SCAN=1/22,
#                             WEB_SCAN=80/443, SYN_SCAN=many ports)
#     f_session_duration    – session-level temporal feature
#     f_session_req_rate    – request rate per session
#
#   Engineered:
#     f_bytes_per_pkt       – flow-level size signature
#     f_rst_minus_fin       – reset-vs-close pattern
#     f_port_is_web         – binary: port in {80, 443, 8080, 8443}
#     f_high_sev_ratio      – proportion of high-severity Suricata alerts
#     f_log_session_req_count    – log(1 + session_req_count), robust to shift
#     f_log_session_unique_paths – log(1 + session_unique_paths)
#     f_log_bytes_total          – log(1 + flow_bytes_total)
#     f_session_err_ratio        – session_error_count / session_req_count
#
# Note: Raw f_session_req_count / f_session_unique_paths / f_session_error_count
# are intentionally excluded — their extreme skew (3 training instances with
# counts > 1000 for WEB_BRUTEFORCE) causes distribution-shift misclassification.
# Log-transformed and ratio versions are used instead.
# ---------------------------------------------------------------------------

# Base columns read directly from CSV
BASE_FEATURES = [
    "dst_port",
    "f_suricata_alerts_60s",
    "f_suricata_high_sev_60s",
    "f_suricata_unique_sigs",
    "f_flow_pkts_out_60s",
    "f_flow_syn_ratio",
    "f_flow_count_60s",
    "f_flow_duration",
    "f_flow_pkts_total",
    "f_flow_bytes_total",
    "f_tcp_syn",
    "f_tcp_fin",
    "f_tcp_rst",
    "f_session_duration",
    "f_session_req_rate",
]

# Engineered features added during prepare_features()
ENGINEERED = [
    "f_bytes_per_pkt",
    "f_rst_minus_fin",
    "f_port_is_web",
    "f_high_sev_ratio",
    "f_log_session_req_count",
    "f_log_session_unique_paths",
    "f_log_bytes_total",
    "f_session_err_ratio",
]

# Columns needed from CSV to compute engineered features
_ENG_SOURCE_COLS = [
    "f_session_req_count",
    "f_session_unique_paths",
    "f_session_error_count",
]

FEATURES = BASE_FEATURES + ENGINEERED
FEATURE_NAMES = FEATURES


def prepare_features(df: pd.DataFrame) -> pd.DataFrame:
    """Add engineered features to a dataframe (in-place safe copy)."""
    df = df.copy()
    df["f_bytes_per_pkt"] = np.where(
        df["f_flow_pkts_total"] > 0,
        df["f_flow_bytes_total"] / df["f_flow_pkts_total"],
        0.0,
    )
    df["f_rst_minus_fin"] = df["f_tcp_rst"] - df["f_tcp_fin"]
    df["f_port_is_web"] = df["dst_port"].isin([80, 443, 8080, 8443]).astype(int)
    df["f_high_sev_ratio"] = np.where(
        df["f_suricata_alerts_60s"] > 0,
        df["f_suricata_high_sev_60s"] / df["f_suricata_alerts_60s"],
        0.0,
    )
    df["f_log_session_req_count"] = np.log1p(
        df.get("f_session_req_count", pd.Series(0, index=df.index))
    )
    df["f_log_session_unique_paths"] = np.log1p(
        df.get("f_session_unique_paths", pd.Series(0, index=df.index))
    )
    df["f_log_bytes_total"] = np.log1p(df["f_flow_bytes_total"])
    req_count = df.get("f_session_req_count", pd.Series(0, index=df.index))
    err_count = df.get("f_session_error_count", pd.Series(0, index=df.index))
    df["f_session_err_ratio"] = np.where(
        req_count > 0, err_count / req_count, 0.0
    )
    return df


def load_data():
    if not TRAIN_PATH.exists() or not TEST_PATH.exists():
        raise FileNotFoundError(
            f"Network train or test CSV not found: {TRAIN_PATH}, {TEST_PATH}"
        )
    train = pd.read_csv(TRAIN_PATH)
    test = pd.read_csv(TEST_PATH)

    required = BASE_FEATURES + _ENG_SOURCE_COLS + ["label"]
    train = train.dropna(subset=required)
    test = test.dropna(subset=required)

    train = prepare_features(train)
    test = prepare_features(test)

    return train, test


def _evaluate(y_true, y_pred, labels):
    """Return a metrics dict and a printable classification report."""
    report_str = classification_report(y_true, y_pred, zero_division=0)
    report_dict = classification_report(
        y_true, y_pred, zero_division=0, output_dict=True
    )
    cm = confusion_matrix(y_true, y_pred, labels=labels)
    return report_str, report_dict, cm


def _build_connected_groups(attack_ids, session_ids):
    """Assign a connected-component group to each row via union-find.

    Two rows belong to the same group if they share either an
    attack_instance_id or a session_id.  This guarantees that splitting
    by the returned group labels keeps both ID types fully separated
    across folds.
    """
    # --- union-find with path compression and union by rank -----------
    parent = {}
    rank = {}

    def find(x):
        while parent[x] != x:
            parent[x] = parent[parent[x]]  # path halving
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra == rb:
            return
        if rank[ra] < rank[rb]:
            ra, rb = rb, ra
        parent[rb] = ra
        if rank[ra] == rank[rb]:
            rank[ra] += 1

    # Create element for every unique attack_instance_id and session_id.
    # Prefix to avoid accidental collisions between the two namespaces.
    all_aids = attack_ids.unique()
    all_sids = session_ids.unique()
    for aid in all_aids:
        key = ("A", aid)
        parent[key] = key
        rank[key] = 0
    for sid in all_sids:
        key = ("S", sid)
        parent[key] = key
        rank[key] = 0

    # For each row, union its attack_instance_id node with its session_id
    # node.  Rows that share either ID will transitively merge.
    for aid, sid in zip(attack_ids, session_ids):
        union(("A", aid), ("S", sid))

    # Map each row to its component root → dense integer group label
    root_to_label = {}
    labels = np.empty(len(attack_ids), dtype=np.intp)
    next_label = 0
    for i, (aid, sid) in enumerate(zip(attack_ids, session_ids)):
        root = find(("A", aid))
        if root not in root_to_label:
            root_to_label[root] = next_label
            next_label += 1
        labels[i] = root_to_label[root]

    return pd.Series(labels, index=attack_ids.index)


def _validate_fold_separation(
    train_idx, val_idx, attack_ids, session_ids, fold_idx
):
    """Raise if any attack_instance_id or session_id leaks across the fold."""
    train_attacks = set(attack_ids.iloc[train_idx])
    val_attacks = set(attack_ids.iloc[val_idx])
    overlap_attacks = train_attacks & val_attacks
    if overlap_attacks:
        raise ValueError(
            f"Fold {fold_idx}: attack_instance_id overlap: {overlap_attacks}"
        )

    train_sessions = set(session_ids.iloc[train_idx])
    val_sessions = set(session_ids.iloc[val_idx])
    overlap_sessions = train_sessions & val_sessions
    if overlap_sessions:
        raise ValueError(
            f"Fold {fold_idx}: session_id overlap: {overlap_sessions}"
        )


def _groupkfold_score(
    model_cls, model_params, X, y, groups, attack_ids, session_ids,
    n_splits=5,
):
    """Cross-validate using GroupKFold with connected-component groups.

    Groups are built so that rows sharing either an attack_instance_id
    or a session_id always land in the same fold.  Each fold is validated
    for zero overlap on both ID types before training.

    Returns mean macro-F1 and per-fold scores.
    """
    gkf = GroupKFold(n_splits=n_splits)
    fold_scores = []
    for fold_idx, (train_idx, val_idx) in enumerate(gkf.split(X, y, groups)):
        _validate_fold_separation(
            train_idx, val_idx, attack_ids, session_ids, fold_idx
        )
        X_tr, X_val = X.iloc[train_idx], X.iloc[val_idx]
        y_tr, y_val = y.iloc[train_idx], y.iloc[val_idx]
        m = model_cls(**model_params)
        m.fit(X_tr, y_tr)
        preds = m.predict(X_val)
        score = f1_score(y_val, preds, average="macro", zero_division=0)
        fold_scores.append(score)
    return float(np.mean(fold_scores)), fold_scores


def train_detector():
    train, test = load_data()

    X_train = train[FEATURES]
    y_train = train["label"]
    attack_ids = train["attack_instance_id"]
    session_ids = train["session_id"]
    groups = _build_connected_groups(attack_ids, session_ids)

    X_test = test[FEATURES]
    y_test = test["label"]

    # ------------------------------------------------------------------
    # Model selection on TRAINING data only (GroupKFold by connected
    # components of attack_instance_id + session_id)
    # ------------------------------------------------------------------
    rf_params = dict(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )
    et_params = dict(
        n_estimators=500,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced_subsample",
        random_state=42,
        n_jobs=-1,
    )

    print("=" * 60)
    print("MODEL SELECTION — GroupKFold by connected components")
    print("  (attack_instance_id ∪ session_id, k=5)")
    print("=" * 60)

    rf_mean, rf_folds = _groupkfold_score(
        RandomForestClassifier, rf_params, X_train, y_train, groups,
        attack_ids, session_ids,
    )
    print(f"\nRandom Forest        macro-F1 = {rf_mean:.4f}  folds = "
          f"{[round(s, 4) for s in rf_folds]}")

    et_mean, et_folds = _groupkfold_score(
        ExtraTreesClassifier, et_params, X_train, y_train, groups,
        attack_ids, session_ids,
    )
    print(f"Extra Trees          macro-F1 = {et_mean:.4f}  folds = "
          f"{[round(s, 4) for s in et_folds]}")

    # Pick the best
    if et_mean > rf_mean:
        best_name = "ExtraTreesClassifier"
        best_cls = ExtraTreesClassifier
        best_params = et_params
        best_cv_f1 = et_mean
    else:
        best_name = "RandomForestClassifier"
        best_cls = RandomForestClassifier
        best_params = rf_params
        best_cv_f1 = rf_mean

    print(f"\n→ Selected: {best_name} (CV macro-F1 = {best_cv_f1:.4f})")

    # ------------------------------------------------------------------
    # Retrain on FULL training set, evaluate on held-out test set
    # ------------------------------------------------------------------
    model = best_cls(**best_params)
    model.fit(X_train, y_train)

    predictions = model.predict(X_test)

    report_str, report_dict, cm = _evaluate(y_test, predictions, model.classes_)

    # Feature importance
    importances = dict(
        zip(FEATURES, [float(x) for x in model.feature_importances_])
    )
    sorted_imp = sorted(importances.items(), key=lambda x: -x[1])

    metrics = {
        "model": best_name,
        "feature_set_version": 2,
        "cv_macro_f1": best_cv_f1,
        "cv_folds_rf": [round(s, 4) for s in rf_folds],
        "cv_folds_et": [round(s, 4) for s in et_folds],
        "accuracy": accuracy_score(y_test, predictions),
        "macro_precision": precision_score(
            y_test, predictions, average="macro", zero_division=0
        ),
        "macro_recall": recall_score(
            y_test, predictions, average="macro", zero_division=0
        ),
        "macro_f1": f1_score(
            y_test, predictions, average="macro", zero_division=0
        ),
        "weighted_f1": f1_score(
            y_test, predictions, average="weighted", zero_division=0
        ),
        "training_records": len(train),
        "testing_records": len(test),
        "features": len(FEATURES),
        "feature_names": FEATURES,
        "training_classes": sorted(y_train.unique().tolist()),
        "testing_classes": sorted(y_test.unique().tolist()),
        "unseen_test_classes": sorted(
            set(y_test.unique()) - set(y_train.unique())
        ),
    }

    # ------------------------------------------------------------------
    # Save artefacts
    # ------------------------------------------------------------------
    joblib.dump(model, MODEL_DIR / "network_classifier.joblib")
    joblib.dump(FEATURES, MODEL_DIR / "network_features.joblib")

    with open(MODEL_DIR / "evaluation_metrics.json", "w") as f:
        json.dump(metrics, f, indent=4)

    with open(MODEL_DIR / "classification_report.json", "w") as f:
        json.dump(report_dict, f, indent=4)

    cm_data = {
        "labels": model.classes_.tolist(),
        "matrix": cm.tolist(),
    }
    with open(MODEL_DIR / "confusion_matrix.json", "w") as f:
        json.dump(cm_data, f, indent=4)

    with open(MODEL_DIR / "feature_importance.json", "w") as f:
        json.dump(dict(sorted_imp), f, indent=4)

    # ------------------------------------------------------------------
    # Console output
    # ------------------------------------------------------------------
    print("\n" + "=" * 60)
    print("NETWORK DETECTOR RESULTS (held-out test set)")
    print("=" * 60)

    for key in ["accuracy", "macro_precision", "macro_recall",
                "macro_f1", "weighted_f1"]:
        print(f"  {key:20s}: {metrics[key]:.4f}")

    print(f"  {'training_records':20s}: {metrics['training_records']}")
    print(f"  {'testing_records':20s}: {metrics['testing_records']}")
    print(f"  {'features':20s}: {metrics['features']}")

    print("\nCLASSIFICATION REPORT")
    print(report_str)

    print("CONFUSION MATRIX")
    header = "  ".join(f"{c:>14s}" for c in model.classes_)
    print(f"{'Predicted →':>20s}  {header}")
    for i, row_label in enumerate(model.classes_):
        row = "  ".join(f"{cm[i, j]:>14d}" for j in range(len(model.classes_)))
        print(f"{'Actual ' + row_label:>20s}  {row}")

    print("\nFEATURE IMPORTANCE (top 10)")
    for feat, imp in sorted_imp[:10]:
        print(f"  {feat:30s}: {imp:.4f}")

    print(f"\nMODEL SAVED: {MODEL_DIR}")


def predict_network(network_features):
    """Predict attack class from a dict, Series, or DataFrame of feature values.

    Accepts the BASE_FEATURES columns plus the _ENG_SOURCE_COLS
    (f_session_req_count, f_session_unique_paths, f_session_error_count).
    Engineered features are computed internally if not already present.

    Returns a dict with both legacy ('prediction', 'probabilities') and
    standardized ('predicted_class', 'class_probabilities') keys for
    seamless integration across detectors and hybrid aggregators.
    """
    if not MODEL_PATH.exists() or not FEATURES_PATH.exists():
        raise FileNotFoundError(
            f"Network model artifacts not found in {MODEL_DIR}. "
            "Train the detector first."
        )

    model = joblib.load(MODEL_PATH)
    feature_names = joblib.load(FEATURES_PATH)

    if isinstance(network_features, dict):
        input_data = pd.DataFrame([network_features])
    elif isinstance(network_features, pd.Series):
        input_data = pd.DataFrame([network_features.to_dict()])
    elif isinstance(network_features, pd.DataFrame):
        input_data = network_features.copy()
    else:
        input_data = pd.DataFrame(network_features)

    # Compute engineered features if not already present
    if "f_bytes_per_pkt" not in input_data.columns:
        required_raw = [
            "dst_port",
            "f_flow_pkts_total",
            "f_flow_bytes_total",
            "f_tcp_rst",
            "f_tcp_fin",
            "f_suricata_alerts_60s",
            "f_suricata_high_sev_60s",
        ]
        missing_raw = [col for col in required_raw if col not in input_data.columns]
        if missing_raw:
            raise ValueError(
                f"Missing required raw features to compute network features: {missing_raw}"
            )
        input_data = prepare_features(input_data)

    missing = [f for f in feature_names if f not in input_data.columns]
    if missing:
        raise ValueError(f"Missing inference features: {missing}")

    X = input_data[feature_names].apply(pd.to_numeric, errors="raise")
    if not np.isfinite(X.to_numpy(dtype=float)).all():
        raise ValueError("Inference features contain NaN or infinite values.")

    probabilities = model.predict_proba(X)[0]
    prediction_index = probabilities.argmax()
    predicted_class = str(model.classes_[prediction_index])
    confidence = float(probabilities[prediction_index])
    class_probabilities = {
        str(label): float(probability)
        for label, probability in zip(model.classes_, probabilities)
    }

    return {
        "prediction": predicted_class,
        "confidence": confidence,
        "probabilities": class_probabilities,
        "predicted_class": predicted_class,
        "class_probabilities": class_probabilities,
    }


if __name__ == "__main__":
    train_detector()
