
import os
import json
import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from tensorflow.keras import layers, models, callbacks


ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../..")
)

TRAIN_PATH = os.path.join(
    ROOT, "data/processed/soc_mld/train.csv"
)

TEST_PATH = os.path.join(
    ROOT, "data/processed/soc_mld/test.csv"
)

MODEL_DIR = os.path.join(ROOT, "models/sequence")
os.makedirs(MODEL_DIR, exist_ok=True)

MODEL_PATH = os.path.join(
    MODEL_DIR, "sequence_lstm_v2.keras"
)

SCALER_PATH = os.path.join(
    MODEL_DIR, "sequence_scaler_v2.joblib"
)

METRICS_PATH = os.path.join(
    MODEL_DIR, "evaluation_metrics_v2.json"
)

FEATURES = [
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
    "f_has_sql_comment"
]

PADDING_VALUE = -999.0
RANDOM_SEED = 42

np.random.seed(RANDOM_SEED)
tf.random.set_seed(RANDOM_SEED)


def load_http_data(path):
    df = pd.read_csv(path)

    df = df[df["source"] == "nginx"].copy()

    required = FEATURES + [
        "session_id",
        "timestamp",
        "request_id",
        "label"
    ]

    missing = [
        column for column in required
        if column not in df.columns
    ]

    if missing:
        raise ValueError(f"Missing columns: {missing}")

    df["timestamp"] = pd.to_numeric(
        df["timestamp"], errors="coerce"
    )

    df = df.dropna(
        subset=["session_id", "timestamp", "request_id", "label"]
    )

    if df[FEATURES].isna().any().any():
        raise ValueError("Missing values found in input features")

    df = df.sort_values(
        ["session_id", "timestamp", "request_id"],
        kind="stable"
    ).reset_index(drop=True)

    df["target"] = (
        df["label"].astype(str) != "NORMAL"
    ).astype(np.int32)

    return df


def build_sequences(df, scaler, max_length, fit_scaler=False):

    if fit_scaler:
        scaler = StandardScaler()
        scaler.fit(df[FEATURES])

    scaled = scaler.transform(
        df[FEATURES]
    ).astype(np.float32)

    working = df.copy()
    working[FEATURES] = scaled

    X_sequences = []
    y_sequences = []

    for _, group in working.groupby("session_id", sort=False):

        x = group[FEATURES].to_numpy(dtype=np.float32)
        y = group["target"].to_numpy(dtype=np.int32)

        X_sequences.append(x)
        y_sequences.append(y)

    X = np.full(
        (
            len(X_sequences),
            max_length,
            len(FEATURES)
        ),
        PADDING_VALUE,
        dtype=np.float32
    )

    y = np.full(
        (len(y_sequences), max_length),
        -1,
        dtype=np.int32
    )

    # Post-padding: real requests come first.
    for i, (x_seq, y_seq) in enumerate(
        zip(X_sequences, y_sequences)
    ):

        length = len(x_seq)

        if length > max_length:
            raise ValueError("Sequence exceeds configured maximum")

        X[i, :length, :] = x_seq
        y[i, :length] = y_seq

    return X, y, scaler


def make_model(max_length):

    inputs = layers.Input(
        shape=(max_length, len(FEATURES)),
        name="request_sequence"
    )

    x = layers.LSTM(
        32,
        return_sequences=True,
        name="lstm_layer_1"
    )(inputs)

    x = layers.Dropout(0.25)(x)

    x = layers.LSTM(
        16,
        return_sequences=True,
        name="lstm_layer_2"
    )(x)

    x = layers.Dropout(0.20)(x)

    outputs = layers.Dense(
        1,
        activation="sigmoid",
        name="attack_probability"
    )(x)

    model = models.Model(inputs, outputs)

    model.compile(
        optimizer=tf.keras.optimizers.Adam(
            learning_rate=0.001
        ),
        loss="binary_crossentropy",
        weighted_metrics=[
            tf.keras.metrics.BinaryAccuracy(name="accuracy")
        ]
    )

    return model



def get_valid_predictions(model, X, y):

    probabilities = model.predict(
        X,
        verbose=0
    ).squeeze(-1)

    valid_mask = y != -1

    y_true = y[valid_mask].astype(np.int32)
    y_probability = probabilities[valid_mask]

    return y_true, y_probability


def calculate_metrics(y_true, probabilities):

    predictions = (
        probabilities >= 0.5
    ).astype(np.int32)

    metrics = {
        "accuracy": float(
            accuracy_score(y_true, predictions)
        ),
        "precision": float(
            precision_score(
                y_true,
                predictions,
                zero_division=0
            )
        ),
        "recall": float(
            recall_score(
                y_true,
                predictions,
                zero_division=0
            )
        ),
        "f1": float(
            f1_score(
                y_true,
                predictions,
                zero_division=0
            )
        ),
        "roc_auc": float(
            roc_auc_score(y_true, probabilities)
        ),
        "confusion_matrix": confusion_matrix(
            y_true,
            predictions,
            labels=[0, 1]
        ).tolist(),
        "threshold": 0.5,
        "evaluated_requests": int(len(y_true)),
        "normal_requests": int(np.sum(y_true == 0)),
        "attack_requests": int(np.sum(y_true == 1))
    }

    return metrics, predictions


def main():

    print("Loading HTTP datasets...")

    train_df = load_http_data(TRAIN_PATH)
    test_df = load_http_data(TEST_PATH)

    train_sessions = set(train_df["session_id"])
    test_sessions = set(test_df["session_id"])

    overlap = train_sessions.intersection(test_sessions)

    if overlap:
        raise ValueError(
            f"Session leakage detected: {len(overlap)} shared sessions"
        )

    max_length = int(
        max(
            train_df.groupby("session_id").size().max(),
            test_df.groupby("session_id").size().max()
        )
    )

    print("\nDATASET INFORMATION")
    print("Training requests:", len(train_df))
    print("Testing requests:", len(test_df))
    print("Training sessions:", len(train_sessions))
    print("Testing sessions:", len(test_sessions))
    print("Maximum session length:", max_length)

    print("\nTraining label distribution:")
    print(train_df["target"].value_counts().to_dict())

    print("\nTesting label distribution:")
    print(test_df["target"].value_counts().to_dict())

    X_train, y_train, scaler = build_sequences(
        train_df,
        scaler=None,
        max_length=max_length,
        fit_scaler=True
    )

    X_test, y_test, _ = build_sequences(
        test_df,
        scaler=scaler,
        max_length=max_length
    )

    print("\nSEQUENCE SHAPES")
    print("X_train:", X_train.shape)
    print("y_train:", y_train.shape)
    print("X_test:", X_test.shape)
    print("y_test:", y_test.shape)

    # Session-level validation split.
    rng = np.random.default_rng(RANDOM_SEED)

    indices = rng.permutation(len(X_train))

    val_count = max(
        1,
        int(len(indices) * 0.20)
    )

    val_indices = indices[:val_count]
    fit_indices = indices[val_count:]

    y_train_clean = np.maximum(
        y_train, 0
    )[..., np.newaxis].astype(np.float32)

    train_weights = (
        y_train != -1
    ).astype(np.float32)

    # Balance classes using only the fitting sessions.
    fitting_labels = y_train[fit_indices]
    fitting_labels = fitting_labels[fitting_labels != -1]

    class_counts = np.bincount(
        fitting_labels,
        minlength=2
    )

    if np.any(class_counts == 0):
        raise ValueError(
            "Both classes must occur in training sessions"
        )

    class_weights = (
        len(fitting_labels) /
        (2.0 * class_counts)
    )

    train_weights[fit_indices] *= np.where(
        y_train[fit_indices] == 1,
        class_weights[1],
        class_weights[0]
    )

    validation_weights = (
        y_train[val_indices] != -1
    ).astype(np.float32)

    model = make_model(max_length)

    model.summary()

    early_stop = callbacks.EarlyStopping(
        monitor="val_loss",
        patience=8,
        restore_best_weights=True
    )

    reduce_lr = callbacks.ReduceLROnPlateau(
        monitor="val_loss",
        factor=0.5,
        patience=4,
        min_lr=0.00001
    )

    print("\nTRAINING LSTM...")

    history = model.fit(
        X_train[fit_indices],
        y_train_clean[fit_indices],
        sample_weight=train_weights[fit_indices],
        validation_data=(
            X_train[val_indices],
            y_train_clean[val_indices],
            validation_weights
        ),
        epochs=40,
        batch_size=8,
        callbacks=[
            early_stop,
            reduce_lr
        ],
        verbose=1
    )

    print("\nVALIDATION EVALUATION")

    val_true, val_probabilities = get_valid_predictions(
        model,
        X_train[val_indices],
        y_train[val_indices]
    )

    val_metrics, _ = calculate_metrics(
        val_true,
        val_probabilities
    )

    for key, value in val_metrics.items():
        print(f"{key}: {value}")

    print("\nHELD-OUT TEST EVALUATION")

    test_true, test_probabilities = get_valid_predictions(
        model,
        X_test,
        y_test
    )

    test_metrics, test_predictions = calculate_metrics(
        test_true,
        test_probabilities
    )

    print("\nCLASSIFICATION REPORT")

    print(
        classification_report(
            test_true,
            test_predictions,
            labels=[0, 1],
            target_names=["NORMAL", "ATTACK"],
            zero_division=0
        )
    )

    print("\nCONFUSION MATRIX")

    print(
        np.array(test_metrics["confusion_matrix"])
    )

    print("\nTEST METRICS")

    for key, value in test_metrics.items():
        print(f"{key}: {value}")

    # Verify every HTTP test request was evaluated.
    if test_metrics["evaluated_requests"] != len(test_df):
        raise ValueError(
            "Not all test requests were evaluated"
        )

    final_results = {
        "model": "LSTM",
        "architecture": "LSTM_32_LSTM_16",
        "task": "request_level_binary_classification",
        "features": FEATURES,
        "feature_count": len(FEATURES),
        "max_sequence_length": max_length,
        "training_requests": len(train_df),
        "testing_requests": len(test_df),
        "training_sessions": len(train_sessions),
        "testing_sessions": len(test_sessions),
        "epochs_trained": len(history.history["loss"]),
        "validation_metrics": val_metrics,
        "test_metrics": test_metrics
    }

    model.save(MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)

    with open(METRICS_PATH, "w") as file:
        json.dump(final_results, file, indent=4)

    print("\nMODEL SAVED SUCCESSFULLY")
    print("Model:", MODEL_PATH)
    print("Scaler:", SCALER_PATH)
    print("Metrics:", METRICS_PATH)


if __name__ == "__main__":
    main()
