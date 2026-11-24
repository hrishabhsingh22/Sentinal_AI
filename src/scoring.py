
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from tensorflow import keras


MODEL_DIR = Path("models")


def load_detector():
    model_path = MODEL_DIR / "autoencoder.keras"
    scaler_path = MODEL_DIR / "scaler.joblib"
    config_path = MODEL_DIR / "autoencoder_config.joblib"

    for path in [model_path, scaler_path, config_path]:
        if not path.exists():
            raise FileNotFoundError(
                f"Required model artifact not found: {path}"
            )

    model = keras.models.load_model(model_path)
    scaler = joblib.load(scaler_path)
    config = joblib.load(config_path)

    feature_names = config["feature_names"]
    threshold = float(config["threshold"])

    if not np.isfinite(threshold) or threshold < 0:
        raise ValueError("Invalid anomaly threshold.")

    return model, scaler, feature_names, threshold


def score_features(df, model, scaler, feature_names, threshold):
    missing_features = [
        feature for feature in feature_names
        if feature not in df.columns
    ]

    if missing_features:
        raise ValueError(
            f"Missing required features: {missing_features}"
        )

    X = df[feature_names].to_numpy(dtype=np.float32)

    if not np.isfinite(X).all():
        raise ValueError(
            "Input features contain NaN or infinite values."
        )

    X_scaled = scaler.transform(X)

    reconstructed = model.predict(
        X_scaled,
        verbose=0,
    )

    errors = np.mean(
        (X_scaled - reconstructed) ** 2,
        axis=1,
    )

    predictions = (errors > threshold).astype(int)

    return pd.DataFrame({
        "reconstruction_error": errors,
        "predicted_anomaly": predictions,
    })
