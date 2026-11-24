
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import tensorflow as tf

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from tensorflow import keras
from tensorflow.keras import layers

SEED = 42
tf.keras.utils.set_random_seed(SEED)

DATA_PATH = Path("data/processed/train_features.csv")
MODEL_DIR = Path("models")
REPORT_DIR = Path("reports")

MODEL_DIR.mkdir(parents=True, exist_ok=True)
REPORT_DIR.mkdir(parents=True, exist_ok=True)

df = pd.read_csv(DATA_PATH)

if df.empty or df.isnull().any().any():
    raise ValueError("Training dataset is empty or contains missing values.")

feature_names = list(df.columns)
X = df[feature_names].to_numpy(dtype=np.float32)

X_train, X_remaining = train_test_split(
    X,
    test_size=0.30,
    random_state=SEED,
    shuffle=True,
)

X_val, X_calibration = train_test_split(
    X_remaining,
    test_size=0.50,
    random_state=SEED,
    shuffle=True,
)

scaler = StandardScaler()

X_train = scaler.fit_transform(X_train)
X_val = scaler.transform(X_val)
X_calibration = scaler.transform(X_calibration)

inputs = keras.Input(shape=(X_train.shape[1],))

x = layers.Dense(32, activation="relu")(inputs)
x = layers.Dense(16, activation="relu")(x)
x = layers.Dense(8, activation="relu")(x)
x = layers.Dense(16, activation="relu")(x)
x = layers.Dense(32, activation="relu")(x)

outputs = layers.Dense(X_train.shape[1])(x)

model = keras.Model(inputs, outputs)

model.compile(
    optimizer="adam",
    loss="mse",
)

early_stopping = keras.callbacks.EarlyStopping(
    monitor="val_loss",
    patience=5,
    restore_best_weights=True,
)

history = model.fit(
    X_train,
    X_train,
    validation_data=(X_val, X_val),
    epochs=50,
    batch_size=64,
    callbacks=[early_stopping],
    shuffle=True,
    verbose=1,
)

calibration_reconstructed = model.predict(
    X_calibration,
    verbose=0,
)

calibration_errors = np.mean(
    (X_calibration - calibration_reconstructed) ** 2,
    axis=1,
)

threshold = float(np.quantile(calibration_errors, 0.95))

if not np.isfinite(threshold):
    raise ValueError("Invalid calibration threshold.")

model.save(MODEL_DIR / "autoencoder.keras")

joblib.dump(
    scaler,
    MODEL_DIR / "scaler.joblib",
)

joblib.dump(
    {
        "feature_names": feature_names,
        "threshold": threshold,
        "seed": SEED,
    },
    MODEL_DIR / "autoencoder_config.joblib",
)

calibration_results = pd.DataFrame({
    "reconstruction_error": calibration_errors,
})

calibration_results.to_csv(
    REPORT_DIR / "calibration_errors.csv",
    index=False,
)

print("\nTraining complete.")
print("Training requests:", len(X_train))
print("Validation requests:", len(X_val))
print("Calibration requests:", len(X_calibration))
print("Epochs completed:", len(history.history["loss"]))
print("Calibration threshold:", threshold)
print(
    "Calibration error 95th percentile:",
    float(np.quantile(calibration_errors, 0.95)),
)
print("Saved calibration errors to reports/calibration_errors.csv")
