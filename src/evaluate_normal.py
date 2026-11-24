
import joblib
import numpy as np
import pandas as pd
from tensorflow import keras

MODEL_DIR = "models"

model = keras.models.load_model(
    f"{MODEL_DIR}/autoencoder.keras"
)
scaler = joblib.load(f"{MODEL_DIR}/scaler.joblib")
config = joblib.load(
    f"{MODEL_DIR}/autoencoder_config.joblib"
)

test = pd.read_csv(
    "data/processed/test_features.csv"
)

features = config["feature_names"]
X = test[features].to_numpy(dtype=np.float32)
X_scaled = scaler.transform(X)

reconstructed = model.predict(X_scaled, verbose=0)
errors = np.mean(
    (X_scaled - reconstructed) ** 2,
    axis=1,
)

threshold = config["threshold"]
predicted_anomalies = errors > threshold

false_positive_rate = float(
    predicted_anomalies.mean()
)

print("Normal test requests:", len(test))
print("Threshold:", threshold)
print("Flagged normal requests:", int(predicted_anomalies.sum()))
print("Normal false-positive rate:", false_positive_rate)
print("Median reconstruction error:", float(np.median(errors)))
print("95th percentile test error:", float(np.quantile(errors, 0.95)))

results = pd.DataFrame({
    "reconstruction_error": errors,
    "predicted_anomaly": predicted_anomalies.astype(int),
})

results.to_csv(
    "reports/normal_test_scores.csv",
    index=False,
)
print("Saved test scores.")
