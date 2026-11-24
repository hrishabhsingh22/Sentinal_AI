
import pandas as pd

from src.detection.http_detector import (
    predict_http,
    FEATURE_NAMES,
    TEST_PATH,
)


def main():
    df = pd.read_csv(TEST_PATH)
    df = df[df["source"] == "nginx"].copy()

    sample = df.iloc[[0]][FEATURE_NAMES]

    result = predict_http(sample)

    print("\n--- HTTP INFERENCE TEST ---")
    print("Predicted class:", result["predicted_class"])
    print("Confidence:", round(result["confidence"], 4))

    print("\nTop 5 predictions:")

    top_predictions = sorted(
        result["class_probabilities"].items(),
        key=lambda item: item[1],
        reverse=True,
    )[:5]

    for label, probability in top_predictions:
        print(f"{label}: {probability:.4f}")

    print("\nActual class:", df.iloc[0]["label"])


if __name__ == "__main__":
    main()
