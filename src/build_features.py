
from pathlib import Path

import pandas as pd

from src.parse_http import parse_http_file
from src.features import extract_features


RAW_DIR = Path("data/raw")
OUT_DIR = Path("data/processed")


def process_dataset(input_name, output_name):
    input_path = RAW_DIR / input_name
    output_path = OUT_DIR / output_name

    if not input_path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {input_path}"
        )

    requests = parse_http_file(input_path)

    if not requests:
        raise ValueError(
            f"No HTTP requests parsed from {input_name}"
        )

    rows = [extract_features(request) for request in requests]

    df = pd.DataFrame(rows)

    if df.empty:
        raise ValueError(
            f"No features generated for {input_name}"
        )

    if df.isnull().any().any():
        raise ValueError(
            f"Missing feature values in {input_name}"
        )

    OUT_DIR.mkdir(parents=True, exist_ok=True)
    df.to_csv(output_path, index=False)

    print(f"\nDataset: {input_name}")
    print(f"Records: {len(df)}")
    print(f"Features: {len(df.columns)}")
    print(f"Saved: {output_path}")
    print(f"Missing values: {int(df.isna().sum().sum())}")

    return list(df.columns)


def main():
    train_columns = process_dataset(
        "normalTrafficTraining.txt",
        "train_features.csv",
    )

    test_columns = process_dataset(
        "normalTrafficTest.txt",
        "test_features.csv",
    )

    attack_columns = process_dataset(
        "anomalousTrafficTest.txt",
        "attack_features.csv",
    )

    if not (
        train_columns == test_columns == attack_columns
    ):
        raise ValueError(
            "Feature columns differ between datasets."
        )

    print("\nAll three feature datasets generated successfully.")
    print(f"Feature count: {len(train_columns)}")


if __name__ == "__main__":
    main()
