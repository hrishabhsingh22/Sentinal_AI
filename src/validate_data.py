
from pathlib import Path

import joblib
import numpy as np
import pandas as pd


DATA_DIR = Path("data/processed")
MODEL_DIR = Path("models")

DATASETS = {
    "Training": DATA_DIR / "train_features.csv",
    "Normal testing": DATA_DIR / "test_features.csv",
    "Anomalous testing": DATA_DIR / "attack_features.csv",
}


def validate_file(name, path):
    if not path.exists():
        raise FileNotFoundError(
            f"{name} dataset not found: {path}"
        )

    df = pd.read_csv(path)

    if df.empty:
        raise ValueError(f"{name} dataset is empty.")

    if df.columns.duplicated().any():
        raise ValueError(
            f"{name} contains duplicate column names."
        )

    if df.isnull().any().any():
        raise ValueError(
            f"{name} contains missing values."
        )

    if not all(
        pd.api.types.is_numeric_dtype(dtype)
        for dtype in df.dtypes
    ):
        raise TypeError(
            f"{name} contains non-numeric features."
        )

    values = df.to_numpy(dtype=np.float64)

    if not np.isfinite(values).all():
        raise ValueError(
            f"{name} contains NaN or infinite values."
        )

    print(f"\n{name} dataset")
    print("-------------------------")
    print("Records:", len(df))
    print("Features:", len(df.columns))
    print("Missing values:", int(df.isna().sum().sum()))
    print("All values finite:", bool(np.isfinite(values).all()))

    return df


def main():
    datasets = {}

    for name, path in DATASETS.items():
        datasets[name] = validate_file(name, path)

    train_columns = list(datasets["Training"].columns)

    for name, df in datasets.items():
        if list(df.columns) != train_columns:
            raise ValueError(
                f"Feature columns or ordering differ in {name}."
            )

    config_path = MODEL_DIR / "autoencoder_config.joblib"

    if not config_path.exists():
        raise FileNotFoundError(
            "Saved autoencoder configuration not found."
        )

    config = joblib.load(config_path)
    model_features = config["feature_names"]

    if train_columns != model_features:
        raise ValueError(
            "Dataset features do not match the saved model configuration."
        )

    print("\nAll validation checks passed!")
    print("All three datasets have matching feature schemas.")
    print("Saved model feature schema matches the datasets.")
    print("Total records:", sum(len(df) for df in datasets.values()))


if __name__ == "__main__":
    main()
