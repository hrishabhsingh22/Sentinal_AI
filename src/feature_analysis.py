
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

DATA_DIR = Path("data/processed")
REPORT_DIR = Path("reports")


def load_datasets():
    normal = pd.read_csv(
        DATA_DIR / "train_features.csv"
    )

    attack = pd.read_csv(
        DATA_DIR / "attack_features.csv"
    )

    if list(normal.columns) != list(attack.columns):
        raise ValueError("Feature schemas do not match.")

    if normal.empty or attack.empty:
        raise ValueError("One or more datasets are empty.")

    return normal, attack


def compare_features(normal, attack):
    rows = []

    for feature in normal.columns:
        normal_mean = normal[feature].mean()
        attack_mean = attack[feature].mean()

        normal_std = normal[feature].std()
        attack_std = attack[feature].std()

        pooled_std = np.sqrt(
            (normal_std ** 2 + attack_std ** 2) / 2
        )

        if pooled_std == 0:
            effect_size = 0.0
        else:
            effect_size = (
                attack_mean - normal_mean
            ) / pooled_std

        rows.append({
            "feature": feature,
            "normal_mean": normal_mean,
            "attack_mean": attack_mean,
            "normal_std": normal_std,
            "attack_std": attack_std,
            "effect_size": effect_size,
            "absolute_effect_size": abs(effect_size),
        })

    results = pd.DataFrame(rows)

    results = results.sort_values(
        "absolute_effect_size",
        ascending=False,
    )

    return results


def plot_feature_distributions(normal, attack):
    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    for feature in normal.columns:
        plt.figure(figsize=(8, 5))

        plt.hist(
            normal[feature],
            bins=50,
            alpha=0.6,
            density=True,
            label="Normal",
        )

        plt.hist(
            attack[feature],
            bins=50,
            alpha=0.6,
            density=True,
            label="Attack",
        )

        plt.xlabel(feature)
        plt.ylabel("Density")
        plt.title(f"Feature Distribution: {feature}")
        plt.legend()
        plt.tight_layout()

        plt.savefig(
            REPORT_DIR / f"feature_{feature}.png"
        )

        plt.close()


def main():
    print("Loading feature datasets...")

    normal, attack = load_datasets()

    print("Normal requests:", len(normal))
    print("Attack requests:", len(attack))
    print("Features:", len(normal.columns))

    print("\nComparing feature distributions...")

    results = compare_features(normal, attack)

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    results.to_csv(
        REPORT_DIR / "feature_comparison.csv",
        index=False,
    )

    print("\nFeature comparison:")
    print(results.to_string(index=False))

    print("\nGenerating feature distribution plots...")

    plot_feature_distributions(normal, attack)

    print("\nFeature analysis completed.")
    print("Saved: reports/feature_comparison.csv")
    print("Saved: reports/feature_<name>.png")


if __name__ == "__main__":
    main()
