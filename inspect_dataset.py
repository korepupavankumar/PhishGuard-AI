
from pathlib import Path
import pandas as pd

DATASET_PATH = Path("data/PhiUSIIL_Phishing_URL_Dataset.csv")


def main():
    if not DATASET_PATH.exists():
        print(f"Dataset not found: {DATASET_PATH.resolve()}")
        return

    print("Loading PhishGuard AI dataset...")
    df = pd.read_csv(DATASET_PATH, low_memory=False)

    print("\n--- Dataset Information ---")
    print(f"Rows: {df.shape[0]:,}")
    print(f"Columns: {df.shape[1]}")

    print("\n--- Column Names ---")
    print(df.columns.tolist())

    print("\n--- Missing Values ---")
    print(df[["URL", "label"]].isnull().sum())

    print("\n--- Label Distribution ---")
    print(df["label"].value_counts(dropna=False))

    print("\n--- Duplicate URLs ---")
    print(df["URL"].duplicated().sum())

    print("\n--- Sample Records ---")
    print(df[["URL", "label"]].head())

    print("\nDataset inspection completed.")


if __name__ == "__main__":
    main()
