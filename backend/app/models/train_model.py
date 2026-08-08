"""
train_model.py
---------------
Trains a Random Forest classifier on a labeled dataset of URLs
(Safe / Suspicious / Malicious), evaluates it, and saves the trained
model to disk as a .pkl file using joblib (free, no paid service).

Expects a CSV at dataset/dataset.csv with two columns:
    url,label
    https://google.com,safe
    http://192.168.1.1/verify,malicious
    ...

Label values must be exactly: safe, suspicious, malicious
(see dataset/build_dataset.py, File 12, for how to build this CSV
from free sources like PhishTank + Tranco).
"""

import os
import sys
import json
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import (
    accuracy_score,
    precision_recall_fscore_support,
    confusion_matrix,
    classification_report,
)

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from feature_pipeline import extract_features, FEATURE_NAMES  # noqa: E402

# Paths — adjust if your folder layout differs
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))  # backend/
PROJECT_ROOT = os.path.dirname(BASE_DIR)  # repo root
DATASET_PATH = os.path.join(PROJECT_ROOT, "dataset", "dataset.csv")
MODEL_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "models", "threat_model.pkl")
METRICS_OUTPUT_PATH = os.path.join(PROJECT_ROOT, "models", "training_metrics.json")

LABEL_MAP = {"safe": 0, "suspicious": 1, "malicious": 2}
REVERSE_LABEL_MAP = {v: k for k, v in LABEL_MAP.items()}


def build_feature_dataset(csv_path: str) -> pd.DataFrame:
    """
    Reads the url,label CSV and runs the full feature pipeline on every
    URL (this makes real network calls — SSL/WHOIS/DNS — so it can take
    a while for large datasets). Returns a DataFrame ready for training.
    """
    df = pd.read_csv(csv_path)
    if "url" not in df.columns or "label" not in df.columns:
        raise ValueError("dataset.csv must have 'url' and 'label' columns")

    rows = []
    total = len(df)
    for i, row in df.iterrows():
        url = row["url"]
        label = str(row["label"]).strip().lower()
        if label not in LABEL_MAP:
            print(f"[skip] row {i}: unknown label '{label}'")
            continue

        print(f"[{i + 1}/{total}] extracting features for {url} ...")
        try:
            result = extract_features(url)
            feature_row = result["features"]
            feature_row["label"] = LABEL_MAP[label]
            rows.append(feature_row)
        except Exception as e:
            print(f"[skip] row {i}: feature extraction failed: {e}")

    if not rows:
        raise RuntimeError("No usable rows after feature extraction — check dataset.csv")

    return pd.DataFrame(rows)


def train(feature_df: pd.DataFrame):
    X = feature_df[FEATURE_NAMES]
    y = feature_df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if y.nunique() > 1 else None
    )

    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        random_state=42,
        class_weight="balanced",  # helps if classes are imbalanced (few malicious samples etc.)
    )
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_test, y_pred, average="weighted", zero_division=0
    )
    cm = confusion_matrix(y_test, y_pred).tolist()
    report = classification_report(
        y_test, y_pred, target_names=list(LABEL_MAP.keys()), zero_division=0
    )

    metrics = {
        "accuracy": accuracy,
        "precision_weighted": precision,
        "recall_weighted": recall,
        "f1_weighted": f1,
        "confusion_matrix": cm,
        "label_order": list(LABEL_MAP.keys()),
        "classification_report": report,
        "feature_importances": dict(
            zip(FEATURE_NAMES, model.feature_importances_.tolist())
        ),
    }

    print("\n=== Training complete ===")
    print(f"Accuracy:  {accuracy:.3f}")
    print(f"Precision: {precision:.3f}")
    print(f"Recall:    {recall:.3f}")
    print(f"F1 score:  {f1:.3f}")
    print("\nClassification report:\n", report)

    return model, metrics


def main():
    os.makedirs(os.path.dirname(MODEL_OUTPUT_PATH), exist_ok=True)

    if not os.path.exists(DATASET_PATH):
        print(f"ERROR: dataset not found at {DATASET_PATH}")
        print("Create dataset/dataset.csv with columns: url,label")
        print("(see dataset/build_dataset.py, File 12, to build one from free sources)")
        return

    print(f"Loading dataset from {DATASET_PATH} ...")
    feature_df = build_feature_dataset(DATASET_PATH)

    print(f"\nBuilt feature dataset with {len(feature_df)} usable rows.")
    print(feature_df["label"].value_counts().rename(index=REVERSE_LABEL_MAP))

    model, metrics = train(feature_df)

    joblib.dump({"model": model, "feature_names": FEATURE_NAMES, "label_map": LABEL_MAP}, MODEL_OUTPUT_PATH)
    print(f"\nModel saved to {MODEL_OUTPUT_PATH}")

    with open(METRICS_OUTPUT_PATH, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"Metrics saved to {METRICS_OUTPUT_PATH}")


if __name__ == "__main__":
    main()