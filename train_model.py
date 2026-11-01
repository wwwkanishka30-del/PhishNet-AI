"""
PhishNet AI - Machine Learning Model Training and Evaluation Pipeline
Script: train_model.py

This script trains, validates, and exports a Machine Learning classifier
(Random Forest) for phishing URL detection. It performs stratified splitting,
calculates rigorous classification metrics (Precision, Recall, F1, Confusion Matrix),
and compares performance against a Logistic Regression baseline.
"""

import csv
import json
import os
import sys
import numpy as np

from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split
import joblib

# Ensure local modules can be imported
sys.path.insert(0, os.path.dirname(__file__))
import detector


FEATURE_NAMES = [
    "url_length",
    "hostname_length",
    "dot_count_host",
    "hyphen_count_host",
    "has_at_symbol",
    "is_ip_host",
    "is_https",
    "subdomain_count",
    "path_length",
    "query_length",
    "has_suspicious_keyword",
    "has_target_brand"
]


def load_dataset(csv_path: str):
    """Loads URLs and labels from the curated dataset."""
    urls = []
    labels = []
    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            urls.append(row["url"].strip())
            labels.append(int(row["label"].strip()))
    return urls, labels


def train_and_evaluate():
    base_dir = os.path.dirname(__file__)
    data_path = os.path.join(base_dir, "data", "dataset.csv")
    models_dir = os.path.join(base_dir, "models")
    os.makedirs(models_dir, exist_ok=True)

    print(f"[*] Loading dataset from: {data_path}")
    urls, labels = load_dataset(data_path)
    total_samples = len(urls)
    legit_count = labels.count(0)
    phish_count = labels.count(1)
    print(f"[*] Total samples: {total_samples} (Legitimate: {legit_count}, Phishing: {phish_count})")

    # Feature extraction
    print("[*] Extracting 12 structural, lexical, and behavioral features...")
    X = np.array([detector.extract_features_vector(u) for u in urls])
    y = np.array(labels)

    # Stratified Train/Test Split (80% train, 20% test)
    X_train, X_test, y_train, y_test, urls_train, urls_test = train_test_split(
        X, y, urls, test_size=0.20, random_state=42, stratify=y
    )

    print(f"[*] Training samples: {len(y_train)}, Testing samples: {len(y_test)}")

    # 1. Baseline Model: Logistic Regression
    print("\n--- Model 1: Logistic Regression Baseline ---")
    lr = LogisticRegression(max_iter=1000, random_state=42)
    lr.fit(X_train, y_train)
    lr_pred = lr.predict(X_test)
    lr_acc = accuracy_score(y_test, lr_pred)
    lr_f1 = f1_score(y_test, lr_pred, zero_division=0)
    print(f"Logistic Regression -> Accuracy: {lr_acc:.4f}, F1-Score: {lr_f1:.4f}")

    # 2. Primary Model: Random Forest Classifier
    print("\n--- Model 2: Random Forest Classifier (Ensemble) ---")
    rf = RandomForestClassifier(n_estimators=100, max_depth=6, random_state=42)
    rf.fit(X_train, y_train)
    rf_pred = rf.predict(X_test)
    rf_proba = rf.predict_proba(X_test)

    # Compute detailed evaluation metrics
    acc = accuracy_score(y_test, rf_pred)
    prec = precision_score(y_test, rf_pred, zero_division=0)
    rec = recall_score(y_test, rf_pred, zero_division=0)
    f1 = f1_score(y_test, rf_pred, zero_division=0)
    cm = confusion_matrix(y_test, rf_pred).tolist()
    # cm layout: [[TN, FP], [FN, TP]]
    tn, fp, fn, tp = confusion_matrix(y_test, rf_pred).ravel()

    print(f"Accuracy  : {acc:.4f} ({acc*100:.1f}%)")
    print(f"Precision : {prec:.4f}")
    print(f"Recall    : {rec:.4f}")
    print(f"F1-Score  : {f1:.4f}")
    print(f"Confusion Matrix: TN={tn}, FP={fp}, FN={fn}, TP={tp}")
    print("\nClassification Report:\n", classification_report(y_test, rf_pred, target_names=["Legitimate", "Phishing"]))

    # Feature Importances
    importances = rf.feature_importances_
    ranked_features = sorted(zip(FEATURE_NAMES, importances), key=lambda x: x[1], reverse=True)
    print("\nFeature Importances (Random Forest):")
    for name, imp in ranked_features:
        print(f" - {name:25s}: {imp:.4f}")

    # Save model
    model_file = os.path.join(models_dir, "phishing_model.joblib")
    joblib.dump(rf, model_file)
    print(f"\n[+] Saved trained model to: {model_file}")

    # Save metadata and metrics
    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "max_depth": 6,
        "dataset_size": total_samples,
        "train_samples": len(y_train),
        "test_samples": len(y_test),
        "metrics": {
            "accuracy": round(float(acc), 4),
            "precision": round(float(prec), 4),
            "recall": round(float(rec), 4),
            "f1_score": round(float(f1), 4),
            "confusion_matrix": {
                "true_negative": int(tn),
                "false_positive": int(fp),
                "false_negative": int(fn),
                "true_positive": int(tp)
            }
        },
        "baseline_comparison": {
            "logistic_regression_accuracy": round(float(lr_acc), 4),
            "logistic_regression_f1": round(float(lr_f1), 4)
        },
        "feature_importances": {name: round(float(val), 4) for name, val in ranked_features},
        "features": FEATURE_NAMES
    }

    metadata_file = os.path.join(models_dir, "model_metadata.json")
    with open(metadata_file, "w", encoding="utf-8") as f:
        json.dump(metadata, f, indent=2)
    print(f"[+] Saved model metadata and metrics to: {metadata_file}")


if __name__ == "__main__":
    train_and_evaluate()
