"""
SentinelFlow ML Training & Model Selection Engine
Trains and benchmarks Random Forest, XGBoost, and Isolation Forest on NSL-KDD.
Selects best performing model by macro-F1 on KDDTest+, computes SHAP background
summaries, and serializes the complete pipeline into sentinel_pipeline.joblib.
"""

import os
import sys
import time
import logging
import json
import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.utils import resample
import xgboost as xgb
import shap

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app.ml.preprocess import (
    ALL_FEATURES, CAT_FEATURES, CLASS_NAMES,
    map_raw_label, SentinelDataPipeline
)
from app.ml.evaluate import evaluate_model, save_metrics

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("sentinel.ml.train")

RAW_COLUMNS = ALL_FEATURES + ["label", "difficulty"]

def load_and_prep_data(train_path: str, test_path: str):
    """Loads NSL-KDD train and test datasets with 5-class mapping."""
    logger.info(f"Loading train set from {train_path}...")
    train_df = pd.read_csv(train_path, header=None, names=RAW_COLUMNS, low_memory=False)
    test_df = pd.read_csv(test_path, header=None, names=RAW_COLUMNS, low_memory=False)

    # Filter out any header rows if present
    train_df = train_df[train_df["duration"] != "duration"].reset_index(drop=True)
    test_df = test_df[test_df["duration"] != "duration"].reset_index(drop=True)

    # Drop difficulty score
    train_df.drop("difficulty", axis=1, inplace=True, errors="ignore")
    test_df.drop("difficulty", axis=1, inplace=True, errors="ignore")

    # Map labels to 5 categories
    train_df["label"] = train_df["label"].apply(map_raw_label)
    test_df["label"] = test_df["label"].apply(map_raw_label)

    logger.info(f"Loaded {len(train_df)} train records, {len(test_df)} test records.")
    logger.info(f"Train class distribution:\n{train_df['label'].value_counts().to_dict()}")
    return train_df, test_df

def balance_dataset(train_df: pd.DataFrame, min_samples: int = 4000, max_samples: int = 30000) -> pd.DataFrame:
    """
    Balances minority classes (especially U2R and R2L) and caps massive classes
    to prevent majority class domination while maintaining high variance.
    """
    balanced_groups = []
    for label, group in train_df.groupby("label"):
        n_samples = len(group)
        if n_samples < min_samples:
            # Oversample minority (U2R, R2L)
            group = resample(group, replace=True, n_samples=min_samples, random_state=42)
        elif n_samples > max_samples:
            # Undersample dominant majority to accelerate training without loss of diversity
            group = resample(group, replace=False, n_samples=max_samples, random_state=42)
        balanced_groups.append(group)
    
    balanced = pd.concat(balanced_groups).sample(frac=1, random_state=42).reset_index(drop=True)
    logger.info(f"Balanced train dataset: {len(balanced)} rows.")
    return balanced

def train_and_evaluate_all(train_path: str = None, test_path: str = None, output_dir: str = None):
    """
    Runs full training workflow:
    1. Preprocesses train & test with unified SentinelDataPipeline
    2. Trains Random Forest and XGBoost
    3. Trains Isolation Forest for anomaly boundary scoring
    4. Evaluates on KDDTest+ and selects best classifier by macro-F1
    5. Computes SHAP explainer baseline
    6. Saves sentinel_pipeline.joblib and metrics.json
    """
    if train_path is None:
        train_path = os.path.join(BASE_DIR, "data", "KDDTrain+.txt")
    if test_path is None:
        test_path = os.path.join(BASE_DIR, "data", "KDDTest+.txt")
    if output_dir is None:
        output_dir = os.path.join(BASE_DIR, "app", "ml")

    train_df, test_df = load_and_prep_data(train_path, test_path)
    train_balanced = balance_dataset(train_df)

    # Build and fit preprocessing pipeline
    logger.info("Fitting unified SentinelDataPipeline...")
    pipeline = SentinelDataPipeline()
    pipeline.fit(train_balanced[ALL_FEATURES], train_balanced["label"])

    X_train = pipeline.transform_df(train_balanced[ALL_FEATURES])
    y_train = pipeline.target_encoder.transform(train_balanced["label"])

    X_test = pipeline.transform_df(test_df[ALL_FEATURES])
    y_test = pipeline.target_encoder.transform(test_df["label"])

    # 1. Train Random Forest
    logger.info("Training Random Forest Classifier (balanced weights)...")
    rf_start = time.time()
    rf_model = RandomForestClassifier(
        n_estimators=180,
        max_depth=20,
        min_samples_split=4,
        min_samples_leaf=2,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    )
    rf_model.fit(X_train, y_train)
    rf_duration = time.time() - rf_start
    logger.info(f"Random Forest trained in {rf_duration:.1f}s.")

    logger.info("Evaluating Random Forest on test set...")
    rf_metrics = evaluate_model(rf_model, X_test, y_test, CLASS_NAMES)
    rf_metrics["training_time_seconds"] = round(rf_duration, 2)
    logger.info(f"Random Forest Accuracy: {rf_metrics['accuracy']*100:.2f}%, Macro-F1: {rf_metrics['macro_f1']:.4f}")

    # 2. Train XGBoost
    logger.info("Training XGBoost Classifier...")
    xgb_start = time.time()
    xgb_model = xgb.XGBClassifier(
        n_estimators=140,
        max_depth=6,
        learning_rate=0.1,
        subsample=0.8,
        colsample_bytree=0.8,
        random_state=42,
        n_jobs=-1,
        eval_metric="mlogloss"
    )
    xgb_model.fit(X_train, y_train)
    xgb_duration = time.time() - xgb_start
    logger.info(f"XGBoost trained in {xgb_duration:.1f}s.")

    logger.info("Evaluating XGBoost on test set...")
    xgb_metrics = evaluate_model(xgb_model, X_test, y_test, CLASS_NAMES)
    xgb_metrics["training_time_seconds"] = round(xgb_duration, 2)
    logger.info(f"XGBoost Accuracy: {xgb_metrics['accuracy']*100:.2f}%, Macro-F1: {xgb_metrics['macro_f1']:.4f}")

    # 3. Train Anomaly Model (Isolation Forest)
    logger.info("Training Isolation Forest Anomaly Detector...")
    normal_idx = np.where(y_train == pipeline.target_encoder.transform(["Normal"])[0])[0]
    iso_start = time.time()
    iso_model = IsolationForest(
        n_estimators=100,
        contamination=0.10,
        random_state=42,
        n_jobs=-1
    )
    iso_model.fit(X_train[normal_idx])
    iso_duration = time.time() - iso_start
    logger.info(f"Isolation Forest trained in {iso_duration:.1f}s.")

    # Model Selection: Best by macro-F1
    comparison = {
        "Random Forest": {
            "accuracy": rf_metrics["accuracy"],
            "macro_f1": rf_metrics["macro_f1"],
            "weighted_f1": rf_metrics["weighted_f1"],
            "macro_precision": rf_metrics["macro_precision"],
            "macro_recall": rf_metrics["macro_recall"],
            "roc_auc": rf_metrics["roc_auc"],
            "training_time": rf_metrics["training_time_seconds"]
        },
        "XGBoost": {
            "accuracy": xgb_metrics["accuracy"],
            "macro_f1": xgb_metrics["macro_f1"],
            "weighted_f1": xgb_metrics["weighted_f1"],
            "macro_precision": xgb_metrics["macro_precision"],
            "macro_recall": xgb_metrics["macro_recall"],
            "roc_auc": xgb_metrics["roc_auc"],
            "training_time": xgb_metrics["training_time_seconds"]
        }
    }

    if xgb_metrics["macro_f1"] >= rf_metrics["macro_f1"]:
        best_name = "XGBoost"
        best_model = xgb_model
        best_metrics = xgb_metrics
    else:
        best_name = "Random Forest"
        best_model = rf_model
        best_metrics = rf_metrics

    logger.info(f"Selected Best Model: {best_name} (Macro-F1: {best_metrics['macro_f1']:.4f})")

    # Feature Importance
    if hasattr(best_model, "feature_importances_"):
        importances = best_model.feature_importances_
        feature_importance_dict = {
            feat: round(float(imp), 5) for feat, imp in zip(ALL_FEATURES, importances)
        }
        sorted_importance = sorted(feature_importance_dict.items(), key=lambda x: x[1], reverse=True)
    else:
        sorted_importance = []

    # Initialize SHAP Explainer
    logger.info("Initializing SHAP TreeExplainer with background sample...")
    background_sample = shap.sample(X_train, 100, random_state=42)
    try:
        explainer = shap.TreeExplainer(best_model, background_sample)
        logger.info("SHAP TreeExplainer initialized successfully.")
    except Exception as e:
        logger.warning(f"Could not build TreeExplainer: {e}. Using fast feature contribution fallback.")
        explainer = None

    # Save comprehensive metrics.json
    final_metrics_payload = {
        "selected_model": best_name,
        "models_compared": comparison,
        "best_metrics": best_metrics,
        "feature_importance": [{"feature": k, "score": v} for k, v in sorted_importance[:15]],
        "dataset_info": {
            "train_samples": len(train_df),
            "test_samples": len(test_df),
            "feature_count": len(ALL_FEATURES),
            "classes": CLASS_NAMES
        },
        "updated_at": time.strftime("%Y-%m-%d %H:%M:%S")
    }

    metrics_file = os.path.join(output_dir, "metrics.json")
    save_metrics(final_metrics_payload, metrics_file)
    logger.info(f"Metrics saved to {metrics_file}")

    # Save complete unified pipeline bundle
    bundle = {
        "model_name": best_name,
        "model": best_model,
        "isolation_forest": iso_model,
        "pipeline": pipeline,
        "feature_names": ALL_FEATURES,
        "cat_features": CAT_FEATURES,
        "class_names": CLASS_NAMES,
        "target_encoder": pipeline.target_encoder,
        "scaler": pipeline.scaler,
        "encoders": pipeline.encoders,
        "explainer": explainer,
        "background_sample": background_sample,
        "feature_importance": sorted_importance,
        "metrics": best_metrics
    }

    bundle_path = os.path.join(output_dir, "sentinel_pipeline.joblib")
    joblib.dump(bundle, bundle_path, compress=3)
    logger.info(f"Unified SentinelFlow pipeline saved to {bundle_path} ({os.path.getsize(bundle_path) / (1024*1024):.1f} MB)")

    return bundle, final_metrics_payload

if __name__ == "__main__":
    train_and_evaluate_all()
