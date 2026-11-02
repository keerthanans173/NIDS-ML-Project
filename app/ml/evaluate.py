"""
SentinelFlow Model Evaluation Suite
Computes multi-class classification metrics on KDDTest+ or validation splits:
- Accuracy, Macro-F1, Weighted-F1
- Per-class Precision, Recall, F1-score, Support
- Confusion matrix (both raw counts and normalized percentages)
- Multi-class ROC-AUC (OVR) and ROC curve coordinate series for UI rendering
"""

import json
import os
import numpy as np
from sklearn.metrics import (
    accuracy_score, precision_recall_fscore_support,
    confusion_matrix, roc_auc_score, roc_curve
)

def evaluate_model(model, X_test, y_test, class_names):
    """
    Evaluates classifier predictions and probabilities against ground truth.
    Returns a comprehensive metrics dictionary suitable for JSON serialization.
    """
    y_pred = model.predict(X_test)
    
    # Probabilities
    if hasattr(model, "predict_proba"):
        y_prob = model.predict_proba(X_test)
    elif hasattr(model, "decision_function"):
        df = model.decision_function(X_test)
        if df.ndim == 1:
            y_prob = np.vstack([1 - df, df]).T
        else:
            exp_df = np.exp(df - np.max(df, axis=1, keepdims=True))
            y_prob = exp_df / np.sum(exp_df, axis=1, keepdims=True)
    else:
        y_prob = None

    # Overall metrics
    accuracy = float(accuracy_score(y_test, y_pred))
    p_macro, r_macro, f1_macro, _ = precision_recall_fscore_support(y_test, y_pred, average="macro", zero_division=0)
    p_weight, r_weight, f1_weight, _ = precision_recall_fscore_support(y_test, y_pred, average="weighted", zero_division=0)
    
    # Per-class metrics
    p_class, r_class, f1_class, support_class = precision_recall_fscore_support(
        y_test, y_pred, labels=range(len(class_names)), zero_division=0
    )
    
    per_class = {}
    for i, c_name in enumerate(class_names):
        per_class[c_name] = {
            "precision": round(float(p_class[i]), 4),
            "recall": round(float(r_class[i]), 4),
            "f1": round(float(f1_class[i]), 4),
            "support": int(support_class[i])
        }

    # Confusion Matrix
    cm = confusion_matrix(y_test, y_pred, labels=range(len(class_names)))
    cm_norm = cm.astype('float') / (cm.sum(axis=1)[:, np.newaxis] + 1e-9)
    
    # ROC-AUC (OVR)
    roc_auc_val = 0.0
    roc_curves = {}
    if y_prob is not None:
        try:
            # One-hot encode y_test
            n_classes = len(class_names)
            y_test_oh = np.eye(n_classes)[y_test]
            roc_auc_val = float(roc_auc_score(y_test_oh, y_prob, multi_class="ovr", average="macro"))
            
            # Extract sample ROC points for UI visualization (sampled down to 25 points per class)
            for i, c_name in enumerate(class_names):
                fpr, tpr, _ = roc_curve(y_test_oh[:, i], y_prob[:, i])
                step = max(1, len(fpr) // 25)
                sampled_fpr = [round(float(x), 3) for x in fpr[::step]]
                sampled_tpr = [round(float(x), 3) for x in tpr[::step]]
                if sampled_fpr[-1] != 1.0:
                    sampled_fpr.append(1.0)
                    sampled_tpr.append(1.0)
                roc_curves[c_name] = {"fpr": sampled_fpr, "tpr": sampled_tpr}
        except Exception:
            roc_auc_val = 0.0

    return {
        "accuracy": round(accuracy, 4),
        "macro_f1": round(float(f1_macro), 4),
        "weighted_f1": round(float(f1_weight), 4),
        "macro_precision": round(float(p_macro), 4),
        "macro_recall": round(float(r_macro), 4),
        "roc_auc": round(roc_auc_val, 4),
        "per_class": per_class,
        "confusion_matrix": cm.tolist(),
        "confusion_matrix_norm": [[round(float(x), 4) for x in row] for row in cm_norm.tolist()],
        "class_names": class_names,
        "roc_curves": roc_curves
    }

def save_metrics(metrics: dict, output_path: str):
    """Saves metrics dictionary to a JSON file."""
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
