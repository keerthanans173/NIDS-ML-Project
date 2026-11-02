"""
SentinelFlow Detection Engine Service
Provides robust multi-class threat prediction, confidence scoring,
risk index calculation, sensitivity thresholding, and SHAP explainability.
Guarantees fallback to ids_model.pkl if the primary pipeline is missing.
"""

import os
import pickle
import logging
import random
import joblib
import numpy as np
import pandas as pd

from app.ml.preprocess import (
    ALL_FEATURES, CAT_FEATURES, CLASS_NAMES,
    DEFAULT_FEATURE_VALUES, SentinelDataPipeline
)
from app.services.explainer import SentinelExplainer

logger = logging.getLogger("sentinel.services.detector")

BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
PRIMARY_MODEL_PATH = os.path.join(BASE_DIR, "app", "ml", "sentinel_pipeline.joblib")
FALLBACK_MODEL_PATH = os.path.join(BASE_DIR, "ids_model.pkl")

# Risk weighting table per attack category
CATEGORY_RISK_WEIGHTS = {
    "Normal": 0.05,
    "Probe": 0.55,
    "DoS": 0.85,
    "R2L": 0.90,
    "U2R": 1.00
}

class SentinelDetector:
    _instance = None

    def __init__(self):
        self.pipeline = None
        self.model = None
        self.model_name = "Unknown"
        self.iso_forest = None
        self.explainer = None
        self.is_fallback = False
        self.sensitivity_threshold = 0.60  # Default: if Normal < 60%, flag attack
        self.load_model()

    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = SentinelDetector()
        return cls._instance

    def set_sensitivity(self, sensitivity: float):
        """Sets the attack decision threshold (0.10 to 0.90)."""
        self.sensitivity_threshold = max(0.10, min(0.95, float(sensitivity)))
        logger.info(f"Detector sensitivity threshold updated to: {self.sensitivity_threshold:.2f}")

    def load_model(self):
        """Loads primary pipeline or gracefully falls back to legacy pickle."""
        if os.path.exists(PRIMARY_MODEL_PATH):
            try:
                bundle = joblib.load(PRIMARY_MODEL_PATH)
                self.model = bundle["model"]
                self.model_name = bundle.get("model_name", "XGBoost")
                self.pipeline = bundle["pipeline"]
                self.iso_forest = bundle.get("isolation_forest")
                raw_explainer = bundle.get("explainer")
                self.explainer = SentinelExplainer(
                    explainer=raw_explainer,
                    model=self.model,
                    feature_names=bundle.get("feature_names", ALL_FEATURES)
                )
                self.is_fallback = False
                logger.info(f"Loaded primary SentinelFlow pipeline: {self.model_name}")
                return
            except Exception as e:
                logger.error(f"Failed to load primary pipeline: {e}. Attempting fallback...")

        # Fallback to ids_model.pkl
        if os.path.exists(FALLBACK_MODEL_PATH):
            try:
                with open(FALLBACK_MODEL_PATH, "rb") as f:
                    bundle = pickle.load(f)
                self.model = bundle["model"]
                self.model_name = "Random Forest (Fallback)"
                # Construct compatibility wrapper
                self.pipeline = SentinelDataPipeline()
                self.pipeline.scaler = bundle["scaler"]
                self.pipeline.encoders = bundle["encoders"]
                self.pipeline.target_encoder = bundle["target_encoder"]
                self.explainer = SentinelExplainer(explainer=None, model=self.model)
                self.is_fallback = True
                logger.warning("Loaded fallback model: ids_model.pkl")
                return
            except Exception as e:
                logger.critical(f"Failed to load fallback model: {e}")

        raise RuntimeError("No model bundle found! Run 'python app/ml/train.py' first.")

    def predict_one(self, input_dict: dict, source_ip: str = None) -> dict:
        """
        Runs comprehensive prediction and explainability on a single record dictionary.
        Returns complete analysis: attack_type, confidence, risk_score,
        threat_level, traffic_status, class_probabilities, and SHAP explanation.
        """
        # Clean inputs with defaults
        clean_inputs = {}
        for feat in ALL_FEATURES:
            val = input_dict.get(feat, DEFAULT_FEATURE_VALUES.get(feat, 0))
            if feat in CAT_FEATURES:
                clean_inputs[feat] = str(val).strip().lower()
            else:
                try:
                    clean_inputs[feat] = float(val)
                except (ValueError, TypeError):
                    clean_inputs[feat] = float(DEFAULT_FEATURE_VALUES.get(feat, 0.0))

        # Scale features
        X_scaled = self.pipeline.transform_single(clean_inputs)

        # Predict probabilities
        if hasattr(self.model, "predict_proba"):
            probs = self.model.predict_proba(X_scaled)[0]
        else:
            probs = np.array([0.2] * len(CLASS_NAMES))

        # Map class probabilities
        target_classes = getattr(self.pipeline.target_encoder, "classes_", CLASS_NAMES)
        prob_dict = {cls_name: float(probs[i]) for i, cls_name in enumerate(target_classes)}

        # Ensure all standard classes exist
        for c in CLASS_NAMES:
            if c not in prob_dict:
                prob_dict[c] = 0.0

        normal_prob = prob_dict.get("Normal", 0.0)

        # Decision threshold evaluation
        if normal_prob < self.sensitivity_threshold:
            # Threat detected: select highest attack class
            attack_candidates = {k: v for k, v in prob_dict.items() if k != "Normal"}
            if attack_candidates:
                attack_type = max(attack_candidates, key=attack_candidates.get)
                confidence = round(attack_candidates[attack_type] * 100.0, 2)
            else:
                attack_type = "DoS"
                confidence = round((1.0 - normal_prob) * 100.0, 2)
        else:
            attack_type = "Normal"
            confidence = round(normal_prob * 100.0, 2)

        # Anomaly scoring via Isolation Forest
        anomaly_factor = 1.0
        if self.iso_forest is not None:
            try:
                # Returns -1 for anomaly, 1 for inlier
                iso_score = self.iso_forest.decision_function(X_scaled)[0]
                # Lower decision score = more anomalous
                anomaly_factor = max(0.8, min(1.3, 1.0 - iso_score))
            except Exception:
                anomaly_factor = 1.0

        # Calculate risk score (0-100)
        base_cat_weight = CATEGORY_RISK_WEIGHTS.get(attack_type, 0.5)
        if attack_type == "Normal":
            # Very low risk for normal, slightly scaled if normal probability was near borderline
            raw_risk = (1.0 - normal_prob) * 20.0
        else:
            raw_risk = (base_cat_weight * 70.0) + (confidence * 0.30)
            raw_risk *= anomaly_factor

        risk_score = round(max(0.0, min(100.0, raw_risk)), 1)

        # Threat level & traffic status categorization
        if attack_type == "Normal":
            threat_level = "Low"
            traffic_status = "Safe"
        elif attack_type == "U2R":
            threat_level = "Critical"
            traffic_status = "Malicious"
        elif attack_type in ("DoS", "R2L"):
            threat_level = "High" if risk_score >= 60 else "Medium"
            traffic_status = "Malicious"
        else:  # Probe
            threat_level = "Medium" if risk_score >= 40 else "Low"
            traffic_status = "Suspicious"

        # Generate realistic simulated IP if not provided
        if not source_ip:
            if attack_type == "Normal":
                source_ip = f"192.168.1.{random.randint(10, 80)}"
            elif attack_type == "DoS":
                source_ip = f"45.142.{random.randint(10, 250)}.{random.randint(1, 254)}"
            elif attack_type == "Probe":
                source_ip = f"185.220.{random.randint(100, 150)}.{random.randint(1, 254)}"
            elif attack_type == "R2L":
                source_ip = f"103.251.{random.randint(10, 90)}.{random.randint(1, 254)}"
            else: # U2R
                source_ip = f"192.168.1.{random.randint(150, 220)}"

        # Compute SHAP explanation
        class_idx = list(target_classes).index(attack_type) if attack_type in target_classes else 0
        explanation_data = self.explainer.explain_instance(
            X_scaled=X_scaled,
            raw_features=clean_inputs,
            predicted_class=attack_type,
            class_idx=class_idx
        )

        return {
            "attack_type": attack_type,
            "confidence": confidence,
            "risk_score": risk_score,
            "threat_level": threat_level,
            "traffic_status": traffic_status,
            "source_ip": source_ip,
            "class_probabilities": {k: round(v * 100.0, 1) for k, v in prob_dict.items()},
            "top_features": explanation_data["top_features"],
            "explanation": explanation_data["plain_english"],
            "raw_inputs": clean_inputs,
            "is_fallback": self.is_fallback,
            "model_name": self.model_name
        }
