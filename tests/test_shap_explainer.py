"""
Unit tests for SentinelDetector & SHAP Explainer
"""

import pytest
from app.services.detector import SentinelDetector
from app.services.explainer import SentinelExplainer
from app.ml.preprocess import PRESETS

def test_detector_normal_prediction():
    detector = SentinelDetector.get_instance()
    res = detector.predict_one(PRESETS["Normal"])

    assert res["attack_type"] == "Normal"
    assert res["traffic_status"] == "Safe"
    assert res["threat_level"] == "Low"
    assert 0 <= res["confidence"] <= 100
    assert 0 <= res["risk_score"] <= 100
    assert "top_features" in res
    assert len(res["top_features"]) <= 5
    assert isinstance(res["explanation"], str)
    assert len(res["explanation"]) > 10

def test_detector_dos_prediction():
    detector = SentinelDetector.get_instance()
    res = detector.predict_one(PRESETS["DoS"])

    assert res["attack_type"] in ("DoS", "Probe")
    assert res["traffic_status"] in ("Malicious", "Suspicious")
    assert res["risk_score"] > 20
    assert "DoS" in res["class_probabilities"]

def test_shap_explanation_sentence():
    explainer = SentinelExplainer()
    sample_features = [
        {"feature": "serror_rate", "friendly_name": "SYN error rate", "importance": 0.45, "raw_value": 1.0, "impact": "positive"},
        {"feature": "count", "friendly_name": "2-second connection burst count", "importance": 0.32, "raw_value": 250, "impact": "positive"}
    ]
    sentence = explainer._generate_english_sentence("DoS", sample_features, {"serror_rate": 1.0, "count": 250})
    assert "DoS" in sentence or "Denial-of-Service" in sentence
    assert "SYN error rate" in sentence
