"""
SentinelFlow Detection Blueprint
Serves the multi-mode detection studio:
1. Manual form (grouped fields, presets, tooltips, beginner/expert modes)
2. CSV batch upload with downloadable results table
3. Live Replay stream runner (1x, 5x, 10x)
4. Experimental live packet capture interface
Preserves full backward compatibility for POST /predict.
"""

import os
import io
import csv
import json
import pandas as pd
from flask import (
    Blueprint, render_template, request, jsonify,
    redirect, url_for, current_app, send_file, flash
)
from app.models import db, Prediction, Alert, AuditLog
from app.services.detector import SentinelDetector
from app.services.simulator import TrafficSimulator
from app.ml.preprocess import (
    ALL_FEATURES, CAT_FEATURES, FEATURE_GROUPS,
    FEATURE_METADATA, DEFAULT_FEATURE_VALUES, PRESETS
)

detect_bp = Blueprint("detect", __name__)

@detect_bp.route("/")
@detect_bp.route("/detect")
def detect_view():
    """Renders the comprehensive multi-mode detection studio."""
    return render_template(
        "detect/index.html",
        feature_groups=FEATURE_GROUPS,
        feature_metadata=FEATURE_METADATA,
        all_features=ALL_FEATURES,
        cat_features=CAT_FEATURES,
        presets=PRESETS,
        default_values=DEFAULT_FEATURE_VALUES
    )

@detect_bp.route("/predict", methods=["POST"])
def predict():
    """
    Primary prediction endpoint.
    Preserves exact backward-compatible inputs from forms and JSON requests.
    Inserts prediction record into SQLite and triggers an alert if malicious.
    """
    try:
        detector = SentinelDetector.get_instance()
        input_data = {}

        # Handle JSON or Form-encoded
        if request.is_json:
            raw_payload = request.get_json() or {}
        else:
            raw_payload = request.form.to_dict()

        for feature in ALL_FEATURES:
            val = raw_payload.get(feature, DEFAULT_FEATURE_VALUES.get(feature, 0))
            if feature in CAT_FEATURES:
                input_data[feature] = str(val).strip().lower()
            else:
                try:
                    input_data[feature] = float(val)
                except (ValueError, TypeError):
                    input_data[feature] = float(DEFAULT_FEATURE_VALUES.get(feature, 0.0))

        # Perform detection & SHAP explanation
        source_ip = raw_payload.get("source_ip")
        result = detector.predict_one(input_data, source_ip=source_ip)

        # Persist to database
        pred = Prediction(
            attack_type=result["attack_type"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            threat_level=result["threat_level"],
            traffic_status=result["traffic_status"],
            protocol_type=str(input_data.get("protocol_type", "tcp")),
            service=str(input_data.get("service", "http")),
            flag=str(input_data.get("flag", "SF")),
            src_bytes=float(input_data.get("src_bytes", 0)),
            dst_bytes=float(input_data.get("dst_bytes", 0)),
            count=int(input_data.get("count", 1)),
            serror_rate=float(input_data.get("serror_rate", 0)),
            source_ip=result["source_ip"],
            is_flagged=(result["attack_type"] != "Normal")
        )
        db.session.add(pred)
        db.session.flush()

        # Create alert if attack detected
        if result["attack_type"] != "Normal":
            alert = Alert(
                prediction_id=pred.id,
                attack_type=result["attack_type"],
                severity=result["threat_level"],
                risk_score=result["risk_score"],
                confidence=result["confidence"],
                source_ip=result["source_ip"],
                status="New",
                summary=f"{result['threat_level']} risk {result['attack_type']} detection",
                explanation=result["explanation"],
                top_features_json=json.dumps(result["top_features"])
            )
            db.session.add(alert)

        db.session.commit()

        # Emit socketio event if configured
        socketio = current_app.extensions.get("socketio")
        if socketio:
            socketio.emit("traffic_packet", {
                "id": pred.id,
                "attack_type": result["attack_type"],
                "confidence": result["confidence"],
                "risk_score": result["risk_score"],
                "threat_level": result["threat_level"],
                "traffic_status": result["traffic_status"],
                "source_ip": result["source_ip"],
                "protocol": input_data.get("protocol_type"),
                "service": input_data.get("service"),
                "flag": input_data.get("flag"),
                "timestamp": pred.timestamp.strftime("%H:%M:%S") if pred.timestamp else "",
                "explanation": result["explanation"],
                "is_simulated": False
            })

        # Return JSON if requested
        if request.is_json or request.headers.get("Accept") == "application/json":
            return jsonify({
                "id": pred.id,
                "prediction": result["attack_type"],
                "confidence": result["confidence"],
                "risk_score": result["risk_score"],
                "threat_level": result["threat_level"],
                "traffic_status": result["traffic_status"],
                "source_ip": result["source_ip"],
                "class_probabilities": result["class_probabilities"],
                "top_features": result["top_features"],
                "explanation": result["explanation"]
            })

        # Otherwise render result.html (100% backward compatible template variables)
        return render_template(
            "result.html",
            prediction=result["attack_type"],
            confidence=result["confidence"],
            risk_score=result["risk_score"],
            threat_level=result["threat_level"],
            traffic_status=result["traffic_status"],
            source_ip=result["source_ip"],
            top_features=result["top_features"],
            explanation=result["explanation"],
            class_probabilities=result["class_probabilities"]
        )

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Prediction failed: {e}")
        if request.is_json:
            return jsonify({"error": str(e)}), 500
        return f"<h2>Error: {str(e)}</h2><a href='/'>Go Back</a>", 500

@detect_bp.route("/detect/batch", methods=["POST"])
def batch_detect():
    """Handles CSV batch upload analysis."""
    if "file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400

    file = request.files["file"]
    if file.filename == "":
        return jsonify({"error": "Empty filename"}), 400

    try:
        stream = io.StringIO(file.stream.read().decode("UTF8"), newline=None)
        df = pd.read_csv(stream)
        detector = SentinelDetector.get_instance()

        batch_results = []
        threat_count = 0

        # Process up to 500 records per batch for responsiveness
        max_rows = min(500, len(df))
        for i in range(max_rows):
            row_dict = df.iloc[i].to_dict()
            res = detector.predict_one(row_dict)
            if res["attack_type"] != "Normal":
                threat_count += 1
            batch_results.append({
                "row_index": i + 1,
                "attack_type": res["attack_type"],
                "confidence": res["confidence"],
                "risk_score": res["risk_score"],
                "threat_level": res["threat_level"],
                "traffic_status": res["traffic_status"],
                "source_ip": res["source_ip"],
                "top_feature": res["top_features"][0]["friendly_name"] if res["top_features"] else "N/A"
            })

        return jsonify({
            "total_records": len(batch_results),
            "threats_detected": threat_count,
            "threat_percentage": round((threat_count / len(batch_results)) * 100, 1),
            "results": batch_results
        })

    except Exception as e:
        return jsonify({"error": f"Failed to process CSV: {str(e)}"}), 500

@detect_bp.route("/detect/presets/<preset_name>")
def get_preset(preset_name):
    """Returns prefilled preset features for quick form population."""
    preset = PRESETS.get(preset_name)
    if not preset:
        return jsonify({"error": "Preset not found"}), 404
    return jsonify(preset)

@detect_bp.route("/detect/stream/<action>", methods=["POST"])
def stream_control(action):
    """Controls the simulated live traffic replay."""
    simulator = TrafficSimulator.get_instance()
    if action == "start":
        speed = float(request.form.get("speed", 1.0))
        success = simulator.start_replay(speed=speed, app=current_app._get_current_object())
        return jsonify({"status": "running" if success else "error", "speed": speed})
    elif action == "stop":
        simulator.stop_replay()
        return jsonify({"status": "stopped"})
    elif action == "speed":
        speed = float(request.form.get("speed", 1.0))
        simulator.set_speed(speed)
        return jsonify({"status": "updated", "speed": speed})
    return jsonify({"error": "Invalid action"}), 400
