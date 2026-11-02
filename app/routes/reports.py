"""
SentinelFlow Reports, Simulator, History & Settings Blueprint
Handles:
- PDF executive report download (ReportLab)
- CSV telemetry export
- Synthetic attack injection simulator
- Prediction audit history & clearing (backward-compatible)
- Project About page (backward-compatible)
- System settings & sensitivity configuration
"""

import os
from flask import (
    Blueprint, render_template, request, redirect,
    url_for, send_file, flash, jsonify, current_app
)
from app.models import db, Prediction, Alert, BlockedIP, AuditLog, SystemSetting
from app.services.report import generate_pdf_report, generate_csv_export
from app.services.simulator import TrafficSimulator
from app.services.detector import SentinelDetector

reports_bp = Blueprint("reports", __name__)

@reports_bp.route("/reports")
def reports_view():
    """Renders the threat reporting hub."""
    from app.routes.dashboard import get_dashboard_summary
    stats = get_dashboard_summary()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(10).all()
    return render_template(
        "reports/index.html",
        stats=stats,
        recent_alerts=[a.to_dict() for a in recent_alerts]
    )

@reports_bp.route("/reports/download/pdf")
def download_pdf():
    """Streams executive PDF report."""
    from app.routes.dashboard import get_dashboard_summary
    stats = get_dashboard_summary()
    recent_alerts = Alert.query.order_by(Alert.created_at.desc()).limit(15).all()

    pdf_buffer = generate_pdf_report(stats, [a.to_dict() for a in recent_alerts])
    return send_file(
        pdf_buffer,
        as_attachment=True,
        download_name=f"SentinelFlow_Threat_Report_{datetime_now_str()}.pdf",
        mimetype="application/pdf"
    )

@reports_bp.route("/reports/download/csv")
def download_csv():
    """Streams CSV file of detection history."""
    records = Prediction.query.order_by(Prediction.timestamp.desc()).limit(5000).all()
    csv_content = generate_csv_export([r.to_dict() for r in records], record_type="predictions")

    import io
    mem = io.BytesIO()
    mem.write(csv_content.encode("utf-8"))
    mem.seek(0)
    return send_file(
        mem,
        as_attachment=True,
        download_name=f"SentinelFlow_Detections_{datetime_now_str()}.csv",
        mimetype="text/csv"
    )

@reports_bp.route("/simulator")
def simulator_view():
    """Renders the Attack Simulator laboratory."""
    return render_template("simulator/index.html")

@reports_bp.route("/api/simulator/inject", methods=["POST"])
def inject_attack():
    """API endpoint to inject synthetic attack packets."""
    attack_type = request.form.get("attack_type", "DoS")
    intensity = int(request.form.get("intensity", 5))

    simulator = TrafficSimulator.get_instance()
    results = simulator.inject_synthetic_attack(
        attack_type=attack_type,
        intensity=intensity,
        app=current_app._get_current_object()
    )

    return jsonify({
        "success": True,
        "attack_type": attack_type,
        "injected_count": len(results),
        "sample": results[0] if results else None
    })

# ================= LEGACY ENDPOINTS PRESERVED =================

@reports_bp.route("/history")
def history():
    """
    Preserved /history route.
    Displays full audit log with search, pagination, and status filters.
    """
    page = request.args.get("page", 1, type=int)
    search_q = request.args.get("q", "").strip()

    query = Prediction.query
    if search_q:
        query = query.filter(
            (Prediction.attack_type.like(f"%{search_q}%")) |
            (Prediction.traffic_status.like(f"%{search_q}%")) |
            (Prediction.threat_level.like(f"%{search_q}%")) |
            (Prediction.source_ip.like(f"%{search_q}%"))
        )

    pagination = query.order_by(Prediction.timestamp.desc()).paginate(page=page, per_page=30, error_out=False)
    
    # Format legacy rows tuple for any legacy template compatibility
    legacy_rows = [
        (p.id, p.attack_type, p.confidence, p.risk_score, p.threat_level, p.traffic_status, p.timestamp.strftime("%Y-%m-%d %H:%M:%S") if p.timestamp else "")
        for p in pagination.items
    ]

    return render_template(
        "history.html",
        rows=legacy_rows,
        predictions=pagination.items,
        pagination=pagination,
        search_query=search_q
    )

@reports_bp.route("/clear_history", methods=["POST"])
def clear_history():
    """
    Preserved /clear_history route.
    Deletes all records from predictions and alerts tables.
    """
    try:
        Alert.query.delete()
        Prediction.query.delete()
        db.session.commit()
        flash("All prediction history and alerts have been purged.", "info")
    except Exception as e:
        db.session.rollback()
        flash(f"Error clearing history: {e}", "danger")

    return redirect(url_for("reports.history"))

@reports_bp.route("/about")
def about():
    """
    Preserved /about route.
    Comprehensive explainer of SentinelFlow, architecture, and NSL-KDD benchmark limitations.
    """
    return render_template("about.html")

@reports_bp.route("/settings", methods=["GET", "POST"])
def settings_view():
    """System settings, sensitivity threshold, webhooks, and data retention."""
    detector = SentinelDetector.get_instance()

    if request.method == "POST":
        sensitivity = request.form.get("sensitivity", 0.60)
        try:
            detector.set_sensitivity(float(sensitivity))
            flash("System detection sensitivity updated successfully.", "success")
        except Exception as e:
            flash(f"Failed to update sensitivity: {e}", "danger")

    return render_template(
        "settings/index.html",
        sensitivity=detector.sensitivity_threshold
    )

def datetime_now_str():
    from datetime import datetime
    return datetime.utcnow().strftime("%Y%m%d_%H%M%S")
