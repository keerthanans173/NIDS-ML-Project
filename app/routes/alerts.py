"""
SentinelFlow Incident Response & Alerts Blueprint
Provides alert triage, analyst workflow notes, SHAP feature waterfalls,
and simulated IP mitigation with firewall command generation.
"""

from datetime import datetime, timedelta
import json
from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from app.models import db, Alert, BlockedIP, AuditLog

alerts_bp = Blueprint("alerts", __name__)

@alerts_bp.route("/alerts")
def alerts_view():
    """Renders the comprehensive security alerts center."""
    severity_filter = request.args.get("severity")
    status_filter = request.args.get("status")
    query_search = request.args.get("q", "").strip()

    query = Alert.query

    if severity_filter and severity_filter != "all":
        query = query.filter_by(severity=severity_filter)
    if status_filter and status_filter != "all":
        query = query.filter_by(status=status_filter)
    if query_search:
        query = query.filter(
            (Alert.source_ip.like(f"%{query_search}%")) |
            (Alert.attack_type.like(f"%{query_search}%")) |
            (Alert.explanation.like(f"%{query_search}%"))
        )

    alerts = query.order_by(Alert.created_at.desc()).limit(100).all()
    blocked_ips = BlockedIP.query.order_by(BlockedIP.blocked_at.desc()).limit(20).all()

    # Statistics
    total_alerts = Alert.query.count()
    new_alerts = Alert.query.filter_by(status="New").count()
    investigating = Alert.query.filter_by(status="Investigating").count()
    resolved = Alert.query.filter_by(status="Resolved").count()

    return render_template(
        "alerts/index.html",
        alerts=[a.to_dict() for a in alerts],
        blocked_ips=[b.to_dict() for b in blocked_ips],
        counts={
            "total": total_alerts,
            "new": new_alerts,
            "investigating": investigating,
            "resolved": resolved
        },
        current_severity=severity_filter or "all",
        current_status=status_filter or "all",
        search_query=query_search
    )

@alerts_bp.route("/api/alerts/<int:alert_id>")
def get_alert_detail(alert_id):
    """Returns single alert detail including top SHAP features for modal rendering."""
    alert = Alert.query.get_or_404(alert_id)
    alert_dict = alert.to_dict()

    # Parse top features json if available
    top_features = []
    if alert.top_features_json:
        try:
            top_features = json.loads(alert.top_features_json)
        except Exception:
            try:
                import ast
                top_features = ast.literal_eval(alert.top_features_json)
            except Exception:
                top_features = []
    alert_dict["parsed_features"] = top_features
    return jsonify(alert_dict)

@alerts_bp.route("/api/alerts/<int:alert_id>/status", methods=["POST"])
def update_alert_status(alert_id):
    """Updates triage status and analyst notes."""
    alert = Alert.query.get_or_404(alert_id)
    new_status = request.form.get("status") or request.json.get("status")
    notes = request.form.get("notes") or request.json.get("notes")

    if new_status in ("New", "Investigating", "Resolved", "False Positive"):
        alert.status = new_status
        if new_status in ("Resolved", "False Positive"):
            alert.resolved_at = datetime.utcnow()

    if notes is not None:
        alert.analyst_notes = notes

    log = AuditLog(
        username="Analyst",
        action="Alert Triage Updated",
        details=f"Alert #{alert.id} status changed to {new_status}"
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({"success": True, "alert": alert.to_dict()})

@alerts_bp.route("/api/alerts/block-ip", methods=["POST"])
def block_ip_action():
    """
    Simulates IP block mitigation action.
    Generates exact firewall command and sets expiration window.
    """
    data = request.get_json() if request.is_json else request.form.to_dict()
    ip = data.get("ip_address", "").strip()
    reason = data.get("reason", "Malicious network pattern detected")
    attack_type = data.get("attack_type", "DoS")
    hours = int(data.get("duration_hours", 24))

    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    expires_at = datetime.utcnow() + timedelta(hours=hours)

    # Formulate production-ready commands (both iptables and Windows netsh)
    iptables_cmd = f"sudo iptables -A INPUT -s {ip} -j DROP -m comment --comment 'SentinelFlow:{attack_type}'"
    netsh_cmd = f'netsh advfirewall firewall add rule name="SentinelFlow-Block-{ip}" dir=in action=block remoteip={ip}'
    combined_cmd = f"# Linux (iptables):\n{iptables_cmd}\n\n# Windows (netsh):\n{netsh_cmd}"

    blocked = BlockedIP.query.filter_by(ip_address=ip).first()
    if not blocked:
        blocked = BlockedIP(
            ip_address=ip,
            attack_type=attack_type,
            reason=reason,
            expires_at=expires_at,
            status="Active",
            simulated=True,
            command_run=combined_cmd
        )
        db.session.add(blocked)
    else:
        blocked.status = "Active"
        blocked.expires_at = expires_at
        blocked.reason = reason
        blocked.command_run = combined_cmd

    log = AuditLog(
        username="Analyst",
        action="IP Mitigated (Simulated)",
        details=f"Blocked {ip} for {hours}h ({attack_type})"
    )
    db.session.add(log)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": f"IP {ip} added to simulated blocklist.",
        "blocked_ip": blocked.to_dict(),
        "command": combined_cmd
    })

@alerts_bp.route("/api/alerts/unblock-ip/<int:blocked_id>", methods=["POST"])
def unblock_ip_action(blocked_id):
    """Revokes a blocked IP rule."""
    blocked = BlockedIP.query.get_or_404(blocked_id)
    blocked.status = "Revoked"
    log = AuditLog(
        username="Analyst",
        action="IP Unblocked",
        details=f"Rule revoked for {blocked.ip_address}"
    )
    db.session.add(log)
    db.session.commit()
    return jsonify({"success": True, "message": f"Rule revoked for {blocked.ip_address}."})
