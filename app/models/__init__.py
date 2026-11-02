"""
SentinelFlow SQLAlchemy Database Models
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    role = db.Column(db.String(20), default="Analyst", nullable=False)  # Admin, Analyst, Viewer
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password: str):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password: str) -> bool:
        return check_password_hash(self.password_hash, password)

    def is_admin(self) -> bool:
        return self.role == "Admin"

    def can_edit(self) -> bool:
        return self.role in ("Admin", "Analyst")

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "role": self.role,
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else None
        }


class Prediction(db.Model):
    __tablename__ = "predictions"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    attack_type = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    risk_score = db.Column(db.Float, nullable=False)
    threat_level = db.Column(db.String(20), nullable=False)   # Critical, High, Medium, Low
    traffic_status = db.Column(db.String(30), nullable=False) # Malicious, Suspicious, Safe
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    # Core network telemetry fields
    protocol_type = db.Column(db.String(10), default="tcp")
    service = db.Column(db.String(30), default="http")
    flag = db.Column(db.String(10), default="SF")
    src_bytes = db.Column(db.Float, default=0.0)
    dst_bytes = db.Column(db.Float, default=0.0)
    count = db.Column(db.Integer, default=1)
    serror_rate = db.Column(db.Float, default=0.0)
    source_ip = db.Column(db.String(45), default="192.168.1.105")

    # Workflow tracking
    is_flagged = db.Column(db.Boolean, default=False)
    analyst_status = db.Column(db.String(30), default="New") # New, Investigating, Resolved, False Positive
    analyst_notes = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "attack_type": self.attack_type,
            "confidence": self.confidence,
            "risk_score": self.risk_score,
            "threat_level": self.threat_level,
            "traffic_status": self.traffic_status,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else "",
            "protocol_type": self.protocol_type,
            "service": self.service,
            "flag": self.flag,
            "src_bytes": self.src_bytes,
            "dst_bytes": self.dst_bytes,
            "count": self.count,
            "serror_rate": self.serror_rate,
            "source_ip": self.source_ip,
            "analyst_status": self.analyst_status,
            "analyst_notes": self.analyst_notes or ""
        }


class Alert(db.Model):
    __tablename__ = "alerts"

    id = db.Column(db.Integer, primary_key=True)
    prediction_id = db.Column(db.Integer, db.ForeignKey("predictions.id", ondelete="CASCADE"), nullable=True)
    attack_type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False) # Critical, High, Medium, Low
    risk_score = db.Column(db.Float, nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    source_ip = db.Column(db.String(45), default="192.168.1.100")
    status = db.Column(db.String(30), default="New", index=True) # New, Investigating, Resolved, False Positive
    summary = db.Column(db.String(255), nullable=True)
    explanation = db.Column(db.Text, nullable=True)
    top_features_json = db.Column(db.Text, nullable=True)
    analyst_notes = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, index=True)
    resolved_at = db.Column(db.DateTime, nullable=True)

    prediction = db.relationship("Prediction", backref=db.backref("alert", uselist=False))

    def to_dict(self):
        return {
            "id": self.id,
            "prediction_id": self.prediction_id,
            "attack_type": self.attack_type,
            "severity": self.severity,
            "risk_score": self.risk_score,
            "confidence": self.confidence,
            "source_ip": self.source_ip,
            "status": self.status,
            "summary": self.summary,
            "explanation": self.explanation,
            "top_features_json": self.top_features_json,
            "analyst_notes": self.analyst_notes or "",
            "created_at": self.created_at.strftime("%Y-%m-%d %H:%M:%S") if self.created_at else "",
            "resolved_at": self.resolved_at.strftime("%Y-%m-%d %H:%M:%S") if self.resolved_at else None
        }


class BlockedIP(db.Model):
    __tablename__ = "blocked_ips"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False)
    attack_type = db.Column(db.String(50), default="DoS")
    reason = db.Column(db.String(255), nullable=False)
    blocked_at = db.Column(db.DateTime, default=datetime.utcnow)
    expires_at = db.Column(db.DateTime, nullable=True)
    status = db.Column(db.String(20), default="Active") # Active, Expired, Revoked
    simulated = db.Column(db.Boolean, default=True)
    command_run = db.Column(db.Text, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "ip_address": self.ip_address,
            "attack_type": self.attack_type,
            "reason": self.reason,
            "blocked_at": self.blocked_at.strftime("%Y-%m-%d %H:%M:%S") if self.blocked_at else "",
            "expires_at": self.expires_at.strftime("%Y-%m-%d %H:%M:%S") if self.expires_at else "Never",
            "status": self.status,
            "simulated": self.simulated,
            "command_run": self.command_run or ""
        }


class AuditLog(db.Model):
    __tablename__ = "audit_logs"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), default="System")
    action = db.Column(db.String(100), nullable=False)
    details = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "action": self.action,
            "details": self.details,
            "timestamp": self.timestamp.strftime("%Y-%m-%d %H:%M:%S") if self.timestamp else ""
        }


class SystemSetting(db.Model):
    __tablename__ = "system_settings"

    id = db.Column(db.Integer, primary_key=True)
    key = db.Column(db.String(80), unique=True, nullable=False)
    value = db.Column(db.String(255), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
