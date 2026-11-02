"""
Integration tests for SentinelFlow Flask Endpoints & API routes
"""

import pytest
from app import create_app, db

@pytest.fixture
def client():
    app = create_app({
        "TESTING": True,
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False
    })

    with app.test_client() as client:
        with app.app_context():
            db.create_all()
        yield client

def test_home_and_detect_view(client):
    res = client.get("/")
    assert res.status_code == 200
    assert b"SentinelFlow" in res.data
    assert b"Detection & Ingestion Studio" in res.data

def test_predict_form_endpoint(client):
    payload = {
        "protocol_type": "tcp",
        "service": "http",
        "flag": "SF",
        "src_bytes": "215",
        "dst_bytes": "450",
        "count": "1",
        "serror_rate": "0.0"
    }
    res = client.post("/predict", data=payload)
    assert res.status_code == 200
    assert b"Prediction Result" in res.data

def test_predict_json_api_endpoint(client):
    payload = {
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "src_bytes": 0,
        "count": 250,
        "serror_rate": 1.0
    }
    res = client.post("/predict", json=payload, headers={"Accept": "application/json"})
    assert res.status_code == 200
    data = res.get_json()
    assert "prediction" in data
    assert "confidence" in data
    assert "risk_score" in data

def test_dashboard_views(client):
    res = client.get("/dashboard")
    assert res.status_code == 200
    assert b"Security Operations Dashboard" in res.data

    api_res = client.get("/api/dashboard/stats")
    assert api_res.status_code == 200
    stats = api_res.get_json()
    assert "total_analyzed" in stats
    assert "detection_rate" in stats

def test_alerts_and_mitigation_workflow(client):
    # 1. Trigger an attack via predict to generate an alert
    client.post("/predict", json={
        "protocol_type": "tcp",
        "service": "private",
        "flag": "S0",
        "count": 250,
        "serror_rate": 1.0
    })

    # 2. View alerts page
    res = client.get("/alerts")
    assert res.status_code == 200
    assert b"Security Incident & Alert Center" in res.data

    # 3. Simulate IP block
    block_res = client.post("/api/alerts/block-ip", json={
        "ip_address": "45.142.212.18",
        "attack_type": "DoS",
        "reason": "Automated test block"
    })
    assert block_res.status_code == 200
    b_data = block_res.get_json()
    assert b_data["success"] is True
    assert "iptables" in b_data["command"]

def test_history_and_clear(client):
    res = client.get("/history")
    assert res.status_code == 200
    assert b"Telemetry Audit History Log" in res.data

    clear_res = client.post("/clear_history", follow_redirects=True)
    assert clear_res.status_code == 200
