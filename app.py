"""
SentinelFlow — Explainable Network Intrusion Detection System (NIDS)
Application Entry Point
"""

import os
from app import create_app, socketio

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    debug = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    # Clean production-ready startup without hardcoded debug=True
    socketio.run(app, host="0.0.0.0", port=port, debug=debug, allow_unsafe_werkzeug=True)