"""
SentinelFlow Application Factory & Extension Registrations
"""

import os
import logging
from flask import Flask, render_template
from flask_login import LoginManager
from flask_socketio import SocketIO
from dotenv import load_dotenv

from app.models import db, User

# Load environment variables
load_dotenv()

login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "info"

socketio = SocketIO(cors_allowed_origins="*", async_mode="threading")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def create_app(test_config=None):
    """Factory creating and configuring the SentinelFlow Flask application."""
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    template_dir = os.path.join(base_dir, "templates")
    static_dir = os.path.join(base_dir, "static")

    app = Flask(
        __name__,
        instance_relative_config=True,
        template_folder=template_dir,
        static_folder=static_dir
    )

    # Logging setup
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    # Database URI configuration: supports DATABASE_URL (PostgreSQL) or SQLite
    raw_db_url = os.environ.get("DATABASE_URL")
    if raw_db_url:
        # Normalize postgres:// to postgresql:// for SQLAlchemy
        if raw_db_url.startswith("postgres://"):
            raw_db_url = raw_db_url.replace("postgres://", "postgresql://", 1)
        db_uri = raw_db_url
    else:
        db_path = os.path.join(base_dir, "database.db")
        db_uri = f"sqlite:///{db_path}"

    app.config.from_mapping(
        SECRET_KEY=os.environ.get("SECRET_KEY", "sentinel-flow-nids-production-secret-key-2026"),
        SQLALCHEMY_DATABASE_URI=db_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        MAX_CONTENT_LENGTH=16 * 1024 * 1024 # 16 MB max upload
    )

    if test_config:
        app.config.update(test_config)

    # Initialize extensions
    db.init_app(app)
    login_manager.init_app(app)
    socketio.init_app(app)

    # Register Blueprints
    from app.routes.auth import auth_bp
    from app.routes.detect import detect_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.alerts import alerts_bp
    from app.routes.models import models_bp
    from app.routes.reports import reports_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(detect_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(models_bp)
    app.register_blueprint(reports_bp)

    # Register Error Handlers
    @app.errorhandler(404)
    def page_not_found(e):
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        return render_template("errors/500.html", error=str(e)), 500

    # Ensure tables and default users exist
    with app.app_context():
        db.create_all()
        # Ensure SQLite has all columns if upgrading an existing DB
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            existing_cols = {col["name"] for col in inspector.get_columns("predictions")}
            new_columns = [
                ("protocol_type", "TEXT DEFAULT 'tcp'"),
                ("service", "TEXT DEFAULT 'http'"),
                ("flag", "TEXT DEFAULT 'SF'"),
                ("src_bytes", "REAL DEFAULT 0.0"),
                ("dst_bytes", "REAL DEFAULT 0.0"),
                ("count", "INTEGER DEFAULT 1"),
                ("serror_rate", "REAL DEFAULT 0.0"),
                ("source_ip", "TEXT DEFAULT '192.168.1.105'"),
                ("is_flagged", "BOOLEAN DEFAULT 0"),
                ("analyst_status", "TEXT DEFAULT 'New'"),
                ("analyst_notes", "TEXT")
            ]
            for col_name, col_def in new_columns:
                if col_name not in existing_cols:
                    db.session.execute(text(f"ALTER TABLE predictions ADD COLUMN {col_name} {col_def}"))
            db.session.commit()
        except Exception as mig_err:
            app.logger.warning(f"Schema check note: {mig_err}")

        # Seed default Demo Users if none exist
        if User.query.count() == 0:
            admin_user = User(username="admin", role="Admin")
            admin_user.set_password(os.environ.get("ADMIN_PASSWORD", "SentinelAdmin2026!"))

            analyst_user = User(username="analyst", role="Analyst")
            analyst_user.set_password("Analyst123!")

            viewer_user = User(username="viewer", role="Viewer")
            viewer_user.set_password("Viewer123!")

            db.session.add_all([admin_user, analyst_user, viewer_user])
            db.session.commit()
            app.logger.info("Default roles (Admin, Analyst, Viewer) seeded successfully.")

    # Initialize simulator singleton with socketio
    from app.services.simulator import TrafficSimulator
    TrafficSimulator.get_instance(socketio=socketio)

    return app
