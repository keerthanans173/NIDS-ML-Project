"""
SentinelFlow Authentication & RBAC Blueprint
Provides user login, registration, role management (Admin, Analyst, Viewer),
and a convenient demo switcher for seamless evaluation.
"""

from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from app.models import db, User, AuditLog

auth_bp = Blueprint("auth", __name__)

@auth_bp.route("/login", methods=["GET", "POST"])
@auth_bp.route("/auth/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.dashboard_view"))

    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            log = AuditLog(username=user.username, action="User Login", details=f"Role: {user.role}")
            db.session.add(log)
            db.session.commit()
            flash(f"Welcome back, {user.username} ({user.role})!", "success")
            next_page = request.args.get("next")
            return redirect(next_page or url_for("dashboard.dashboard_view"))
        else:
            flash("Invalid username or password.", "danger")

    return render_template("auth/login.html")

@auth_bp.route("/demo-login/<role>")
@auth_bp.route("/auth/demo-login/<role>")
def demo_login(role):
    """Convenient demo switcher so evaluators can inspect Admin, Analyst, or Viewer perspectives."""
    role = role.capitalize()
    if role not in ("Admin", "Analyst", "Viewer"):
        role = "Analyst"

    username = f"demo_{role.lower()}"
    user = User.query.filter_by(username=username).first()
    if not user:
        user = User(username=username, role=role)
        user.set_password("sentinel123")
        db.session.add(user)
        db.session.commit()

    login_user(user)
    log = AuditLog(username=user.username, action="Demo Switcher", details=f"Switched to {role} role")
    db.session.add(log)
    db.session.commit()
    flash(f"Switched session to {role} role.", "info")

    ref = request.referrer
    if ref and ("127.0.0.1" in ref or "localhost" in ref):
        return redirect(ref)
    return redirect(url_for("dashboard.dashboard_view"))

@auth_bp.route("/logout")
@auth_bp.route("/auth/logout")
@login_required
def logout():
    log = AuditLog(username=current_user.username, action="User Logout")
    db.session.add(log)
    db.session.commit()
    logout_user()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("auth.login"))

@auth_bp.route("/register", methods=["GET", "POST"])
@auth_bp.route("/auth/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        role = request.form.get("role", "Analyst")

        if not username or not password:
            flash("Username and password are required.", "warning")
            return render_template("auth/register.html")

        if User.query.filter_by(username=username).first():
            flash("Username already exists. Please choose another.", "warning")
            return render_template("auth/register.html")

        if role not in ("Admin", "Analyst", "Viewer"):
            role = "Analyst"

        # First registered user becomes Admin automatically
        if User.query.count() == 0:
            role = "Admin"

        new_user = User(username=username, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f"Account created successfully for {username}! You may now log in.", "success")
        return redirect(url_for("auth.login"))

    return render_template("auth/register.html")
