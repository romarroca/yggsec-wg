# path: app.py  (minimal cleanup + safe redirect + favicon)
import ipaddress
import json
import os
import re
import secrets
import subprocess
import tempfile
import time
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import (
    Flask,
    current_app,
    flash,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    send_from_directory,
    session,
    url_for,
)
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash

from src.core import core_legacy as core
from src.core import firewall, monitor
from src.core.firewall import persist_vpnfw_table
from src.services.totp_service import TOTPService
from src.utils.error_handler import ErrorHandler, handle_api_error

app = Flask(__name__, template_folder="../../templates", static_folder="../../static")
app.secret_key = os.environ["SECRET_KEY"]

# Security configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,  # HTTPS only
    SESSION_COOKIE_HTTPONLY=True,  # No JS access
    SESSION_COOKIE_SAMESITE="Lax",  # CSRF protection
    PERMANENT_SESSION_LIFETIME=1800,  # 30 minutes timeout (improved security)
    WTF_CSRF_TIME_LIMIT=1800,  # CSRF token timeout (match session)
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Initialize rate limiting
limiter = Limiter(key_func=get_remote_address, default_limits=["100 per hour"])
limiter.init_app(app)

# Initialize TOTP service
totp_service = TOTPService()

# -----------------------------
# Admin store (JSON; env is first-boot fallback)
# -----------------------------
ADMINS_FILE = Path("configs/admins.json")


def _load_admins_dict():
    if ADMINS_FILE.exists():
        data = json.loads(ADMINS_FILE.read_text() or "{}")
        return {a["username"]: a for a in data.get("admins", [])}
    # Bootstrap from env if no file
    u = os.environ.get("ADMIN_USERNAME", "administrator")
    p = os.environ.get("ADMIN_PASSWORD")

    # SECURITY FIX: No hardcoded password default
    if not p:
        raise ValueError(
            "ADMIN_PASSWORD environment variable must be set - no default password for security"
        )

    return {
        u: {
            "username": u,
            "first_name": "Admin",
            "last_name": "User",
            "password_hash": generate_password_hash(p),
        }
    }


def _save_admins_dict(d):
    ADMINS_FILE.parent.mkdir(parents=True, exist_ok=True)
    ADMINS_FILE.write_text(json.dumps({"admins": list(d.values())}, indent=2))


ADMINS = _load_admins_dict()


def verify_admin(username, password):
    a = ADMINS.get(username)
    return bool(a and check_password_hash(a["password_hash"], password))


# Rate limiting storage for ping API
_ping_rate_limits = {}

# Ping results persistence
PING_RESULTS_FILE = Path("configs/ping_results.json")


def _load_ping_results():
    """Load persistent ping results from file."""
    if PING_RESULTS_FILE.exists():
        try:
            with open(PING_RESULTS_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError):
            return {}
    return {}


def _save_ping_result(spoke_name, result_data):
    """Save a single ping result to persistent storage."""
    try:
        # Load existing results
        ping_results = _load_ping_results()

        # Update with new result
        ping_results[spoke_name] = {
            "reachable": result_data.get("reachable", False),
            "response_time": result_data.get("response_time"),
            "message": result_data.get("message", ""),
            "timestamp": result_data.get("timestamp", int(time.time())),
            "vpn_ip": result_data.get("vpn_ip", ""),
        }

        # Ensure directory exists
        PING_RESULTS_FILE.parent.mkdir(parents=True, exist_ok=True)

        # Write atomically with secure permissions
        with tempfile.NamedTemporaryFile(
            mode="w", dir=PING_RESULTS_FILE.parent, delete=False, suffix=".tmp"
        ) as f:
            json.dump(ping_results, f, indent=2)
            os.fchmod(f.fileno(), 0o600)  # Secure permissions (Bandit B108)
            temp_path = f.name

        os.replace(temp_path, PING_RESULTS_FILE)
        return True
    except Exception as e:
        sanitized_error = ErrorHandler._sanitize_message(str(e))
        current_app.logger.error(f"Failed to save ping result: {sanitized_error}")
        return False


def _validate_vpn_ip(ip_str):
    """Strict IP validation for VPN subnets to prevent injection"""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        # Handle both IP addresses and CIDR notation (strip /32 if present)
        clean_ip = ip_str.strip()
        if "/" in clean_ip:
            clean_ip = clean_ip.split("/")[0]

        ipaddress.IPv4Address(clean_ip)  # Validate IP format
        # Allow any valid IPv4 address (WireGuard can use any IP range)
        return True
    except ValueError:
        return False


def _parse_ping_time(ping_output):
    """Extract ping time from ping command output"""
    match = re.search(r"time=(\d+(?:\.\d+)?)", ping_output)
    return float(match.group(1)) if match else None


def _check_ping_rate_limit(user, max_requests=10, window_seconds=60):
    """Rate limit ping requests per user"""
    now = time.time()
    user_key = f"ping_{user}"

    if user_key not in _ping_rate_limits:
        _ping_rate_limits[user_key] = []

    # Remove old requests outside the window
    _ping_rate_limits[user_key] = [
        req_time
        for req_time in _ping_rate_limits[user_key]
        if now - req_time < window_seconds
    ]

    # Check if limit exceeded
    if len(_ping_rate_limits[user_key]) >= max_requests:
        return False

    # Add current request
    _ping_rate_limits[user_key].append(now)
    return True


def current_user():
    u = session.get("user")
    return ADMINS.get(u)


@app.context_processor
def inject_user():
    return {"current_user": current_user()}


# Generate nonce for CSP
@app.before_request
def generate_nonce():
    """Generate a unique nonce for Content Security Policy"""
    g.nonce = secrets.token_urlsafe(16)


# Session management with sliding expiration and automatic logout
@app.before_request
def extend_session():
    """
    Implement sliding session expiration with automatic logout for expired sessions.
    This provides better security (30min timeout) with improved usability
    (active users stay logged in automatically, expired sessions auto-logout).
    """
    if "user" in session:
        # Check if session has expired by testing session validity
        try:
            from datetime import datetime, timedelta
            
            # Check if last_activity timestamp exists and if session has expired
            last_activity = session.get("last_activity")
            if last_activity:
                last_activity_time = datetime.fromisoformat(last_activity)
                session_timeout = timedelta(seconds=app.config["PERMANENT_SESSION_LIFETIME"])
                
                if datetime.now() - last_activity_time > session_timeout:
                    # Session expired, clear it and redirect to login
                    session.clear()
                    flash("Session expired. Please log in again.", "warning")
                    return redirect(url_for("login"))
            
            # Session is valid, extend it with sliding expiration
            session.permanent = True
            session.modified = True
            session["last_activity"] = datetime.now().isoformat()

            # Log session activity for security monitoring (optional)
            username = session.get("user", "unknown")
            current_app.logger.debug(f"Session extended for user: {username}")
        except Exception:
            # Fail silently if logging/timestamp fails, but still extend session
            session.permanent = True
            session.modified = True


# Security headers
@app.after_request
def security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "style-src 'self' cdn.jsdelivr.net; "
        f"script-src 'self' cdn.jsdelivr.net 'nonce-{g.nonce}'; "
        "img-src 'self' data:; "
        "font-src 'self' cdn.jsdelivr.net"
    )
    return response


# -----------------------------
# Auth helpers
# -----------------------------
def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)

    return wrapped


@app.route("/login", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def login():
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        totp_token = (request.form.get("totp_token") or "").strip()
        backup_code = (request.form.get("backup_code") or "").strip()

        # Step 1: Verify username/password OR check pending 2FA
        pending_user = session.get("pending_2fa_user")
        if verify_admin(username, password) or (
            password == "verified" and pending_user == username
        ):
            # Step 2: Check if 2FA is enabled
            if totp_service.is_2fa_enabled(username):
                # 2FA is enabled - require TOTP token or backup code
                if totp_token:
                    if totp_service.verify_token(username, totp_token):
                        # Valid TOTP token - complete login
                        session["user"] = username
                        session.permanent = True
                        # Set initial activity timestamp for session timeout tracking
                        from datetime import datetime
                        session["last_activity"] = datetime.now().isoformat()
                        session.pop("pending_2fa_user", None)  # Clear pending state
                        flash("Signed in with 2FA.", "success")
                        dest = request.args.get("next") or url_for("index")
                        # Proper open-redirect protection
                        parsed = urlparse(dest)
                        if (
                            parsed.netloc
                            or not dest.startswith("/")
                            or dest.startswith("//")
                        ):
                            dest = url_for("index")
                        return redirect(dest)
                    else:
                        flash("Invalid 2FA code.", "error")
                elif backup_code:
                    if totp_service.verify_backup_code(username, backup_code):
                        # Valid backup code - complete login
                        session["user"] = username
                        session.permanent = True
                        # Set initial activity timestamp for session timeout tracking
                        from datetime import datetime
                        session["last_activity"] = datetime.now().isoformat()
                        session.pop("pending_2fa_user", None)  # Clear pending state
                        flash("Signed in with backup code.", "warning")
                        dest = request.args.get("next") or url_for("index")
                        # Proper open-redirect protection
                        parsed = urlparse(dest)
                        if (
                            parsed.netloc
                            or not dest.startswith("/")
                            or dest.startswith("//")
                        ):
                            dest = url_for("index")
                        return redirect(dest)
                    else:
                        flash("Invalid backup code.", "error")
                else:
                    # Store temporary auth state and show 2FA form
                    session["pending_2fa_user"] = username
                    return render_template("login_2fa.html", username=username)
            else:
                # No 2FA enabled - complete login
                session["user"] = username
                session.permanent = True
                # Set initial activity timestamp for session timeout tracking
                from datetime import datetime
                session["last_activity"] = datetime.now().isoformat()
                flash("Signed in.", "success")
                dest = request.args.get("next") or url_for("index")
                # Proper open-redirect protection
                parsed = urlparse(dest)
                if parsed.netloc or not dest.startswith("/") or dest.startswith("//"):
                    dest = url_for("index")
                return redirect(dest)
        else:
            flash("Invalid username or password.", "error")

    # Clear any pending 2FA state
    session.pop("pending_2fa_user", None)
    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    flash("Signed out.", "success")
    return redirect(url_for("login"))


# Serve favicon to avoid noisy 404 tracebacks
@app.route("/favicon.ico")
def favicon():
    static_dir = os.path.join(app.root_path, "static")
    path = os.path.join(static_dir, "favicon.ico")
    if os.path.isfile(path):
        return send_from_directory(
            static_dir, "favicon.ico", mimetype="image/vnd.microsoft.icon"
        )
    return ("", 204)


# -----------------------------
# Profile + password change
# -----------------------------
@app.route("/account")
@login_required
def account():
    user = current_user()
    if not user:
        return redirect(url_for("login"))
    return render_template("accounts.html", user=user)


@app.post("/account/password")
@login_required
def account_change_password():
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    oldp = request.form.get("current_password") or ""
    newp = request.form.get("new_password") or ""
    conf = request.form.get("confirm_password") or ""

    if not verify_admin(user["username"], oldp):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("account"))
    if len(newp) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("account"))
    if newp != conf:
        flash("Password confirmation does not match.", "error")
        return redirect(url_for("account"))

    try:
        ADMINS[user["username"]]["password_hash"] = generate_password_hash(newp)
        _save_admins_dict(ADMINS)
        flash("Password updated.", "success")
        return redirect(url_for("account"))
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, "updating password")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("account"))


# --------------------------
# 2FA Management Routes
# --------------------------
@app.route("/account/2fa")
@login_required
def account_2fa():
    """2FA management page"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    username = user["username"]
    status = totp_service.get_user_2fa_status(username)

    return render_template("account_2fa.html", user=user, status=status)


@app.route("/account/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    """Setup 2FA for user"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    username = user["username"]

    if request.method == "POST":
        verification_code = (request.form.get("verification_code") or "").strip()

        if totp_service.enable_2fa(username, verification_code):
            flash("2FA has been enabled successfully!", "success")
            return redirect(url_for("account_2fa"))
        else:
            flash("Invalid verification code. Please try again.", "error")

    # Generate secret if not exists
    if not totp_service.get_secret(username):
        totp_service.generate_secret(username)

    return render_template("setup_2fa.html", user=user)


@app.route("/account/2fa/qr")
@login_required
def get_2fa_qr():
    """Generate QR code for 2FA setup"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    try:
        username = user["username"]
        qr_image = totp_service.generate_qr_code(username)

        from flask import Response

        return Response(qr_image, mimetype="image/png")
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, "generating QR code")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("setup_2fa"))


@app.route("/account/2fa/disable", methods=["POST"])
@login_required
def disable_2fa():
    """Disable 2FA for user"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    # Verify current password for security
    current_password = request.form.get("current_password") or ""
    if not verify_admin(user["username"], current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("account_2fa"))

    if totp_service.disable_2fa(user["username"]):
        flash("2FA has been disabled.", "warning")
    else:
        flash("Failed to disable 2FA.", "error")

    return redirect(url_for("account_2fa"))


@app.route("/account/2fa/backup-codes")
@login_required
def view_backup_codes():
    """View backup codes"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    username = user["username"]
    if not totp_service.is_2fa_enabled(username):
        flash("2FA is not enabled.", "error")
        return redirect(url_for("account_2fa"))

    backup_codes = totp_service.get_backup_codes(username)
    return render_template("backup_codes.html", user=user, backup_codes=backup_codes)


@app.route("/account/2fa/regenerate-backup-codes", methods=["POST"])
@login_required
def regenerate_backup_codes():
    """Regenerate backup codes"""
    user = current_user()
    if not user:
        return redirect(url_for("login"))

    username = user["username"]
    if not totp_service.is_2fa_enabled(username):
        flash("2FA is not enabled.", "error")
        return redirect(url_for("account_2fa"))

    # Verify current password for security
    current_password = request.form.get("current_password") or ""
    if not verify_admin(username, current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("account_2fa"))

    try:
        new_codes = totp_service.regenerate_backup_codes(username)
        flash("New backup codes generated. Please save them securely.", "success")
        return render_template(
            "backup_codes.html", user=user, backup_codes=new_codes, regenerated=True
        )
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, "regenerating backup codes")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("account_2fa"))


# --------------------------
# Monitor Page
# --------------------------
@app.route("/monitor")
@login_required
def monitor_page():
    data = monitor.monitor_snapshot()
    return render_template("monitor.html", data=data)


@app.route("/api/monitor")
@login_required
def monitor_api():
    return jsonify(monitor.monitor_snapshot())


# --------------------------
# Firewall Page
# --------------------------
@app.route("/firewall", methods=["GET", "POST"])
@limiter.limit("10 per minute")
@login_required
def firewall_page():
    if request.method == "POST":
        action = request.form.get("action")

        if action == "reset":
            success, msg = firewall.reset_firewall("drop")
            if success:
                persist_vpnfw_table()
            flash(msg, "success" if success else "error")

        elif action == "add_rule":
            rule_name = request.form.get("rule_name") or None
            src_ip = request.form.get("src_ip") or None
            dst_ip = request.form.get("dst_ip") or None
            dst_port = request.form.get("dst_port") or None
            proto = request.form.get("proto") or "tcp"
            position = request.form.get("position") or "append"
            rule_action = request.form.get("action_type") or "TRUST"
            index = request.form.get("index")
            if index:
                try:
                    index = int(index)
                except ValueError:
                    index = None

            success, msg = firewall.add_rule(
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                action=rule_action,
                position=position,
                index=index,
                name=rule_name,
            )
            if success:
                persist_vpnfw_table()
                flash("Rule added successfully", "success")
            else:
                flash(msg, "error")

        elif action == "edit_rule":
            handle = request.form.get("handle")
            if not handle:
                flash("Missing handle for edit", "error")
                return redirect(url_for("firewall_page"))

            rule_name = request.form.get("rule_name") or None
            src_ip = request.form.get("src_ip") or None
            dst_ip = request.form.get("dst_ip") or None
            dst_port = request.form.get("dst_port") or None
            proto = request.form.get("proto") or "tcp"
            position = request.form.get("position") or "append"
            rule_action = request.form.get("action_type") or "TRUST"
            index = request.form.get("index")
            if index:
                try:
                    index = int(index)
                except ValueError:
                    index = None

            ok, msg = firewall.edit_rule(
                handle=handle,
                src_ip=src_ip,
                dst_ip=dst_ip,
                dst_port=dst_port,
                proto=proto,
                action=rule_action,
                position=position,
                index=index,
                name=rule_name,
            )
            if ok:
                persist_vpnfw_table()
                flash("Rule updated", "success")
            else:
                flash(msg, "error")

        elif action == "delete_rule":
            handle = request.form.get("handle")
            if handle:
                success, msg = firewall.delete_rule(handle)
                if success:
                    persist_vpnfw_table()
                    flash("Rule deleted", "success")
                else:
                    flash(msg, "error")

        return redirect(url_for("firewall_page"))

    rules = firewall.list_rules_table()
    return render_template("firewall.html", rules=rules)


# -----------------------------
# Main Dashboard
# -----------------------------
@app.route("/")
@login_required
def index():
    topology = core.load_topology()
    return render_template("index.html", topology=topology)


# -----------------------------
# Add Remote Site
# -----------------------------
# Add Remote Site — POST only (modal submits here)
@app.post("/add-spoke")
@login_required
def add_spoke():
    name = (request.form.get("name") or "").strip()
    lan_subnet_raw = (request.form.get("lan_subnet") or "").strip()
    lan_subnet = lan_subnet_raw if lan_subnet_raw else None

    if not name or not re.match(r"^[a-zA-Z0-9_-]{1,20}$", name):
        flash(
            "Invalid spoke name: only alphanumeric, dash, underscore allowed (max 20 chars)",
            "error",
        )
        return redirect(url_for("index"))

    try:
        core.add_spoke(name=name, lan_subnet=lan_subnet)
        if lan_subnet:
            message = f"Spoke '{name}' added with LAN {lan_subnet}."
        else:
            message = f"Spoke '{name}' added (no LAN subnet)."
        flash(message, "success")
        return redirect(url_for("index"))
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, f"adding spoke '{name}'")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("index"))


# -----------------------------
# Add Hub LAN
# -----------------------------
# Add Hub LAN — POST only (modal submits here)
@app.post("/add-hub-lan")
@login_required
def add_hub_lan():
    lan_subnets = (request.form.get("lan_subnets") or "").strip()
    if not lan_subnets:
        flash("LAN subnet(s) are required", "error")
        return redirect(url_for("index"))

    try:
        core.add_hub_lan(lan_subnets)
        flash("Hub LAN(s) added successfully!", "success")
        return redirect(url_for("index"))
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, "adding hub LAN")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("index"))


@app.post("/remove-hub-lan")
@login_required
def remove_hub_lan():
    lan_subnet = (request.form.get("lan_subnet") or "").strip()
    if not lan_subnet:
        flash("LAN subnet is required", "error")
        return redirect(url_for("index"))

    try:
        core.remove_hub_lan(lan_subnet)
        flash("Hub LAN removed successfully!", "success")
        return redirect(url_for("index"))
    except Exception as e:
        user_message, correlation_id = handle_api_error(e, "removing hub LAN")
        flash(f"{user_message} (ID: {correlation_id})", "error")
        return redirect(url_for("index"))


@app.post("/edit-vpn-subnet")
@login_required
def edit_vpn_subnet():
    vpn_subnet = (request.form.get("vpn_subnet") or "").strip()
    if not vpn_subnet:
        flash("VPN subnet is required", "error")
        return redirect(url_for("index"))

    try:
        core.edit_vpn_subnet(vpn_subnet)
        flash(
            "VPN subnet updated successfully! Please reconfigure all clients.",
            "success",
        )
        return redirect(url_for("index"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Failed to update VPN subnet: {str(e)}", "error")
        return redirect(url_for("index"))


@app.post("/edit-public-ip")
@limiter.limit("10 per minute")
@login_required
def edit_public_ip():
    public_ip = (request.form.get("public_ip") or "").strip()
    if not public_ip:
        flash("Public IP/FQDN is required", "error")
        return redirect(url_for("index"))

    try:
        core.edit_public_ip(public_ip)
        flash(
            "Public IP updated successfully! Please reconfigure all clients.",
            "success",
        )
        return redirect(url_for("index"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Failed to update public IP: {str(e)}", "error")
        return redirect(url_for("index"))


@app.post("/edit-wg-port")
@limiter.limit("10 per minute")
@login_required
def edit_wg_port():
    wg_port = (request.form.get("wg_port") or "").strip()
    if not wg_port:
        flash("WireGuard port is required", "error")
        return redirect(url_for("index"))

    try:
        core.edit_wg_port(wg_port)
        flash(
            "WireGuard port updated successfully! Please reconfigure all clients.",
            "success",
        )
        return redirect(url_for("index"))
    except ValueError as e:
        flash(str(e), "error")
        return redirect(url_for("index"))
    except Exception as e:
        flash(f"Failed to update WireGuard port: {str(e)}", "error")
        return redirect(url_for("index"))


# -----------------------------
# Config Management
# -----------------------------
@app.route("/regenerate", methods=["POST"])
@limiter.limit("3 per minute")
@login_required
def regenerate():
    core.regenerate_all()
    flash("Configuration regenerated successfully!", "success")
    return redirect(url_for("index"))


@app.route("/restart", methods=["GET", "POST"])
@limiter.limit("1 per minute")
@login_required
def restart():
    wg_conf = os.path.join(core.WG_DIR, f"{core.WG_IFACE}.conf")
    try:
        core.restart_full(wg_conf)
        flash("wg0 restarted successfully.", "success")
    except Exception:  # Intentionally catching all exceptions
        current_app.logger.error("wg0 restart failed - check service logs for details")
        flash("Service restart failed. Check logs.", "danger")
    return redirect(url_for("index"))


@app.route("/regenerate/hub", methods=["POST"])
@limiter.limit("3 per minute")
@login_required
def regen_hub_keys():
    if core.regenerate_hub_keys():
        flash("Hub keys regenerated successfully!", "success")
    else:
        flash("Failed to regenerate hub keys", "error")
    return redirect(url_for("index"))


@app.route("/regenerate/spoke/<name>", methods=["POST"])
@limiter.limit("3 per minute")
@login_required
def regen_spoke_keys(name):
    if core.regenerate_spoke_keys(name):
        flash(f"Spoke {name} keys regenerated successfully!", "success")
    else:
        flash(f"Failed to regenerate keys for spoke {name}", "error")
    return redirect(url_for("index"))


@app.route("/delete/<name>", methods=["POST"])
@limiter.limit("5 per minute")
@login_required
def delete_spoke(name):
    if core.delete_spoke(name):
        flash(f"Spoke {name} deleted successfully!", "success")
    else:
        flash(f"Failed to delete spoke {name}", "error")
    return redirect(url_for("index"))


# -----------------------------
# Download Config
# -----------------------------
@app.route("/download/<name>")
@limiter.limit("20 per minute")
@login_required
def download_spoke(name):
    # Validate filename to prevent path traversal
    if not re.match(r"^[a-zA-Z0-9_-]+$", name):
        flash("Invalid spoke name", "error")
        return redirect(url_for("index"))
    config_dir = os.path.join(core.ROOT_DIR, "configs")
    filename = f"{name}-wg0.conf"
    filepath = os.path.join(config_dir, filename)
    if os.path.exists(filepath):
        return send_from_directory(config_dir, filename, as_attachment=True)
    else:
        flash(f"No config file found for {name}", "error")
        return redirect(url_for("index"))


# --------------------------
# Suricata / IPS Events (UI)
# --------------------------
@app.route("/suricata")
@login_required
def suricata_page():
    from src.core.suricata import read_eve

    alerts = read_eve(n=200, history=True)
    return render_template("suricata.html", alerts=alerts)


# --------------------------
# Suricata / IPS Events
# --------------------------
@app.get("/api/suricata/eve")
@login_required
def api_suricata_eve():
    n = request.args.get("n", type=int, default=200)
    from src.core.suricata import read_eve

    return jsonify({"alerts": read_eve(n=n, history=True)})


@app.get("/api/suricata/status")
@login_required
def api_suricata_status():
    from src.core.suricata import get_suricata_mode, get_suricata_status

    return jsonify({"mode": get_suricata_mode(), "status": get_suricata_status()})


@app.post("/api/suricata/clear")
@login_required
def api_suricata_clear():
    from src.core.suricata import clear_alert_cache

    success = clear_alert_cache()
    return jsonify({"success": success})


# Suricata control endpoints removed due to NoNewPrivileges=true security constraint
# Manual control: SSH → sudo systemctl start/stop/restart suricata


# -----------------------------
# Secure Peer Ping API
# -----------------------------
@app.post("/api/ping-peer")
@login_required
def api_ping_peer():
    """
    Secure on-demand peer ping with comprehensive protection against RCE
    """
    try:
        # 1. Rate limiting protection
        current_username = session.get("user")
        if not _check_ping_rate_limit(
            current_username, max_requests=10, window_seconds=60
        ):
            return (
                jsonify({"error": "Rate limit exceeded. Try again in a minute."}),
                429,
            )

        # 2. Validate request format
        if not request.is_json:
            return jsonify({"error": "Invalid request format"}), 400

        # 3. Extract and validate spoke name
        spoke_name = request.json.get("spoke_name", "").strip()
        if not spoke_name or not re.match(r"^[a-zA-Z0-9_-]{1,20}$", spoke_name):
            return jsonify({"error": "Invalid spoke name"}), 400

        # 4. Load topology and validate spoke exists
        topology = core.load_topology()
        if not topology or "spokes" not in topology:
            return jsonify({"error": "No topology configuration"}), 500

        # 5. Find spoke in topology (whitelist validation)
        target_spoke = None
        for spoke in topology["spokes"]:
            if spoke.get("name") == spoke_name:
                target_spoke = spoke
                break

        if not target_spoke:
            return jsonify({"error": "Spoke not found in topology"}), 400

        # 6. Validate VPN IP exists and is valid
        vpn_ip_raw = target_spoke.get("vpn_ip", "").strip()
        if not vpn_ip_raw:
            current_app.logger.warning(
                f"Ping request for spoke {spoke_name}: No VPN IP configured"
            )
            return jsonify({"error": "Spoke has no VPN IP configured"}), 400

        if not _validate_vpn_ip(vpn_ip_raw):
            current_app.logger.warning(
                f"Ping request validation failed: spoke={spoke_name}, ip={vpn_ip_raw}"
            )
            return jsonify({"error": f"Invalid VPN IP address: {vpn_ip_raw}"}), 400

        # Clean IP for ping (remove /32 if present)
        ping_ip = vpn_ip_raw.split("/")[0] if "/" in vpn_ip_raw else vpn_ip_raw

        # 7. Execute secure ping (no shell injection possible)
        try:
            result = subprocess.run(
                ["/bin/ping", "-c", "1", "-W", "2", ping_ip],
                capture_output=True,
                timeout=5,
                text=True,
                check=False,
                shell=False,
            )

            success = result.returncode == 0
            response_time = _parse_ping_time(result.stdout) if success else None

            result_data = {
                "success": True,
                "spoke_name": spoke_name,
                "vpn_ip": ping_ip,
                "reachable": success,
                "response_time": response_time,
                "message": (
                    f"Peer reachable ({response_time}ms)"
                    if success
                    else "Peer unreachable (offline or blocking ping)"
                ),
                "timestamp": int(time.time()),
            }

            # Save result to persistent storage
            _save_ping_result(spoke_name, result_data)

            return jsonify(result_data)

        except subprocess.TimeoutExpired:
            timeout_result = {
                "success": True,
                "spoke_name": spoke_name,
                "vpn_ip": ping_ip,
                "reachable": False,
                "message": "Ping timeout - peer likely offline",
                "timestamp": int(time.time()),
            }

            # Save timeout result to persistent storage
            _save_ping_result(spoke_name, timeout_result)

            return jsonify(timeout_result)

    except Exception as e:
        sanitized_error = ErrorHandler._sanitize_message(str(e))
        current_app.logger.error(f"Ping API error: {sanitized_error}")
        return jsonify({"error": "Internal server error"}), 500


# -----------------------------
# Ping Results Retrieval API
# -----------------------------
@app.get("/api/ping-results")
@login_required
def api_ping_results():
    """Get all stored ping results."""
    try:
        ping_results = _load_ping_results()
        return jsonify({"success": True, "results": ping_results})
    except Exception as e:
        sanitized_error = ErrorHandler._sanitize_message(str(e))
        current_app.logger.error(f"Failed to load ping results: {sanitized_error}")
        return jsonify({"error": "Failed to load ping results"}), 500


# -----------------------------
# QR
# -----------------------------
@app.route("/api/spoke-config/<name>")
@login_required
def api_spoke_config(name):
    try:
        cfg_path = os.path.join(core.WG_DIR, f"{name}-{core.WG_IFACE}.conf")
        if not os.path.isfile(cfg_path):
            current_app.logger.warning("QR config not found for spoke: %s", name)
            return jsonify({"error": "not_found", "spoke": name}), 404
        with open(cfg_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
        return jsonify({"name": name, "config": text})
    except Exception as e:
        sanitized_error = ErrorHandler._sanitize_message(str(e))
        current_app.logger.error(f"QR config load failed for {name}: {sanitized_error}")
        return jsonify({"error": "internal", "detail": str(e)}), 500


# -----------------------------
# Main Entrypoint
# -----------------------------
if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8080, debug=False)
