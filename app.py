import os
import ipaddress
import socket
import traceback

from flask import (
    Flask,
    render_template,
    request,
    session,
    redirect,
    url_for
)

from scanner.nmap_scanner import scan_target

from database import (
    save_scan,
    get_scan_history,
    get_scan,
    create_user,
    authenticate_user,
    get_user
)


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)


# ============================================================
# SESSION SECURITY
# ============================================================

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=True
)


# ============================================================
# LOGIN PROTECTION
# ============================================================

def login_required():

    user_id = session.get("user_id")

    if not user_id:
        return False

    try:

        user = get_user(user_id)

        if user is None:

            session.clear()

            return False

        return True

    except Exception as error:

        print(
            "========== LOGIN CHECK ERROR =========="
        )

        print(
            f"ERROR: {error}"
        )

        traceback.print_exc()

        print(
            "======================================="
        )

        session.clear()

        return False


# ============================================================
# TARGET VALIDATION
# ============================================================

def is_valid_target(target):

    if not target:
        return False

    target = target.strip()

    if len(target) > 253:
        return False

    # --------------------------------------------------------
    # Only allow normal IP / hostname characters
    # --------------------------------------------------------

    allowed_characters = (
        "abcdefghijklmnopqrstuvwxyz"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "0123456789"
        ".:-_"
    )

    if any(
        character not in allowed_characters
        for character in target
    ):
        return False

    # --------------------------------------------------------
    # Check IP address
    # --------------------------------------------------------

    try:

        ipaddress.ip_address(target)

        return True

    except ValueError:

        pass

    # --------------------------------------------------------
    # Check hostname
    # --------------------------------------------------------

    try:

        socket.gethostbyname(target)

        return True

    except socket.gaierror:

        return False


# ============================================================
# TARGET AUTHORIZATION
# ============================================================

def is_target_allowed(target):

    """
    Target authorization.

    The previous version required the target to exist inside
    the ALLOWED_TARGETS environment variable.

    This version does NOT require that variable.

    Therefore, valid targets are not rejected simply because
    they are missing from ALLOWED_TARGETS.
    """

    return True


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_security(results):

    open_ports = len(results)

    recommendations = []

    risky_ports = {

        21:
        "FTP can expose credentials. Consider using SFTP instead.",

        23:
        "Telnet is insecure because it sends data without encryption.",

        3389:
        "RDP should be restricted to trusted networks or protected with a VPN.",

        445:
        "SMB should not be unnecessarily exposed to untrusted networks."
    }

    # --------------------------------------------------------
    # Check risky ports
    # --------------------------------------------------------

    for result in results:

        port = result.get("port")

        if port in risky_ports:

            recommendation = risky_ports[port]

            if recommendation not in recommendations:

                recommendations.append(
                    recommendation
                )

    # --------------------------------------------------------
    # Determine risk
    # --------------------------------------------------------

    if open_ports == 0:

        risk_level = "LOW"

        recommendations.append(
            "No open ports were detected in the scan results."
        )

    elif open_ports <= 2:

        risk_level = "LOW"

    elif open_ports <= 5:

        risk_level = "MEDIUM"

        recommendations.append(
            "Review open ports and disable services "
            "that are not required."
        )

    else:

        risk_level = "HIGH"

        recommendations.append(
            "A large number of open ports were detected. "
            "Review exposed services."
        )

    # --------------------------------------------------------
    # General recommendation
    # --------------------------------------------------------

    recommendations.append(
        "Keep network services and software updated."
    )

    return risk_level, recommendations


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_stats():

    user_id = session["user_id"]

    history_data = get_scan_history(
        user_id
    )

    # --------------------------------------------------------
    # Total scans
    # --------------------------------------------------------

    total_scans = len(
        history_data
    )

    # --------------------------------------------------------
    # Total open ports
    # --------------------------------------------------------

    total_open_ports = sum(
        scan.get(
            "open_ports",
            0
        )
        for scan in history_data
    )

    # --------------------------------------------------------
    # Risk statistics
    # --------------------------------------------------------

    high_risk = sum(
        1
        for scan in history_data
        if scan.get(
            "risk_level",
            ""
        ).upper() == "HIGH"
    )

    medium_risk = sum(
        1
        for scan in history_data
        if scan.get(
            "risk_level",
            ""
        ).upper() == "MEDIUM"
    )

    low_risk = sum(
        1
        for scan in history_data
        if scan.get(
            "risk_level",
            ""
        ).upper() == "LOW"
    )

    # --------------------------------------------------------
    # Latest scan
    # --------------------------------------------------------

    if history_data:

        latest_scan = history_data[0]

        latest_target = latest_scan.get(
            "target",
            "—"
        )

        latest_risk = latest_scan.get(
            "risk_level",
            "—"
        )

        latest_date = latest_scan.get(
            "date",
            "—"
        )

    else:

        latest_target = "—"

        latest_risk = "—"

        latest_date = "—"

    return {

        "total_scans":
            total_scans,

        "total_open_ports":
            total_open_ports,

        "high_risk":
            high_risk,

        "medium_risk":
            medium_risk,

        "low_risk":
            low_risk,

        "latest_target":
            latest_target,

        "latest_risk":
            latest_risk,

        "latest_date":
            latest_date
    }


# ============================================================
# REGISTER
# ============================================================

@app.route(
    "/register",
    methods=["GET", "POST"]
)
def register():

    # --------------------------------------------------------
    # Already logged in
    # --------------------------------------------------------

    if login_required():

        return redirect(
            url_for("home")
        )

    error_message = ""

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        email = request.form.get(
            "email",
            ""
        ).strip().lower()

        password = request.form.get(
            "password",
            ""
        )

        confirm_password = request.form.get(
            "confirm_password",
            ""
        )

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        if (
            not username
            or not email
            or not password
            or not confirm_password
        ):

            error_message = (
                "Please fill in all fields."
            )

        elif password != confirm_password:

            error_message = (
                "Passwords do not match."
            )

        elif len(username) < 3:

            error_message = (
                "Username must be at least 3 characters."
            )

        elif len(password) < 6:

            error_message = (
                "Password must be at least 6 characters."
            )

        else:

            try:

                user_id = create_user(
                    username,
                    email,
                    password
                )

                if user_id is None:

                    error_message = (
                        "Username or email already exists."
                    )

                else:

                    return redirect(
                        url_for("login")
                    )

            except Exception as error:

                print(
                    "========== REGISTER ERROR =========="
                )

                print(
                    f"ERROR: {error}"
                )

                traceback.print_exc()

                print(
                    "===================================="
                )

                error_message = (
                    "Registration failed. Please try again."
                )

    return render_template(
        "register.html",
        error_message=error_message
    )


# ============================================================
# LOGIN
# ============================================================

@app.route(
    "/login",
    methods=["GET", "POST"]
)
def login():

    # --------------------------------------------------------
    # Already logged in
    # --------------------------------------------------------

    if login_required():

        return redirect(
            url_for("home")
        )

    error_message = ""

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        username = request.form.get(
            "username",
            ""
        ).strip()

        password = request.form.get(
            "password",
            ""
        )

        # ----------------------------------------------------
        # Validation
        # ----------------------------------------------------

        if not username or not password:

            error_message = (
                "Please enter your username and password."
            )

        else:

            try:

                user = authenticate_user(
                    username,
                    password
                )

                if user is None:

                    error_message = (
                        "Invalid username or password."
                    )

                else:

                    # ------------------------------------------------
                    # Create session
                    # ------------------------------------------------

                    session.clear()

                    session["user_id"] = user["id"]

                    session["username"] = user["username"]

                    session["email"] = user["email"]

                    return redirect(
                        url_for("home")
                    )

            except Exception as error:

                print(
                    "========== LOGIN ERROR =========="
                )

                print(
                    f"ERROR: {error}"
                )

                traceback.print_exc()

                print(
                    "================================="
                )

                error_message = (
                    "Login failed. Please try again."
                )

    return render_template(
        "login.html",
        error_message=error_message
    )


# ============================================================
# LOGOUT
# ============================================================

@app.route("/logout")
def logout():

    session.clear()

    return redirect(
        url_for("login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def home():

    if not login_required():

        return redirect(
            url_for("login")
        )

    dashboard_stats = get_dashboard_stats()

    return render_template(
        "index.html",
        dashboard_stats=dashboard_stats
    )


# ============================================================
# PORT SCANNER
# ============================================================

@app.route(
    "/scanner",
    methods=["GET", "POST"]
)
def scanner():

    if not login_required():

        return redirect(
            url_for("login")
        )

    results = []

    target = ""

    risk_level = ""

    recommendations = []

    error_message = ""

    # --------------------------------------------------------
    # Get scan settings
    # --------------------------------------------------------

    scan_type = session.get(
        "scan_type",
        "standard"
    )

    service_detection = session.get(
        "service_detection",
        True
    )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        # ----------------------------------------------------
        # Target validation
        # ----------------------------------------------------

        if not target:

            error_message = (
                "Please enter an IP address or hostname."
            )

        elif not is_valid_target(target):

            error_message = (
                "Invalid IP address or hostname."
            )

        elif not is_target_allowed(target):

            error_message = (
                "This target is not authorized for scanning."
            )

        else:

            try:

                print(
                    "========================================"
                )

                print(
                    "STARTING NMAP SCAN"
                )

                print(
                    f"Target: {target}"
                )

                print(
                    f"Scan type: {scan_type}"
                )

                print(
                    f"Service detection: {service_detection}"
                )

                print(
                    "========================================"
                )

                # ------------------------------------------------
                # Run Nmap
                # ------------------------------------------------

                results = scan_target(
                    target,
                    scan_type=scan_type,
                    service_detection=service_detection
                )

                # ------------------------------------------------
                # Analyze results
                # ------------------------------------------------

                risk_level, recommendations = (
                    analyze_security(
                        results
                    )
                )

                # ------------------------------------------------
                # Save scan
                # ------------------------------------------------

                user_id = session["user_id"]

                save_scan(
                    user_id,
                    target,
                    results,
                    risk_level,
                    recommendations
                )

                print(
                    "========== SCAN COMPLETE =========="
                )

                print(
                    f"Open ports: {len(results)}"
                )

                print(
                    "===================================="
                )

            except Exception as error:

                print(
                    "========== SCAN ERROR =========="
                )

                print(
                    f"ERROR: {error}"
                )

                traceback.print_exc()

                print(
                    "================================"
                )

                results = []

                risk_level = ""

                recommendations = []

                error_message = (
                    f"Scan error: {error}"
                )

    return render_template(
        "scanner.html",

        results=results,

        target=target,

        risk_level=risk_level,

        recommendations=recommendations,

        scan_type=scan_type,

        service_detection=service_detection,

        error_message=error_message
    )


# ============================================================
# SCAN HISTORY
# ============================================================

@app.route("/history")
def history():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    history_data = get_scan_history(
        user_id
    )

    return render_template(
        "history.html",
        history=history_data
    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    history_data = get_scan_history(
        user_id
    )

    return render_template(
        "reports.html",
        history=history_data
    )


# ============================================================
# INDIVIDUAL REPORT
# ============================================================

@app.route(
    "/reports/<int:scan_id>"
)
def report_details(scan_id):

    if not login_required():

        return redirect(
            url_for("login")
        )

    user_id = session["user_id"]

    # --------------------------------------------------------
    # Only allow this user to access their own report
    # --------------------------------------------------------

    scan = get_scan(
        scan_id,
        user_id
    )

    if scan is None:

        return "Report not found", 404

    return render_template(
        "reports.html",
        history=[scan]
    )


# ============================================================
# SETTINGS
# ============================================================

@app.route(
    "/settings",
    methods=["GET", "POST"]
)
def settings():

    if not login_required():

        return redirect(
            url_for("login")
        )

    # --------------------------------------------------------
    # POST
    # --------------------------------------------------------

    if request.method == "POST":

        scan_type = request.form.get(
            "scan_type",
            "standard"
        )

        # ----------------------------------------------------
        # Validate scan type
        # ----------------------------------------------------

        if scan_type not in {
            "quick",
            "standard"
        }:

            scan_type = "standard"

        # ----------------------------------------------------
        # Service detection
        # ----------------------------------------------------

        service_detection = (
            "service_detection"
            in request.form
        )

        # ----------------------------------------------------
        # Save settings to session
        # ----------------------------------------------------

        session["scan_type"] = (
            scan_type
        )

        session["service_detection"] = (
            service_detection
        )

        return render_template(
            "settings.html",

            settings={
                "scan_type":
                    scan_type,

                "service_detection":
                    service_detection
            },

            saved=True
        )

    # --------------------------------------------------------
    # Current settings
    # --------------------------------------------------------

    current_settings = {

        "scan_type":
            session.get(
                "scan_type",
                "standard"
            ),

        "service_detection":
            session.get(
                "service_detection",
                True
            )
    }

    return render_template(
        "settings.html",

        settings=current_settings,

        saved=False
    )


# ============================================================
# ABOUT
# ============================================================

@app.route("/about")
def about():

    return render_template(
        "about.html"
    )


# ============================================================
# HEALTH CHECK
# ============================================================

@app.route("/health")
def health():

    return {
        "status": "ok",
        "service": "SecureScan"
    }


# ============================================================
# START APPLICATION
# ============================================================

if __name__ == "__main__":

    port = int(
        os.environ.get(
            "PORT",
            5000
        )
    )

    app.run(
        host="0.0.0.0",
        port=port,
        debug=False
    )