import os
import ipaddress
import socket

from flask import Flask, render_template, request, session

from scanner.nmap_scanner import scan_target

from database import (
    save_scan,
    get_scan_history,
    get_scan
)


# ============================================================
# APPLICATION
# ============================================================

app = Flask(__name__)

# Never hard-code the production secret key.
app.secret_key = os.environ.get(
    "SECRET_KEY",
    "development-secret-key-change-this"
)


# ============================================================
# SECURITY CONFIGURATION
# ============================================================

# Optional allowlist for production.
#
# Example environment variable:
#
# ALLOWED_TARGETS=scanme.nmap.org,192.168.1.10
#
# Leave empty during local development.
ALLOWED_TARGETS = {
    target.strip().lower()
    for target in os.environ.get(
        "ALLOWED_TARGETS",
        ""
    ).split(",")
    if target.strip()
}


def is_valid_target(target):
    """
    Basic validation for IP addresses and hostnames.
    """

    if not target:
        return False

    if len(target) > 253:
        return False

    # Reject characters that should never appear
    # in a hostname/IP target.
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

    # Try IP address validation.
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        pass

    # Hostname validation.
    try:

        socket.gethostbyname(target)

        return True

    except socket.gaierror:

        return False


def is_target_allowed(target):
    """
    If ALLOWED_TARGETS is configured, only those targets
    can be scanned.
    """

    if not ALLOWED_TARGETS:
        return True

    return target.lower() in ALLOWED_TARGETS


# ============================================================
# SECURITY ANALYSIS
# ============================================================

def analyze_security(results):

    open_ports = len(results)

    recommendations = []

    risky_ports = {
        21: "FTP can expose credentials. Consider using SFTP instead.",
        23: "Telnet is insecure because it sends data without encryption.",
        3389: "RDP should be restricted to trusted networks or protected with a VPN.",
        445: "SMB should not be unnecessarily exposed to untrusted networks."
    }

    for result in results:

        port = result.get("port")

        if port in risky_ports:

            recommendation = risky_ports[port]

            if recommendation not in recommendations:

                recommendations.append(
                    recommendation
                )

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
            "Review open ports and disable services that are not required."
        )

    else:

        risk_level = "HIGH"

        recommendations.append(
            "A large number of open ports were detected. "
            "Review exposed services."
        )

    recommendations.append(
        "Keep network services and software updated."
    )

    return risk_level, recommendations


# ============================================================
# DASHBOARD STATISTICS
# ============================================================

def get_dashboard_stats():

    history_data = get_scan_history()

    total_scans = len(history_data)

    total_open_ports = sum(
        scan.get("open_ports", 0)
        for scan in history_data
    )

    high_risk = sum(
        1
        for scan in history_data
        if scan.get("risk_level", "").upper() == "HIGH"
    )

    medium_risk = sum(
        1
        for scan in history_data
        if scan.get("risk_level", "").upper() == "MEDIUM"
    )

    low_risk = sum(
        1
        for scan in history_data
        if scan.get("risk_level", "").upper() == "LOW"
    )

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

        "total_scans": total_scans,

        "total_open_ports": total_open_ports,

        "high_risk": high_risk,

        "medium_risk": medium_risk,

        "low_risk": low_risk,

        "latest_target": latest_target,

        "latest_risk": latest_risk,

        "latest_date": latest_date
    }


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/")
def home():

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

    results = []

    target = ""

    risk_level = ""

    recommendations = []

    error_message = ""

    scan_type = session.get(
        "scan_type",
        "standard"
    )

    service_detection = session.get(
        "service_detection",
        True
    )

    # --------------------------------------------------------
    # RUN SCAN
    # --------------------------------------------------------

    if request.method == "POST":

        target = request.form.get(
            "target",
            ""
        ).strip()

        # ----------------------------------------------------
        # TARGET VALIDATION
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

                # ------------------------------------------------
                # RUN NMAP
                # ------------------------------------------------

                results = scan_target(
                    target,
                    scan_type=scan_type,
                    service_detection=service_detection
                )

                # ------------------------------------------------
                # ANALYZE RESULTS
                # ------------------------------------------------

                risk_level, recommendations = (
                    analyze_security(results)
                )

                # ------------------------------------------------
                # SAVE RESULT
                # ------------------------------------------------

                save_scan(
                    target,
                    results,
                    risk_level,
                    recommendations
                )

            except Exception:

                # Don't expose internal server/Nmap errors
                # to public users.

                results = []

                risk_level = ""

                recommendations = []

                error_message = (
                    "The scan could not be completed. "
                    "Please verify the target and try again."
                )

    # --------------------------------------------------------
    # PAGE
    # --------------------------------------------------------

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

    history_data = get_scan_history()

    return render_template(
        "history.html",
        history=history_data
    )


# ============================================================
# REPORTS
# ============================================================

@app.route("/reports")
def reports():

    history_data = get_scan_history()

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

    scan = get_scan(scan_id)

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

    if request.method == "POST":

        scan_type = request.form.get(
            "scan_type",
            "standard"
        )

        # Only allow known scan types.

        if scan_type not in {
            "quick",
            "standard"
        }:

            scan_type = "standard"

        service_detection = (
            "service_detection"
            in request.form
        )

        session["scan_type"] = scan_type

        session["service_detection"] = (
            service_detection
        )

        return render_template(
            "settings.html",

            settings={
                "scan_type": scan_type,

                "service_detection":
                    service_detection
            },

            saved=True
        )

    current_settings = {

        "scan_type": session.get(
            "scan_type",
            "standard"
        ),

        "service_detection": session.get(
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