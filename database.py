import sqlite3
import json
import os
from datetime import datetime


# ============================================================
# DATABASE LOCATION
# ============================================================

BASE_DIR = os.path.dirname(
    os.path.abspath(__file__)
)

DATABASE = os.path.join(
    BASE_DIR,
    "securescan.db"
)


# ============================================================
# DATABASE CONNECTION
# ============================================================

def get_connection():

    connection = sqlite3.connect(
        DATABASE
    )

    connection.row_factory = sqlite3.Row

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    connection = get_connection()

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            target TEXT NOT NULL,

            date TEXT NOT NULL,

            risk_level TEXT NOT NULL,

            open_ports INTEGER NOT NULL,

            results TEXT NOT NULL,

            recommendations TEXT NOT NULL
        )
    """)

    connection.commit()

    connection.close()


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    target,
    results,
    risk_level,
    recommendations
):

    connection = get_connection()

    connection.execute(
        """
        INSERT INTO scans
        (
            target,
            date,
            risk_level,
            open_ports,
            results,
            recommendations
        )
        VALUES (?, ?, ?, ?, ?, ?)
        """,

        (
            target,

            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            risk_level,

            len(results),

            json.dumps(results),

            json.dumps(
                recommendations
            )
        )
    )

    connection.commit()

    connection.close()


# ============================================================
# GET SCAN HISTORY
# ============================================================

def get_scan_history():

    connection = get_connection()

    scans = connection.execute(
        """
        SELECT *
        FROM scans
        ORDER BY id DESC
        LIMIT 50
        """
    ).fetchall()

    connection.close()

    history = []

    for scan in scans:

        history.append({

            "id": scan["id"],

            "target": scan["target"],

            "date": scan["date"],

            "risk_level": scan["risk_level"],

            "open_ports": scan["open_ports"],

            "results": json.loads(
                scan["results"]
            ),

            "recommendations": json.loads(
                scan["recommendations"]
            )
        })

    return history


# ============================================================
# GET INDIVIDUAL SCAN
# ============================================================

def get_scan(scan_id):

    connection = get_connection()

    scan = connection.execute(
        """
        SELECT *
        FROM scans
        WHERE id = ?
        """,

        (scan_id,)
    ).fetchone()

    connection.close()

    if scan is None:

        return None

    return {

        "id": scan["id"],

        "target": scan["target"],

        "date": scan["date"],

        "risk_level": scan["risk_level"],

        "open_ports": scan["open_ports"],

        "results": json.loads(
            scan["results"]
        ),

        "recommendations": json.loads(
            scan["recommendations"]
        )
    }


# ============================================================
# INITIALIZE DATABASE ON STARTUP
# ============================================================

init_database()