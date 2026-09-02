import sqlite3
import json
import os
from datetime import datetime

from werkzeug.security import generate_password_hash, check_password_hash


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

    # Enable foreign keys
    connection.execute(
        "PRAGMA foreign_keys = ON"
    )

    return connection


# ============================================================
# INITIALIZE DATABASE
# ============================================================

def init_database():

    connection = get_connection()

    # ========================================================
    # USERS TABLE
    # ========================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS users (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            username TEXT NOT NULL UNIQUE,

            email TEXT NOT NULL UNIQUE,

            password_hash TEXT NOT NULL,

            created_at TEXT NOT NULL
        )
    """)

    # ========================================================
    # SCANS TABLE
    # ========================================================

    connection.execute("""
        CREATE TABLE IF NOT EXISTS scans (

            id INTEGER PRIMARY KEY AUTOINCREMENT,

            user_id INTEGER,

            target TEXT NOT NULL,

            date TEXT NOT NULL,

            risk_level TEXT NOT NULL,

            open_ports INTEGER NOT NULL,

            results TEXT NOT NULL,

            recommendations TEXT NOT NULL,

            FOREIGN KEY (user_id)
                REFERENCES users(id)
                ON DELETE CASCADE
        )
    """)

    # ========================================================
    # DATABASE MIGRATION
    # ========================================================
    #
    # If your old scans table was created before login,
    # add user_id automatically.
    #

    columns = connection.execute(
        "PRAGMA table_info(scans)"
    ).fetchall()

    column_names = [
        column["name"]
        for column in columns
    ]

    if "user_id" not in column_names:

        connection.execute("""
            ALTER TABLE scans
            ADD COLUMN user_id INTEGER
        """)

    connection.commit()

    connection.close()


# ============================================================
# CREATE USER
# ============================================================

def create_user(
    username,
    email,
    password
):

    connection = get_connection()

    password_hash = generate_password_hash(
        password
    )

    try:

        cursor = connection.execute(
            """
            INSERT INTO users
            (
                username,
                email,
                password_hash,
                created_at
            )
            VALUES (?, ?, ?, ?)
            """,

            (
                username,
                email,
                password_hash,
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )
        )

        connection.commit()

        return cursor.lastrowid

    except sqlite3.IntegrityError:

        return None

    finally:

        connection.close()


# ============================================================
# AUTHENTICATE USER
# ============================================================

def authenticate_user(username, password):

    connection = get_connection()

    user = connection.execute(
        """
        SELECT *
        FROM users
        WHERE username = ?
        """,
        (username,)
    ).fetchone()

    print("========== LOGIN DEBUG ==========")
    print("Username entered:", username)
    print("User found:", user is not None)

    if user is not None:
        print("User ID:", user["id"])
        print("Stored email:", user["email"])
        print("Password hash exists:", bool(user["password_hash"]))

    connection.close()

    if user is None:
        return None

    try:
        password_valid = check_password_hash(
            user["password_hash"],
            password
        )

        print("Password valid:", password_valid)

    except Exception as error:
        print("Password check error:", error)
        return None

    if not password_valid:
        return None

    return {
        "id": user["id"],
        "username": user["username"],
        "email": user["email"]
    }
# ============================================================
# GET USER
# ============================================================

def get_user(user_id):

    connection = get_connection()

    user = connection.execute(
        """
        SELECT
            id,
            username,
            email,
            created_at
        FROM users
        WHERE id = ?
        """,

        (user_id,)
    ).fetchone()

    connection.close()

    if user is None:

        return None

    return {

        "id": user["id"],

        "username": user["username"],

        "email": user["email"],

        "created_at": user["created_at"]
    }


# ============================================================
# SAVE SCAN
# ============================================================

def save_scan(
    user_id,
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
            user_id,
            target,
            date,
            risk_level,
            open_ports,
            results,
            recommendations
        )
        VALUES (?, ?, ?, ?, ?, ?, ?)
        """,

        (
            user_id,

            target,

            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

            risk_level,

            len(results),

            json.dumps(
                results
            ),

            json.dumps(
                recommendations
            )
        )
    )

    connection.commit()

    connection.close()


# ============================================================
# GET USER SCAN HISTORY
# ============================================================

def get_scan_history(user_id):

    connection = get_connection()

    scans = connection.execute(
        """
        SELECT
            id,
            user_id,
            target,
            date,
            risk_level,
            open_ports,
            results,
            recommendations
        FROM scans
        WHERE user_id = ?
        ORDER BY id DESC
        LIMIT 50
        """,

        (user_id,)
    ).fetchall()

    connection.close()

    history = []

    for scan in scans:

        try:

            results = json.loads(
                scan["results"]
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            results = []

        try:

            recommendations = json.loads(
                scan["recommendations"]
            )

        except (
            json.JSONDecodeError,
            TypeError
        ):

            recommendations = []

        history.append({

            "id":
                scan["id"],

            "user_id":
                scan["user_id"],

            "target":
                scan["target"],

            "date":
                scan["date"],

            "risk_level":
                scan["risk_level"],

            "open_ports":
                scan["open_ports"],

            "results":
                results,

            "recommendations":
                recommendations
        })

    return history


# ============================================================
# GET INDIVIDUAL USER SCAN
# ============================================================

def get_scan(
    scan_id,
    user_id
):

    connection = get_connection()

    scan = connection.execute(
        """
        SELECT
            id,
            user_id,
            target,
            date,
            risk_level,
            open_ports,
            results,
            recommendations
        FROM scans
        WHERE id = ?
        AND user_id = ?
        """,

        (
            scan_id,
            user_id
        )
    ).fetchone()

    connection.close()

    if scan is None:

        return None

    try:

        results = json.loads(
            scan["results"]
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):

        results = []

    try:

        recommendations = json.loads(
            scan["recommendations"]
        )

    except (
        json.JSONDecodeError,
        TypeError
    ):

        recommendations = []

    return {

        "id":
            scan["id"],

        "user_id":
            scan["user_id"],

        "target":
            scan["target"],

        "date":
            scan["date"],

        "risk_level":
            scan["risk_level"],

        "open_ports":
            scan["open_ports"],

        "results":
            results,

        "recommendations":
            recommendations
    }


# ============================================================
# INITIALIZE DATABASE
# ============================================================

init_database()