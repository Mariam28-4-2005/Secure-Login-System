
import logging
from datetime import datetime, timedelta

from ai_monitor import (
    get_failed_login_events,
    detect_suspicious_logins,
    save_security_alert,
)
from database import get_db_connection

logger = logging.getLogger(__name__)


def monitor_failed_login(ip_address):
    """Analyze recent failed logins and save a new alert."""

    if not ip_address:
        return None

    try:
        events = get_failed_login_events()

        now = datetime.now()
        recent_events = [
            event for event in events
            if event["ip_address"] == ip_address
            and now - timedelta(minutes=5)
            <= event["time"] <= now
        ]

        alert = detect_suspicious_logins(recent_events)

        if alert is None:
            return None

        # Avoid duplicate alerts for the same IP within 5 minutes
        connection = get_db_connection()
        cursor = None

        try:
            cursor = connection.cursor()
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM security_alerts
                WHERE alert_type = %s
                  AND ip_address = %s
                  AND created_at >= NOW() - INTERVAL 5 MINUTE
                """,
                ("SUSPICIOUS_LOGIN", ip_address)
            )

            existing_count = cursor.fetchone()[0]

        finally:
            if cursor:
                cursor.close()
            connection.close()

        if existing_count > 0:
            return None

        save_security_alert(alert)
        return alert

    except Exception:
        logger.exception("AI login monitoring failed")
        return None


# ==========================================
# REGISTRATION SALT MONITORING
# ==========================================

from pathlib import Path
import joblib
from functools import lru_cache

from ai_monitor import (
    extract_salt_features,
    analyze_salt,
    save_security_alert,
)

MODEL_PATH = Path(__file__).resolve().parent / "salt_model.joblib"

@lru_cache(maxsize=1)
def get_salt_model():
    """Load the trusted local AI model once."""
    return joblib.load(MODEL_PATH)


def monitor_registration_salt(password_hash):
    """Check salt reuse and run experimental ML analysis."""

    try:
        # Validate the bcrypt hash format
        extract_salt_features(password_hash)

        # Read existing hashes from MySQL
        connection = get_db_connection()
        cursor = None

        try:
            cursor = connection.cursor()
            cursor.execute(
                "SELECT password_hash FROM users"
            )
            existing_hashes = [
                row[0] for row in cursor.fetchall()
            ]
        finally:
            if cursor:
                cursor.close()
            connection.close()

        # Check whether the new salt is already in use
        new_salt = password_hash[7:29]

        salt_reused = any(
            existing_hash[7:29] == new_salt
            for existing_hash in existing_hashes
        )


        if salt_reused:
            try:
                save_security_alert({
                    "alert_type": "SALT_REUSE",
                    "severity": "HIGH",
                    "description": "Duplicate bcrypt salt detected during registration",
                    "ip_address": None,
                })
            except Exception:
                logger.exception("Failed to save SALT_REUSE alert")


        # Load locally trained experimental model
        model = get_salt_model()

        result = analyze_salt(model, password_hash)

        if result["is_anomaly"]:
            try:
                save_security_alert({
                    "alert_type": "SALT_ANOMALY",
                    "severity": "LOW",
                    "description": "Experimental AI detected unusual salt features",
                    "ip_address": None,
                })
            except Exception:
                logger.exception("Failed to save SALT_ANOMALY alert")

        return {
            "salt_reused": salt_reused,
            "ai_anomaly": result["is_anomaly"],
            "anomaly_score": result["anomaly_score"],
        }

    except Exception:
        logger.exception("Salt monitoring failed")
        return None
