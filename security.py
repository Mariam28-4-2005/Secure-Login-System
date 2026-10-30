
import logging
from database import get_db_connection

logger = logging.getLogger(__name__)

ALLOWED_EVENTS = {
    "LOGIN_SUCCESS",
    "LOGIN_FAILED",
    "ACCOUNT_LOCKED",
    "OTP_SUCCESS",
    "OTP_FAILED",
    "LOGOUT",
}


def log_security_event(event_type, user_id=None, email=None, ip_address=None):
    """Store an authentication security event in MySQL."""

    if event_type not in ALLOWED_EVENTS:
        raise ValueError("Unsupported security event type")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO security_logs
                (user_id, event_type, email, ip_address)
            VALUES (%s, %s, %s, %s)
            """,
            (user_id, event_type, email, ip_address)
        )

        connection.commit()

    except Exception:
        if connection:
            connection.rollback()

        logger.exception("Failed to save security event")
        # Logging failure must not expose credentials.

    finally:
        if cursor:
            cursor.close()

        if connection:
            connection.close()
