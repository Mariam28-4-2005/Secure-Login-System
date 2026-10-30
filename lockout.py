
from datetime import datetime, timedelta, timezone
from database import get_db_connection

MAX_ATTEMPTS = 3
LOCKOUT_MINUTES = 5


def get_lock_status(email):
    """Check if login is temporarily locked."""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        cursor.execute(
            """
            SELECT locked_until
            FROM login_attempts
            WHERE email = %s
            """,
            (email,)
        )

        record = cursor.fetchone()

        if not record or not record["locked_until"]:
            return False

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        return record["locked_until"] > now

    finally:
        cursor.close()
        connection.close()


def record_failed_attempt(email):
    """Count failed logins and lock after 3 attempts."""
    connection = get_db_connection()
    cursor = connection.cursor(dictionary=True)

    try:
        now = datetime.now(timezone.utc).replace(tzinfo=None)

        cursor.execute(
            """
            SELECT failed_attempts, locked_until
            FROM login_attempts
            WHERE email = %s
            FOR UPDATE
            """,
            (email,)
        )

        record = cursor.fetchone()

        if record is None:
            attempts = 1
            cursor.execute(
                """
                INSERT INTO login_attempts
                    (email, failed_attempts, locked_until)
                VALUES (%s, %s, NULL)
                """,
                (email, attempts)
            )

        else:
            if record["locked_until"] and record["locked_until"] > now:
                connection.commit()
                return True

            if record["locked_until"] and record["locked_until"] <= now:
                attempts = 1
            else:
                attempts = record["failed_attempts"] + 1

            cursor.execute(
                """
                UPDATE login_attempts
                SET failed_attempts = %s,
                    locked_until = NULL
                WHERE email = %s
                """,
                (attempts, email)
            )

        if attempts >= MAX_ATTEMPTS:
            locked_until = now + timedelta(minutes=LOCKOUT_MINUTES)

            cursor.execute(
                """
                UPDATE login_attempts
                SET locked_until = %s
                WHERE email = %s
                """,
                (locked_until, email)
            )

        connection.commit()
        return attempts >= MAX_ATTEMPTS

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()


def reset_failed_attempts(email):
    """Reset failed attempts after successful OTP verification."""
    connection = get_db_connection()
    cursor = connection.cursor()

    try:
        cursor.execute(
            "DELETE FROM login_attempts WHERE email = %s",
            (email,)
        )
        connection.commit()

    except Exception:
        connection.rollback()
        raise

    finally:
        cursor.close()
        connection.close()
