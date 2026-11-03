from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

from ai_monitor import (
    get_failed_login_events,
    detect_suspicious_logins,
)


def test_database_reading():
    now = datetime.now()

    fake_records = [
        {
            "event_type": "LOGIN_FAILED",
            "ip_address": "127.0.0.1",
            "event_time": now + timedelta(seconds=i * 30),
        }
        for i in range(3)
    ]

    fake_connection = MagicMock()
    fake_cursor = fake_connection.cursor.return_value
    fake_cursor.fetchall.return_value = fake_records

    with patch(
        "database.get_db_connection",
        return_value=fake_connection
    ):
        events = get_failed_login_events()

    assert len(events) == 3
    assert events[0]["event_type"] == "LOGIN_FAILED"
    assert events[0]["time"] == fake_records[0]["event_time"]

    alert = detect_suspicious_logins(events)

    assert alert is not None
    assert alert["alert_type"] == "SUSPICIOUS_LOGIN"
    assert alert["severity"] == "HIGH"
    assert alert["failed_attempts"] == 3

    fake_cursor.close.assert_called_once()
    fake_connection.close.assert_called_once()

    print("DATABASE MOCK TEST PASSED")
    print("SECURITY ALERT TEST PASSED")


if __name__ == "__main__":
    test_database_reading()

# TEST SAVING SECURITY ALERT

from unittest.mock import patch, MagicMock
from ai_monitor import save_security_alert


def test_save_security_alert():
    fake_connection = MagicMock()
    fake_cursor = fake_connection.cursor.return_value

    test_alert = {
        "alert_type": "SUSPICIOUS_LOGIN",
        "severity": "HIGH",
        "description": "3 failed login attempts within 5 minutes",
        "ip_address": "127.0.0.1"
    }

    with patch(
        "database.get_db_connection",
        return_value=fake_connection
    ):
        result = save_security_alert(test_alert)

    assert result is True

    fake_cursor.execute.assert_called_once()

    fake_connection.commit.assert_called_once()
    fake_cursor.close.assert_called_once()
    fake_connection.close.assert_called_once()

    print("SAVE SECURITY ALERT TEST PASSED")


if __name__ == "__main__":
    test_save_security_alert()
from datetime import datetime, timedelta
from ai_monitor import detect_suspicious_logins


def test_normal_login_activity():
    now = datetime.now()

    events = [
        {
            "event_type": "LOGIN_FAILED",
            "ip_address": "127.0.0.1",
            "time": now
        },
        {
            "event_type": "LOGIN_FAILED",
            "ip_address": "127.0.0.1",
            "time": now + timedelta(minutes=6)
        }
    ]

    alert = detect_suspicious_logins(events)

    assert alert is None

    print("NORMAL LOGIN TEST PASSED")



# Test AI behavior when saving an alert fails

from unittest.mock import patch, MagicMock
import bcrypt

from ai_integration import monitor_registration_salt


def test_salt_alert_failure():
    salt = bcrypt.gensalt(rounds=4)

    test_hash = bcrypt.hashpw(
        b"TestPassword123!",
        salt
    ).decode()

    fake_connection = MagicMock()
    fake_cursor = fake_connection.cursor.return_value

    # Simulate an existing hash with the same salt
    fake_cursor.fetchall.return_value = [(test_hash,)]

    with patch(
        "ai_integration.get_db_connection",
        return_value=fake_connection
    ), patch(
        "ai_integration.save_security_alert",
        side_effect=Exception("Simulated database error")
    ):
        result = monitor_registration_salt(test_hash)

    assert result is not None
    assert result["salt_reused"] is True

    print("SALT ALERT FAILURE TEST PASSED")


if __name__ == "__main__":
    test_salt_alert_failure()



