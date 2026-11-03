import math
from collections import Counter
from datetime import datetime, timedelta

import bcrypt
import numpy as np
from sklearn.ensemble import IsolationForest


# ==========================================
# 1. BCRYPT SALT FEATURE EXTRACTION
# ==========================================

FEATURE_NAMES = [
    "unique_characters",
    "max_character_frequency",
    "character_entropy",
]


def extract_salt_features(password_hash):
    """Extract statistical features from a bcrypt salt."""

    if isinstance(password_hash, bytes):
        password_hash = password_hash.decode("ascii")

    if not isinstance(password_hash, str):
        raise ValueError("Hash must be text or bytes")

    if (
        len(password_hash) != 60
        or password_hash[:4] not in ("$2a$", "$2b$", "$2y$")
        or password_hash[6] != "$"
        or not password_hash[4:6].isdigit()
        or any(
            char not in "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
            for char in password_hash[7:]
        )
    ):
        raise ValueError("Invalid bcrypt hash format")

    salt = password_hash[7:29]
    counts = Counter(salt)

    probabilities = [
        count / len(salt)
        for count in counts.values()
    ]

    entropy = -sum(
        p * math.log2(p)
        for p in probabilities
    )

    return {
        "unique_characters": len(counts),
        "max_character_frequency": max(counts.values()),
        "character_entropy": round(entropy, 4),
    }


# ==========================================
# 2. SALT REUSE DETECTION
# ==========================================

def check_salt_reuse(password_hashes):
    """Count repeated salts across bcrypt hashes."""

    seen_salts = set()
    duplicates = 0

    for password_hash in password_hashes:
        extract_salt_features(password_hash)

        if isinstance(password_hash, bytes):
            password_hash = password_hash.decode("ascii")

        salt = password_hash[7:29]

        if salt in seen_salts:
            duplicates += 1
        else:
            seen_salts.add(salt)

    return duplicates


# ==========================================
# 3. MACHINE LEARNING SALT MONITOR
# ==========================================

def train_salt_model(training_hashes):
    """Train an experimental anomaly detection model."""

    features = np.array([
        [
            extract_salt_features(h)[name]
            for name in FEATURE_NAMES
        ]
        for h in training_hashes
    ])

    model = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42,
    )

    model.fit(features)
    return model


def analyze_salt(model, password_hash):
    """Return an experimental ML assessment."""

    features = extract_salt_features(password_hash)

    values = np.array([[
        features[name]
        for name in FEATURE_NAMES
    ]])

    prediction = int(model.predict(values)[0])
    score = float(model.decision_function(values)[0])

    return {
        "alert_type": "SALT_ANOMALY" if prediction == -1 else None,
        "is_anomaly": prediction == -1,
        "anomaly_score": score,
        "features": features,
    }


# ==========================================
# 4. SUSPICIOUS LOGIN DETECTION
# ==========================================

def detect_suspicious_logins(events):
    """Detect 3 failed logins from one IP within 5 minutes."""

    failed_events = sorted(
        [
            event for event in events
            if event["event_type"] == "LOGIN_FAILED"
        ],
        key=lambda event: event["time"],
    )

    for event in failed_events:
        window_start = event["time"] - timedelta(minutes=5)

        recent_attempts = [
            item for item in failed_events
            if item["ip_address"] == event["ip_address"]
            and window_start <= item["time"] <= event["time"]
        ]

        if len(recent_attempts) >= 3:
            return {
                "alert_type": "SUSPICIOUS_LOGIN",
                "severity": "HIGH",
                "description": "3 or more failed logins within 5 minutes",
                "ip_address": event["ip_address"],
                "failed_attempts": len(recent_attempts),
            }

    return None


# ==========================================
# 5. LOCAL DEMONSTRATION
# ==========================================

def run_demo():
    print("=== AI SECURITY MONITOR DEMO ===")

    test_password = b"DemoPassword123!"

    hash_1 = bcrypt.hashpw(
        test_password, bcrypt.gensalt(rounds=4)
    )
    hash_2 = bcrypt.hashpw(
        test_password, bcrypt.gensalt(rounds=4)
    )

    reused_hash = bcrypt.hashpw(
        b"AnotherTestPassword456!",
        hash_1[:29],
    )

    print("\n1. Bcrypt Salt Test")
    print("Same password:", True)
    print("Same salt:", hash_1[7:29] == hash_2[7:29])
    print("Both passwords verified:",
          bcrypt.checkpw(test_password, hash_1)
          and bcrypt.checkpw(test_password, hash_2))

    print("\n2. Salt Reuse Detection")
    duplicates = check_salt_reuse([
        hash_1, hash_2, reused_hash
    ])
    print("Duplicate salts found:", duplicates)

    print("\n3. AI Salt Anomaly Detection")

    training_hashes = [
        bcrypt.hashpw(
            b"TrainingPassword123!",
            bcrypt.gensalt(rounds=4),
        )
        for _ in range(100)
    ]

    salt_model = train_salt_model(training_hashes)
    result = analyze_salt(salt_model, hash_2)

    print("Anomaly detected:", result["is_anomaly"])
    print("Anomaly score:", result["anomaly_score"])

    print("\n4. Suspicious Login Detection")

    now = datetime.now()

    test_events = [
        {
            "event_type": "LOGIN_FAILED",
            "ip_address": "127.0.0.1",
            "time": now + timedelta(seconds=i * 30),
        }
        for i in range(3)
    ]

    alert = detect_suspicious_logins(test_events)

    if alert:
        print("SECURITY ALERT DETECTED!")
        print("Type:", alert["alert_type"])
        print("Severity:", alert["severity"])
        print("Failed attempts:", alert["failed_attempts"])
    else:
        print("No suspicious login activity.")


if __name__ == "__main__":
    run_demo()

# ==========================================
# 6. READ SECURITY LOGS FROM MYSQL
# ==========================================

def get_failed_login_events():
    """Read failed login events from MySQL."""

    from database import get_db_connection

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            """
            SELECT event_type, ip_address, event_time
            FROM security_logs
            WHERE event_type = %s
            ORDER BY event_time DESC
            LIMIT 1000
            """,
            ("LOGIN_FAILED",)
        )

        records = cursor.fetchall()

        return [
            {
                "event_type": row["event_type"],
                "ip_address": row["ip_address"],
                "time": row["event_time"]
            }
            for row in records
        ]

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# 7. SAVE SECURITY ALERT TO MYSQL

def save_security_alert(alert):
    """Save a security alert to MySQL."""

    from database import get_db_connection

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor()

        cursor.execute(
            """
            INSERT INTO security_alerts
                (alert_type, severity, description, ip_address)
            VALUES (%s, %s, %s, %s)
            """,
            (
                alert["alert_type"],
                alert["severity"],
                alert["description"],
                alert.get("ip_address")
            )
        )

        connection.commit()
        return True

    except Exception:
        if connection:
            connection.rollback()
        raise

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()
