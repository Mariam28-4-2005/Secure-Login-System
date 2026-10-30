from flask import Flask, render_template, request, flash, redirect, session
import bcrypt
import os
import time
import secrets
import hashlib
from dotenv import load_dotenv

from database import get_db_connection
from otp import generate_otp, send_otp
from lockout import (
    get_lock_status,
    record_failed_attempt,
    reset_failed_attempts
) 
from security import log_security_event

# Load environment variables from .env
load_dotenv(override=True)

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]


# Login Page

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not email or not password:
            flash("Please enter your email and password.")
            return render_template("login.html")

        connection = None
        cursor = None

        try:
            # Check account lockout before password verification
            if get_lock_status(email):
                flash("Too many failed attempts. Please try again after 5 minutes.")
                return redirect("/login")

            connection = get_db_connection()
            cursor = connection.cursor(dictionary=True)

            cursor.execute(
                "SELECT id, email, password_hash FROM users WHERE email = %s",
                (email,)
            )

            user = cursor.fetchone()

            if user and bcrypt.checkpw(
                password.encode("utf-8"),
                user["password_hash"].encode("utf-8")
            ):
                session.clear()

                otp = generate_otp()

                session["pending_user_id"] = user["id"]
                session["otp_hash"] = hashlib.sha256(
                    otp.encode("utf-8")
                ).hexdigest()
                session["otp_expires"] = time.time() + 300
                session["otp_attempts"] = 0

                send_otp(user["email"], otp)

                flash("Verification code sent to your email.")
                return redirect("/verify-otp")

            else:
                locked = record_failed_attempt(email)
                
                log_security_event(
                    "LOGIN_FAILED",
                    user_id=user["id"] if user else None,
                    email=email,
                    ip_address=request.remote_addr
                )
                if locked:
                    log_security_event(
                    "ACCOUNT_LOCKED",
                    user_id=user["id"] if user else None,
                    email=email,
                    ip_address=request.remote_addr
                    )
                    flash("Account temporarily locked for 5 minutes.")
                else:
                    flash("Incorrect email or password.")

        except Exception:
            session.clear()
            app.logger.exception("Login failed")
            flash("Something went wrong. Please try again.")

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("login.html")


# Registration Page
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return render_template("register.html")

        if len(password) < 8:
            flash("Password must be at least 8 characters.")
            return render_template("register.html")

        connection = None
        cursor = None

        try:
            connection = get_db_connection()
            cursor = connection.cursor()

            cursor.execute(
                "SELECT id FROM users WHERE email = %s",
                (email,)
            )

            if cursor.fetchone():
                flash("This email is already registered.")
                return render_template("register.html")

            # Hash password with bcrypt and random salt
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt()
            ).decode("utf-8")

            # Save user in MySQL
            cursor.execute(
                """
                INSERT INTO users (name, email, password_hash)
                VALUES (%s, %s, %s)
                """,
                (name, email, password_hash)
            )

            connection.commit()

            flash("Account created successfully! Please log in.")
            return redirect("/login")


        except Exception as e:
             print("REGISTRATION ERROR:", type(e).__name__, flush=True)
             app.logger.exception("Registration failed")
             flash("Registration failed. Please try again.")
 

        finally:
            if cursor:
                cursor.close()
            if connection:
                connection.close()

    return render_template("register.html")


# OTP Verification
@app.route("/verify-otp", methods=["GET", "POST"])
def verify_otp():
    if not session.get("pending_user_id"):
        return redirect("/login")

    if request.method == "POST":
        entered_otp = request.form.get("otp", "").strip()

        if time.time() > session.get("otp_expires", 0):
            session.clear()
            flash("OTP expired. Please log in again.")
            return redirect("/login")

        attempts = session.get("otp_attempts", 0) + 1
        session["otp_attempts"] = attempts

        if attempts > 3:
            session.clear()
            flash("Too many OTP attempts. Please log in again.")
            return redirect("/login")

        entered_hash = hashlib.sha256(
            entered_otp.encode("utf-8")
        ).hexdigest()

        if (
            len(entered_otp) == 6
            and entered_otp.isdigit()
            and secrets.compare_digest(
                entered_hash,
                session.get("otp_hash", "")
            )
        ):
            user_id = session["pending_user_id"]

            connection = None
            cursor = None

            try:
                connection = get_db_connection()
                cursor = connection.cursor(dictionary=True)

                cursor.execute(
                    "SELECT email FROM users WHERE id = %s",
                    (user_id,)
                )

                user = cursor.fetchone()

                if not user:
                    session.clear()
                    flash("User not found. Please log in again.")
                    return redirect("/login")

                reset_failed_attempts(user["email"])

            except Exception:
                app.logger.exception("Failed to reset login attempts")
                session.clear()
                flash("Verification could not be completed. Please try again.")
                return redirect("/login")

            finally:
                if cursor:
                   cursor.close()
                if connection:
                   connection.close()

            session.clear()
            session["user_id"] = user_id
            session["otp_verified"] = True
            
            log_security_event(
                "OTP_SUCCESS",
                user_id=user_id,
                email=user["email"],
                ip_address=request.remote_addr
            )

            log_security_event(
                "LOGIN_SUCCESS",
                user_id=user_id,
                email=user["email"],
                ip_address=request.remote_addr
            )

            return redirect("/dashboard")

        if attempts >= 3:
            session.clear()
            flash("Too many OTP attempts. Please log in again.")
            return redirect("/login")

        flash("Incorrect OTP. Please try again.")

    return render_template("verify_otp.html")


# Dashboard Page
@app.route("/dashboard")
def dashboard():
    if not session.get("otp_verified"):
        flash("Please complete login verification first.")
        return redirect("/login")

    user_id = session.get("user_id")

    if not user_id:
        return redirect("/login")

    connection = None
    cursor = None

    try:
        connection = get_db_connection()
        cursor = connection.cursor(dictionary=True)

        cursor.execute(
            "SELECT id, name, email FROM users WHERE id = %s",
            (user_id,)
        )

        user = cursor.fetchone()

        if not user:
            session.clear()
            return redirect("/login")

        return render_template("dashboard.html", user=user)

    except Exception:
        app.logger.exception("Dashboard failed")
        flash("Unable to load dashboard.")
        return redirect("/login")

    finally:
        if cursor:
            cursor.close()
        if connection:
            connection.close()

# Logout
@app.route("/logout")
def logout():
    user_id = session.get("user_id")

    session.clear()

    if user_id:
        log_security_event(
            "LOGOUT",
            user_id=user_id,
            ip_address=request.remote_addr
        )

    flash("You have been logged out successfully.")
    return redirect("/login")

if __name__ == "__main__":
    app.run(port=5001, debug=True, use_reloader=False)
