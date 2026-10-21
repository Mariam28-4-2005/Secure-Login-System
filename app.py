from flask import Flask, render_template, request, flash, redirect
import bcrypt
from database import get_db_connection

app = Flask(__name__)
app.secret_key = "development-only-change-later"


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
                flash("Password verified successfully!")
            else:
                flash("Incorrect email or password.")

        except Exception:
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


if __name__ == "__main__":
    app.run(port=5001, debug=True, use_reloader=False)
