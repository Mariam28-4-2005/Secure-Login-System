
import os
import ssl
import secrets
import smtplib
from email.message import EmailMessage


# Generate a secure 6-digit OTP
def generate_otp():
    return str(secrets.randbelow(900000) + 100000)


# Send OTP to the user's registered email
def send_otp(email, otp):
    sender = os.environ["SMTP_EMAIL"]
    password = os.environ["SMTP_PASSWORD"]

    message = EmailMessage()
    message["Subject"] = "Your Secure Login Verification Code"
    message["From"] = sender
    message["To"] = email

    message.set_content(
        "Your verification code is: " + otp +
        "\nThis code expires in 5 minutes."
    )

    with smtplib.SMTP("smtp.gmail.com", 587, timeout=15) as server:
     server.ehlo()
     server.starttls(context=ssl.create_default_context())
     server.ehlo()
     server.login(sender, password)
     server.send_message(message)
