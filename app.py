import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, render_template, redirect, url_for
import mysql.connector
import bcrypt
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(16))

# ---------- DB CONFIG ----------
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "ecofinds"),
    "port": int(os.getenv("DB_PORT", 3306)),
}

def get_db_connection():
    return mysql.connector.connect(**DB_CONFIG)

# ---------- HELPERS ----------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(password, hashed):
    return bcrypt.checkpw(password.encode(), hashed.encode())

def generate_otp():
    return f"{secrets.randbelow(900000) + 100000}"  # 6-digit OTP

def send_email_otp(to_email, otp):
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")

    if not SMTP_USER or not SMTP_PASS:
        print("SMTP credentials not set. Skipping email sending.")
        return

    msg = EmailMessage()
    msg["Subject"] = "EcoFinds OTP Verification"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(f"Your OTP is {otp}. It expires in 10 minutes.")

    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
        smtp.starttls()
        smtp.login(SMTP_USER, SMTP_PASS)
        smtp.send_message(msg)

def store_otp(user_id, otp, ttl=10):
    try:
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO otp_verifications (user_id, otp_code, expires_at) VALUES (%s,%s,%s)",
            (user_id, otp, datetime.utcnow() + timedelta(minutes=ttl)),
        )
        conn.commit()
    except Exception as e:
        print("Error storing OTP:", e)
    finally:
        cur.close()
        conn.close()

# ---------- ROUTES ----------

@app.route("/")
def index():
    return redirect(url_for('register_page'))

@app.route("/register-page")
def register_page():
    return render_template("register.html")  # create this template

@app.route("/login-page")
def login_page():
    return render_template("login.html")  # create this template

@app.route("/verify-page")
def verify_page():
    return render_template("verify_otp.html")  # create this template

@app.route("/verify-forgot-page")
def verify_forgot_page():
    return render_template("verify_forgot_otp.html")  # create this template

@app.route("/reset-password-page")
def reset_password_page():
    return render_template("reset_password.html")  # create this template

@app.route("/dashboard")
def dashboard():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("dashboard.html")  # create this template

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_page"))

# --- Auth API ---

@app.route("/register", methods=["POST"])
def register():
    try:
        data = request.json
        name = data.get("name")
        email = data.get("email")
        password = data.get("password")
        confirm = data.get("confirm")

        if not name or not email or not password or not confirm:
            return jsonify({"error": "All fields are required"}), 400
        if password != confirm:
            return jsonify({"error": "Passwords do not match"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        if cur.fetchone():
            cur.close()
            conn.close()
            return jsonify({"error": "Email already registered"}), 400

        pw_hash = hash_password(password)
        cur.execute(
            "INSERT INTO users (name, email, password_hash, is_email_verified) VALUES (%s,%s,%s,0)",
            (name, email, pw_hash),
        )
        conn.commit()
        user_id = cur.lastrowid
        cur.close()
        conn.close()

        otp = generate_otp()
        print(f"Generated OTP (for testing): {otp}")  # Console print

        send_email_otp(email, otp)
        store_otp(user_id, otp)
        return jsonify({"message": "User registered. OTP sent to email.", "user_id": user_id}), 201

    except Exception as e:
        print("Register error:", e)
        return jsonify({"error": f"Internal server error: {e}"}), 500

@app.route("/verify-otp", methods=["POST"])
def verify_otp():
    try:
        data = request.json
        user_id = data.get("user_id")
        otp = data.get("otp")

        if not user_id or not otp:
            return jsonify({"error": "user_id and otp are required"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT * FROM otp_verifications WHERE user_id=%s AND expires_at > UTC_TIMESTAMP() AND is_used=0 ORDER BY created_at DESC LIMIT 1",
            (user_id,),
        )
        otp_row = cur.fetchone()
        if not otp_row:
            cur.close()
            conn.close()
            return jsonify({"error": "No valid OTP found"}), 400

        if otp_row["otp_code"] != otp:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid OTP"}), 400

        cur.execute("UPDATE users SET is_email_verified=1 WHERE id=%s", (user_id,))
        cur.execute("UPDATE otp_verifications SET is_used=1 WHERE id=%s", (otp_row["id"],))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "OTP verified successfully"}), 200

    except Exception as e:
        print("Verify OTP error:", e)
        return jsonify({"error": f"Internal server error: {e}"}), 500

@app.route("/login", methods=["POST"])
def login():
    try:
        data = request.json
        email = data.get("email")
        password = data.get("password")

        if not email or not password:
            return jsonify({"error": "Email and password required"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = cur.fetchone()
        cur.close()
        conn.close()

        if not user:
            return jsonify({"error": "User not found"}), 404
        if not check_password(password, user["password_hash"]):
            return jsonify({"error": "Incorrect password"}), 400
        if not user["is_email_verified"]:
            return jsonify({"error": "Email not verified"}), 403

        session["user_id"] = user["id"]
        return jsonify({"message": "Login successful", "user_id": user["id"]}), 200

    except Exception as e:
        print("Login error:", e)
        return jsonify({"error": f"Internal server error: {e}"}), 500

@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    try:
        data = request.json
        email = data.get("email")

        if not email:
            return jsonify({"error": "Email is required"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("SELECT id FROM users WHERE email=%s", (email,))
        user = cur.fetchone()

        if not user:
            cur.close()
            conn.close()
            return jsonify({"error": "User not found"}), 404

        user_id = user["id"]
        otp = generate_otp()
        print(f"[Forgot Password] OTP: {otp}")  # Debug/testing only

        send_email_otp(email, otp)

        cur.execute(
            "INSERT INTO otp_verifications (user_id, otp_code, expires_at, type) VALUES (%s, %s, %s, %s)",
            (user_id, otp, datetime.utcnow() + timedelta(minutes=10), 'password_reset')
        )
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "OTP sent to your email", "user_id": user_id}), 200

    except Exception as e:
        print("Forgot Password Error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/verify-forgot-otp", methods=["POST"])
def verify_forgot_otp():
    try:
        data = request.json
        user_id = data.get("user_id")
        otp = data.get("otp")

        if not user_id or not otp:
            return jsonify({"error": "user_id and otp are required"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        cur.execute("""
            SELECT * FROM otp_verifications
            WHERE user_id = %s AND otp_code = %s AND type = 'password_reset'
            AND is_used = 0 AND expires_at > UTC_TIMESTAMP()
            ORDER BY created_at DESC LIMIT 1
        """, (user_id, otp))
        otp_entry = cur.fetchone()

        if not otp_entry:
            cur.close()
            conn.close()
            return jsonify({"error": "Invalid or expired OTP"}), 400

        cur.execute("UPDATE otp_verifications SET is_used = 1 WHERE id = %s", (otp_entry["id"],))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "OTP verified"}), 200

    except Exception as e:
        print("OTP Verify Error:", e)
        return jsonify({"error": "Internal server error"}), 500

@app.route("/reset-password", methods=["POST"])
def reset_password():
    try:
        data = request.json
        user_id = data.get("user_id")
        otp = data.get("otp")
        new_password = data.get("new_password")
        confirm_password = data.get("confirm_password")

        if not all([user_id, otp, new_password, confirm_password]):
            return jsonify({"error": "All fields are required"}), 400

        if new_password != confirm_password:
            return jsonify({"error": "Passwords do not match"}), 400

        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Check that OTP was verified (is_used = 1)
        cur.execute("""
            SELECT * FROM otp_verifications
            WHERE user_id = %s AND otp_code = %s AND type = 'password_reset'
            AND is_used = 1 ORDER BY created_at DESC LIMIT 1
        """, (user_id, otp))
        otp_entry = cur.fetchone()

        if not otp_entry:
            cur.close()
            conn.close()
            return jsonify({"error": "OTP not verified"}), 400

        pw_hash = hash_password(new_password)
        cur.execute("UPDATE users SET password_hash = %s WHERE id = %s", (pw_hash, user_id))
        conn.commit()
        cur.close()
        conn.close()

        return jsonify({"message": "Password reset successfully"}), 200

    except Exception as e:
        print("Reset Password Error:", e)
        return jsonify({"error": "Internal server error"}), 500


# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)
