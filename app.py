import os
import secrets
from datetime import datetime, timedelta
from flask import Flask, request, jsonify, session, render_template, redirect, url_for, flash
import mysql.connector
import bcrypt
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv
from werkzeug.utils import secure_filename

load_dotenv()

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

UPLOAD_FOLDER = os.path.join(os.getcwd(), 'static', 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize Flask app FIRST
app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET", secrets.token_hex(16))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

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

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ---------- ROUTES ----------

@app.route("/")
def index():
    return redirect(url_for('register_page'))

@app.route("/register-page")
def register_page():
    return render_template("register.html")

@app.route("/login-page")
def login_page():
    return render_template("login.html")

@app.route("/verify-page")
def verify_page():
    return render_template("verify_otp.html")

@app.route("/verify-forgot-page")
def verify_forgot_page():
    return render_template("verify_forgot_otp.html")

@app.route("/reset-password-page")
def reset_password_page():
    return render_template("reset_password.html")
# ---------------- DASHBOARD ROUTE ----------------
@app.route("/dashboard", methods=["GET"])
def dashboard():
    if "user_id" not in session:
        flash("You must be logged in to access the dashboard.", "error")
        return redirect(url_for("login_page"))

    category = request.args.get("category", "")
    name = request.args.get("name", "")

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    query = """
        SELECT p.id, p.title, p.price, p.category, u.name AS seller_name
        FROM products p
        JOIN users u ON p.user_id = u.id
        WHERE 1=1
    """
    params = []

    if category:
        query += " AND p.category = %s"
        params.append(category)

    if name:
        query += " AND p.title LIKE %s"
        params.append(f"%{name}%")

    cur.execute(query, tuple(params))
    products = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("dashboard.html", products=products)

@app.route("/product/<int:product_id>")
def product_details(product_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM products WHERE id=%s", (product_id,))
    product = cur.fetchone()

    if not product:
        cur.close()
        conn.close()
        return "Product not found", 404

    cur.execute("SELECT image_path FROM product_images WHERE product_id=%s", (product_id,))
    images = cur.fetchall()
    product["images"] = [img["image_path"] for img in images]

    cur.close()
    conn.close()
    return render_template("product_details.html", product=product)

@app.route("/profile")
def profile():
    if "user_id" not in session:
        flash("You must be logged in to view your profile.", "error")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT * FROM users WHERE id = %s", (session["user_id"],))
    user = cur.fetchone()
    cur.close()
    conn.close()

    return render_template("profile.html", user=user)

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
        print(f"Generated OTP (for testing): {otp}")

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
        print(f"[Forgot Password] OTP: {otp}")

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

# --------- Product Add / Edit / Delete Routes ---------

@app.route("/add-product", methods=["GET"])
def add_product_page():
    if "user_id" not in session:
        return redirect(url_for("login_page"))
    return render_template("add_product.html")

@app.route("/add-product", methods=["POST"])
def add_product():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]
    title = request.form.get("title")
    description = request.form.get("description")
    category = request.form.get("category")
    price = request.form.get("price")
    contact = request.form.get("contact")

    if not all([title, price, contact]):
        return jsonify({"error": "Title, price, and contact are required"}), 400

    try:
        price = float(price)
    except ValueError:
        return jsonify({"error": "Invalid price format"}), 400

    conn = get_db_connection()
    cur = conn.cursor()

    cur.execute("""
        INSERT INTO products (user_id, title, description, category, price, contact)
        VALUES (%s, %s, %s, %s, %s, %s)
    """, (user_id, title, description, category, price, contact))
    conn.commit()
    product_id = cur.lastrowid

    # Save images
    files = request.files.getlist("images")
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            # To avoid overwriting files, prepend unique token
            unique_prefix = secrets.token_hex(8)
            filename = f"{unique_prefix}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            relative_path = f"uploads/{filename}"
            cur.execute(
                "INSERT INTO product_images (product_id, image_path) VALUES (%s, %s)",
                (product_id, relative_path)
            )
    conn.commit()
    cur.close()
    conn.close()

    return redirect(url_for("dashboard"))

@app.route("/my-products")
def my_products():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("""
        SELECT * FROM products WHERE user_id = %s ORDER BY created_at DESC
    """, (user_id,))
    products = cur.fetchall()

    # Fetch images for each product
    for product in products:
        cur.execute("SELECT image_path FROM product_images WHERE product_id = %s", (product["id"],))
        images = cur.fetchall()
        product["images"] = images

    cur.close()
    conn.close()

    return render_template("my_products.html", products=products)

@app.route("/edit-product/<int:product_id>", methods=["GET"])
def edit_product_page(product_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    user_id = session["user_id"]
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    cur.execute("SELECT * FROM products WHERE id = %s AND user_id = %s", (product_id, user_id))
    product = cur.fetchone()

    if not product:
        cur.close()
        conn.close()
        return "Product not found or unauthorized", 404

    cur.execute("SELECT id, image_path FROM product_images WHERE product_id = %s", (product_id,))
    images = cur.fetchall()

    cur.close()
    conn.close()

    return render_template("edit_product.html", product=product, images=images)

@app.route("/edit-product/<int:product_id>", methods=["POST"])
def edit_product(product_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]
    title = request.form.get("title")
    description = request.form.get("description")
    category = request.form.get("category")
    price = request.form.get("price")
    contact = request.form.get("contact")

    if not all([title, price, contact]):
        flash("Title, price, and contact are required", "error")
        return redirect(url_for("edit_product_page", product_id=product_id))

    try:
        price = float(price)
    except ValueError:
        flash("Invalid price format", "error")
        return redirect(url_for("edit_product_page", product_id=product_id))

    conn = get_db_connection()
    cur = conn.cursor()

    # Check ownership
    cur.execute("SELECT id FROM products WHERE id=%s AND user_id=%s", (product_id, user_id))
    if not cur.fetchone():
        cur.close()
        conn.close()
        return jsonify({"error": "Product not found or unauthorized"}), 404

    # Update product info
    cur.execute("""
        UPDATE products
        SET title=%s, description=%s, category=%s, price=%s, contact=%s
        WHERE id=%s
    """, (title, description, category, price, contact, product_id))
    conn.commit()

    # Save new images if any
    files = request.files.getlist("images")
    for file in files:
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            unique_prefix = secrets.token_hex(8)
            filename = f"{unique_prefix}_{filename}"
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)

            relative_path = f"uploads/{filename}"
            cur.execute(
                "INSERT INTO product_images (product_id, image_path) VALUES (%s, %s)",
                (product_id, relative_path)
            )
    conn.commit()
    cur.close()
    conn.close()

    flash("Product updated successfully", "success")
    return redirect(url_for("my_products"))

@app.route("/delete-product/<int:product_id>", methods=["POST"])
def delete_product(product_id):
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401

    user_id = session["user_id"]

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    # Verify ownership
    cur.execute("SELECT * FROM products WHERE id = %s AND user_id = %s", (product_id, user_id))
    product = cur.fetchone()
    if not product:
        cur.close()
        conn.close()
        return jsonify({"error": "Product not found or unauthorized"}), 404

    # Get images for product to delete files
    cur.execute("SELECT image_path FROM product_images WHERE product_id = %s", (product_id,))
    images = cur.fetchall()

    # Delete images from filesystem
    for img in images:
        image_full_path = os.path.join(app.static_folder, img["image_path"])
        if os.path.exists(image_full_path):
            os.remove(image_full_path)

    # Delete product images records
    cur.execute("DELETE FROM product_images WHERE product_id = %s", (product_id,))

    # Delete product record
    cur.execute("DELETE FROM products WHERE id = %s", (product_id,))

    conn.commit()
    cur.close()
    conn.close()

    flash("Product deleted successfully", "success")
    return redirect(url_for("my_products"))

@app.route("/all-products")
def all_products():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)

    try:
        cur.execute("""
            SELECT
                p.id, p.title, p.description, p.category, p.price,
                u.name AS seller_name, u.email AS seller_email
            FROM products p
            JOIN users u ON p.user_id = u.id
            ORDER BY p.created_at DESC
        """)
        products = cur.fetchall()

        # Debug: check data in console
        print(f"[DEBUG] fetched {len(products)} products")

        for product in products:
            cur.execute(
                "SELECT image_path FROM product_images WHERE product_id=%s",
                (product["id"],)
            )
            imgs = cur.fetchall()
            product["images"] = [i["image_path"] for i in imgs]

        return render_template("all_products.html", products=products)

    except Exception as e:
        print("Error in all_products route:", e)
        flash("Failed to load products.", "error")
        return render_template("all_products.html", products=[])

    finally:
        cur.close()
        conn.close()

@app.route("/buy-product/<int:product_id>", methods=["POST"])
def buy(product_id):
    if "user_id" not in session:
        flash("You must be logged in to express interest.", "error")
        return redirect(url_for("login_page"))
    

    buyer_id = session["user_id"]

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Fetch product and seller details
        cur.execute("""
            SELECT p.title, u.name AS seller_name, u.email AS seller_email
            FROM products p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = %s
        """, (product_id,))
        product = cur.fetchone()
        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("all_products"))

        # Fetch buyer details
        cur.execute(
            "SELECT name, email FROM users WHERE id = %s",
            (buyer_id,)
        )
        buyer = cur.fetchone()
        if not buyer:
            flash("Buyer information not found.", "error")
            return redirect(url_for("all_products"))

        # Compose email
        subject = f"[EcoFinds] Interest in \"{product['title']}\""
        body = f"""Hello {product['seller_name']},

You have a buyer interested in your product:

Product: {product['title']}
Buyer: {buyer['name']} ({buyer['email']})

Please contact them to proceed.

Thank you for using EcoFinds!
"""
        print(f"[DEBUG] Sending email to {product['seller_email']}")
        send_email_otp(product['seller_email'], body, subject_override=subject)

        flash("Your interest has been sent to the seller!", "success")
        return redirect(url_for("all_products"))

    except Exception as err:
        print("Buy route error:", err)
        flash("Failed to send interest. Please try again later.", "error")
        return redirect(url_for("all_products"))

    finally:
        if cur:
            cur.close()
        if conn:
            conn.close()

def send_email_otp(to_email, message, subject_override=None):
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")

    if not SMTP_USER or not SMTP_PASS:
        print("SMTP credentials not set; skipping email.")
        return

    msg = EmailMessage()
    msg["Subject"] = subject_override or "EcoFinds Notification"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(message)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
    except Exception as e:
        print("Email send failure:", e)

# ---------------- ADD TO CART ----------------
@app.route("/add-to-cart/<int:product_id>", methods=["POST"])
def add_to_cart(product_id):
    if "user_id" not in session:
        flash("Please log in to add to cart.", "error")
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("INSERT INTO cart_items (user_id, product_id) VALUES (%s, %s)",
                (session["user_id"], product_id))
    conn.commit()
    cur.close()
    conn.close()

    flash("Product added to cart!", "success")
    return redirect(url_for("all_products"))


# ---------------- VIEW CART ----------------
@app.route("/cart")
def view_cart():
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT c.id AS cart_id, p.id AS product_id, p.title, p.price, u.name AS seller_name, u.email AS seller_email
        FROM cart_items c
        JOIN products p ON c.product_id = p.id
        JOIN users u ON p.user_id = u.id
        WHERE c.user_id = %s
    """, (session["user_id"],))
    cart_items = cur.fetchall()
    cur.close()
    conn.close()

    return render_template("cart.html", cart_items=cart_items)


# ---------------- STEP 1: Confirm Buy ----------------
@app.route("/buy/<int:product_id>", methods=["GET", "POST"])
def buy_product(product_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("""
        SELECT p.id, p.title, p.price, u.name AS seller_name, u.email AS seller_email
        FROM products p
        JOIN users u ON p.user_id = u.id
        WHERE p.id = %s
    """, (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()

    if not product:
        flash("Product not found.", "error")
        return redirect(url_for("view_cart"))

    if request.method == "POST":
        payment_type = request.form.get("payment_type")
        if payment_type == "UPI":
            return redirect(url_for("upi_payment", product_id=product_id))
        elif payment_type == "Card":
            return redirect(url_for("card_payment", product_id=product_id))

    return render_template("buy_confirm.html", product=product)


# ---------------- STEP 2A: UPI Payment ----------------
@app.route("/upi-payment/<int:product_id>", methods=["GET", "POST"])
def upi_payment(product_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, title, price FROM products WHERE id=%s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()

    if request.method == "POST":
        upi_id = request.form.get("upi_id")
        return redirect(url_for("verify_upi", product_id=product_id, upi_id=upi_id))

    return render_template("upi_payment.html", product=product)


# ---------------- STEP 2B: Card Payment ----------------
@app.route("/card-payment/<int:product_id>", methods=["GET", "POST"])
def card_payment(product_id):
    if "user_id" not in session:
        return redirect(url_for("login_page"))

    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, title, price FROM products WHERE id=%s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()

    if request.method == "POST":
        card_number = request.form.get("card_number")
        return redirect(url_for("verify_card", product_id=product_id, card_number=card_number))

    return render_template("card_payment.html", product=product)


@app.route("/verify-upi/<int:product_id>", methods=["GET"])
def verify_upi(product_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, title, price FROM products WHERE id=%s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("verify_upi.html", product=product)


@app.route("/verify-card/<int:product_id>", methods=["GET"])
def verify_card(product_id):
    conn = get_db_connection()
    cur = conn.cursor(dictionary=True)
    cur.execute("SELECT id, title, price FROM products WHERE id=%s", (product_id,))
    product = cur.fetchone()
    cur.close()
    conn.close()
    return render_template("verify_card.html", product=product)




import traceback
from datetime import datetime  # keep this import

@app.route("/finalize-payment/<int:product_id>", methods=["POST"])
def finalize_payment(product_id):
    if "user_id" not in session:
        flash("You must be logged in to complete payment.", "error")
        return redirect(url_for("login_page"))

    buyer_id = session["user_id"]
    payment_type = request.form.get("payment_type")

    conn = None
    cur = None
    try:
        conn = get_db_connection()
        cur = conn.cursor(dictionary=True)

        # Fetch product
        cur.execute("""
            SELECT p.title, p.price, u.name AS seller_name, u.email AS seller_email
            FROM products p
            JOIN users u ON p.user_id = u.id
            WHERE p.id = %s
        """, (product_id,))
        product = cur.fetchone()
        if not product:
            flash("Product not found.", "error")
            return redirect(url_for("all_products"))

        # Fetch buyer
        cur.execute("SELECT name, email FROM users WHERE id = %s", (buyer_id,))
        buyer = cur.fetchone()
        if not buyer:
            flash("Buyer not found.", "error")
            return redirect(url_for("all_products"))

        # Generate order ID
        order_id = f"ORD{product_id}{buyer_id}{int(datetime.now().timestamp())}"

        # --- Send Buyer Email ---
        buyer_subject = f"[EcoFinds] Order Confirmation - {product['title']}"
        buyer_body = f"""Hello {buyer['name']},

✅ Your payment is confirmed!

Order ID: {order_id}
Product: {product['title']}
Price: ₹{product['price']}
Payment Method: {payment_type}

Thank you for booking with EcoFinds!
"""
        send_email_notification(buyer['email'], buyer_body, subject_override=buyer_subject)

        # --- Send Seller Email ---
        seller_subject = "[EcoFinds] Your product has been booked!"
        seller_body = f"""Hello {product['seller_name']},

Your product has been successfully booked by a buyer.

Order ID: {order_id}
Product: {product['title']}
Buyer: {buyer['name']} ({buyer['email']})

Please remove this product from your listing.

Thank you for using EcoFinds!
"""
        send_email_notification(product['seller_email'], seller_body, subject_override=seller_subject)

        # --- Flash Green Success Message ---
        flash("✅ Your payment is confirmed!", "success")

        # Show success page
        return render_template("payment_success.html",
                               order_id=order_id,
                               product=product,
                               payment_type=payment_type)

    except Exception as e:
        print("❌ Finalize payment error:", e)
        return redirect(url_for("all_products"))
    finally:
        if cur: cur.close()
        if conn: conn.close()


def send_email_notification(to_email, message, subject_override=None):
    """
    Generic email sender for normal notifications (order confirmations, etc.)
    Uses SMTP_* env vars. Safe to call with plain text message.
    """
    SMTP_HOST = os.getenv("SMTP_HOST")
    SMTP_PORT = int(os.getenv("SMTP_PORT", 587))
    SMTP_USER = os.getenv("SMTP_USER")
    SMTP_PASS = os.getenv("SMTP_PASS")

    if not (SMTP_HOST and SMTP_USER and SMTP_PASS):
        print("[EMAIL] SMTP credentials not set; skipping email.")
        return

    msg = EmailMessage()
    msg["Subject"] = subject_override or "EcoFinds Notification"
    msg["From"] = SMTP_USER
    msg["To"] = to_email
    msg.set_content(message)

    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            smtp.send_message(msg)
        print(f"[EMAIL] Sent to {to_email} with subject '{msg['Subject']}'")
    except Exception as e:
        print("[EMAIL] Send failure:", e)
 


 
# ---------- RUN ----------
if __name__ == "__main__":
    app.run(debug=True)