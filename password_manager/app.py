import os
import random
import string

from cryptography.fernet import Fernet
from flask import (Flask, flash, jsonify, redirect, render_template, request,
                   session, url_for)

app = Flask(__name__)
app.secret_key = "supersecretkey"
# Admin Credentials
ADMIN_USERNAME = "admin"
ADMIN_PASSWORD = "admin123"
# Generate or load encryption key
if not os.path.exists("key.key"):
    with open("key.key", "wb") as key_file:
        key_file.write(Fernet.generate_key())
with open("key.key", "rb") as key_file:
    key = key_file.read()
cipher = Fernet(key)
# Encryption functions
def encrypt_password(password):
    return cipher.encrypt(password.encode()).decode()
def decrypt_password(encrypted_password):
    return cipher.decrypt(encrypted_password.encode()).decode()
# Save password
def save_password(service, username, password):
    with open("data/passwords.txt", "a") as file:
        file.write(f"{service},{username},{encrypt_password(password)}\n")
# Retrieve all passwords
def retrieve_passwords():
    try:
        with open("data/passwords.txt", "r") as file:
            data = file.readlines()
            passwords = []
            for line in data:
                service, username, enc_password = line.strip().split(",")
                passwords.append({
                    "service": service,
                    "username": username,
                    "password": decrypt_password(enc_password)
                })
            return passwords
    except FileNotFoundError:
        return []
    
def search_password(service_name=None, username=None):
    try:
        with open("data/passwords.txt", "r") as file:
            data = file.readlines()
            results = []  # To store all matching results
            for line in data:
                service, user, enc_password = line.strip().split(",")
                # Search by service name or username
                if (service_name and service_name.lower() == service.lower()) or \
                    (username and username.lower() == user.lower()):
                    results.append({
                        "service": service,
                        "username": user,
                        "password": decrypt_password(enc_password)
                    })
            return results if results else None  # Return all matches or None if no matches
    except FileNotFoundError:
        return None

# Password generator
def generate_random_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))
@app.route("/")
def home():
    return render_template("index.html")
@app.route("/add_password", methods=["GET", "POST"])
def add_password():
    if request.method == "POST":
        service = request.form["service"]
        username = request.form["username"]
        password = request.form["password"]
        save_password(service, username, password)
        flash("Password saved successfully!", "success")
        return redirect(url_for("add_password"))
    return render_template("add_password.html")
@app.route("/generate_password")
def generate_password_route():
    # Generate a password and return it as JSON
    password = generate_random_password()
    return jsonify({'password': password})
@app.route("/view_password", methods=["GET", "POST"])
def view_passwords():
    passwords = retrieve_passwords()  # Get all passwords by default
    # Check if search parameters are provided
    search_type = request.args.get('search_type')
    search_value = request.args.get('search_value')
    if search_type and search_value:
        passwords = [password for password in passwords if password[search_type].lower() == search_value.lower()]
    return render_template("view_password.html", passwords=passwords)

@app.route("/search_password", methods=["POST"])
def search_password_view():
    results = []
    if request.method == "POST":
        search_type = request.form.get("search_type")
        search_value = request.form.get("search_value")
        
        # Ensure that we search by either service or username
        if search_type == "service":
            results = search_password(service_name=search_value)
        elif search_type == "username":
            results = search_password(username=search_value)
        
        if not results:
            flash("No matching results found!", "error")

    return render_template("search_p.html", results=results)


@app.route("/encrypt_decrypt", methods=["GET", "POST"])
def encrypt_decrypt():
    result = None
    if request.method == "POST":
        action = request.form["action"]
        text = request.form["text"]
        if action == "encrypt":
            result = encrypt_password(text)
        elif action == "decrypt":
            try:
                result = decrypt_password(text)
            except Exception:
                flash("Decryption failed. Ensure the text is properly encrypted.", "error")
    return render_template("encrypt_decrypt.html", result=result)

@app.route("/admin_login", methods=["GET", "POST"])
def admin_login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if username == ADMIN_USERNAME and password == ADMIN_PASSWORD:
            session["admin_logged_in"] = True
            flash("Admin logged in successfully!", "success")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials.", "error")
    return render_template("admin_login.html")


@app.route("/")
def logout():
    session.pop("admin_logged_in", None)
    flash("Logged out successfully!", "success")
    return redirect(url_for("index"))

if __name__ == "__main__":
    if not os.path.exists("data"):
        os.mkdir("data")
    app.run(debug=True)
