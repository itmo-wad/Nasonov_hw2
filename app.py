from flask import Flask, render_template, request, redirect, session, url_for, render_template_string, send_from_directory, flash
from pymongo import MongoClient
import bcrypt
import os
import logging
import sys
from werkzeug.utils import secure_filename
import uuid
# TODO: add functional "if typing import all needed classes"


app = Flask(__name__)
app.secret_key = os.getenv("FLASK_SECRET_KEY")


# File upload properties. Should be in config.py or smth like that
UPLOAD_FOLDER = os.path.join("uploads")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg"}
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# MongoDB connection
client = MongoClient("mongodb://mongo:27017/")
db = client["auth_demo"]
users = db["users"]

def upload_file(file) -> str:
    if file.filename != "":
        # Validate file size
        if len(file.read()) > MAX_FILE_SIZE:
            raise Exception("Wrong file size")
        file.seek(0)  # Reset file pointer after reading

        # Generate a unique filename
        ext = file.filename.split(".")[-1]
        if ext not in ALLOWED_EXTENSIONS:
            raise Exception("Inavlid filename")
        
        unique_filename = f"{uuid.uuid4().hex}.{ext}"
        file_path = os.path.join(app.config["UPLOAD_FOLDER"], unique_filename)
        file.save(file_path)
        return unique_filename
    else:
        raise Exception("Wrong file name")

# Routes
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("profile"))
    return redirect(url_for("login"))

# TODO: move to ORM!!! Create models for user and so on
@app.route("/login", methods=["GET", "POST"])
def login():
    # POST
    if request.method == "POST":
        if "username" not in request.form or "password" not in request.form:
            return "Username and password are required!", 400  # Bad Request
        username = request.form["username"]
        password = request.form["password"]

        user = users.find_one({"username": username})
        if user and bcrypt.checkpw(password.encode("utf-8"), user["password"]):
            session["username"] = user["username"]
            session["picture"] = user["picture"]
            return redirect(url_for("profile"))
        flash("Invalid username or password", "error")
        return redirect(url_for("login"))
    # GET
    return render_template("login.html")


# TODO: move to ORM!!! Create models for user and so on
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        if "username" not in request.form or "password" not in request.form or "repeat_password" not in request.form:
            return "Username and password are required!", 400  # Bad Request
        
        username = request.form["username"]
        password = request.form["password"]
        repeat_password = request.form["repeat_password"]

        if password != repeat_password:
            flash("Passwords do not match!", "error")
            return redirect(url_for("register"))

        if users.find_one({"username": username}):
            flash("Username already exists!", "error")
            return redirect(url_for("register"))

        hashed_password = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

        picture_filename = "bird.jpg"  # Default picture
        if "picture" in request.files:
            file = request.files["picture"]
            try:
                picture_filename = upload_file(file)
            except Exception as e:
                # Or we can just picture_filename="bird.jpg"???
                flash("Wrong file", "error")
                return redirect(url_for("register"))
            
        # This is basically user model in my app
        user_data = {
            "username": username,
            "password": hashed_password,
            "age": request.form.get("age", "0"),
            "sex": request.form.get("sex", "None"),
            "bio": request.form.get("bio", "None"),
            "email": request.form.get("email", "email@example.com"),
            "picture": picture_filename
        }

        # Insert the new user into the database
        users.insert_one(user_data)
        return redirect(url_for("login"))
    # GET
    return render_template("register.html")


# TODO: move to ORM!!! Create models for user and so on
@app.route("/profile", methods=["GET", "PATCH"])
def profile():
    # Check if logged in
    if "username" not in session:
        return redirect(url_for("login"))
    
    # PATCH
    if request.method == "PATCH":
        data = request.get_json()

        # Update the user's data in the database (update picture is another functionality)
        # Also ignore anything unexpected
        update_data = {}
        for i in ["age", "sex", "bio", "email"]:
            if i in data:
                update_data[i] = data[i]
        
        if "picture" in request.files:
            file = request.files["picture"]
            try:
                update_data['picture'] = upload_file(file)
            except Exception as e:
                return "Invalid file", 400

        # Update the database
        users.update_one(
            {"username": session["username"]},
            {"$set": update_data}
        )
        return "Update success", 200
    # GET
    user = users.find_one({"username": session["username"]})
    if not user:
        return redirect(url_for("login"))
    
    return render_template("profile.html", 
                            username=user["username"],
                            picture_source=user.get("picture", "bird.jpg"),
                            age=user.get("age", 0),
                            sex=user.get("sex", "None"),
                            bio=user.get("bio", "-"),
                            email=user.get("email", "email@example.com") 
    )

@app.route("/change_picture", methods=["POST"])
def change_picture():
    if "username" not in session:
        return "Unauthorized", 401

    username = session["username"]

    if "picture" not in request.files:
        return "No file provided", 400

    file = request.files["picture"]
    if file.filename == "":
        return "No file selected", 400
    
    try:
        unique_filename = upload_file(file)
        if(session["picture"] != "bird.jpg"):
            file_path = os.path.join(app.config["UPLOAD_FOLDER"], session['picture'])
            if os.path.exists(file_path):
                os.remove(os.path.join(app.config["UPLOAD_FOLDER"], session['picture']))
    except Exception as e:
        return "Invalid picture", 400

    users.update_one(
        {"username": username},
        {"$set": {"picture": unique_filename}}
    )
    return "Picture updated successfully", 200

@app.route("/change_password", methods=["POST"])
def change_password():
    if "username" not in session:
        return "Unauthorized", 401

    username = session["username"]
    previous_password = request.form["previous_password"]
    new_password = request.form["new_password"]
    new_password_repeat = request.form["new_password_repeat"]
    if(new_password != new_password_repeat):
        return "Passwords does not match", 400

    user = users.find_one({"username": username})
    if user and bcrypt.checkpw(previous_password.encode("utf-8"), user["password"]):
        users.update_one(
            {"username": username},
            {"$set": {"password": bcrypt.hashpw(new_password.encode("utf-8"), bcrypt.gensalt())}}
        )
        return redirect(url_for("profile"))
    return "Wrong password provided", 401

@app.route("/uploads/<filename>")
def uploaded_file(filename, methods=["GET"]):
    # Check if the user has permission to access the file
    # (e.g., only allow logged-in users to access their own files)
    if "username" not in session:
        return "Unauthorized", 403

    # Verify that the file exists and is safe to serve
    filename = secure_filename(filename)
    file_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    if not os.path.isfile(file_path):
        filename = "bird.jpg"

    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

# TODO: move to ORM!!! Create models for user and so on
@app.route("/logout")
def logout():
    session.pop("username", None)
    session.pop("age", None)
    session.pop("sex", None)
    session.pop("bio", None)
    session.pop("email", None)
    session.pop("picture", None)
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)