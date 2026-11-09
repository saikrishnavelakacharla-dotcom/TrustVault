
import os
import json
import hashlib
from datetime import datetime

from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    flash,
    abort,
    send_from_directory
)

from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user
)

from flask_wtf.csrf import CSRFProtect
from werkzeug.utils import secure_filename

from models import (
    db,
    User,
    Document,
    DocumentPermission,
    AuditLog
)


# --------------------------------------------------
# APPLICATION CONFIGURATION
# --------------------------------------------------

app = Flask(__name__)

BASE_DIR = os.path.abspath(os.path.dirname(__file__))

# Local: uses instance folder.
# Render: can use TRUSTVAULT_DATA_DIR environment variable.
DATA_DIR = os.environ.get(
    "TRUSTVAULT_DATA_DIR",
    os.path.join(BASE_DIR, "instance")
)

INSTANCE_DIR = DATA_DIR
UPLOAD_FOLDER = os.path.join(DATA_DIR, "uploads")

os.makedirs(INSTANCE_DIR, exist_ok=True)
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    "change-this-secret-key-before-deployment"
)

app.config["SQLALCHEMY_DATABASE_URI"] = (
    "sqlite:///" + os.path.join(INSTANCE_DIR, "trustvault.db")
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024

# Secure session cookies in production (HTTPS).
if os.environ.get("RENDER"):
    app.config["SESSION_COOKIE_SECURE"] = True
    app.config["SESSION_COOKIE_HTTPONLY"] = True
    app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

ALLOWED_EXTENSIONS = {"pdf", "docx", "txt"}


# --------------------------------------------------
# INITIALIZE EXTENSIONS
# --------------------------------------------------

db.init_app(app)

csrf = CSRFProtect(app)

login_manager = LoginManager()
login_manager.init_app(app)

login_manager.login_view = "login"
login_manager.login_message = "Please log in to access this page."


# --------------------------------------------------
# CREATE DATABASE TABLES AND OPTIONAL RENDER ADMIN
