
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
INSTANCE_DIR = os.path.join(BASE_DIR, "instance")
UPLOAD_FOLDER = os.path.join(INSTANCE_DIR, "uploads")

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
# CREATE DATABASE TABLES
# --------------------------------------------------

with app.app_context():
    db.create_all()


# --------------------------------------------------
# USER LOADER
# --------------------------------------------------

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))


# --------------------------------------------------
# AUDIT LOGGING
# --------------------------------------------------

def record_audit(
    action,
    status,
    document_id=None,
    target_user_id=None,
    details=None
):
    try:
        actor_id = (
            current_user.id
            if current_user.is_authenticated
            else None
        )

        previous_record = (
            AuditLog.query
            .order_by(AuditLog.id.desc())
            .first()
        )

        previous_hash = (
            previous_record.event_hash
            if previous_record
            else ""
        )

        created_at = datetime.utcnow()
        ip_address = request.remote_addr

        event_data = {
            "actor_id": actor_id,
            "document_id": document_id,
            "target_user_id": target_user_id,
            "action": action,
            "status": status,
            "details": details,
            "ip_address": ip_address,
            "created_at": created_at.isoformat()
        }

        event_string = json.dumps(
            event_data,
            sort_keys=True
        )

        event_hash = hashlib.sha256(
            (previous_hash + event_string).encode("utf-8")
        ).hexdigest()

        audit = AuditLog(
            actor_id=actor_id,
            document_id=document_id,
            target_user_id=target_user_id,
            action=action,
            status=status,
            details=details,
            ip_address=ip_address,
            created_at=created_at,
            previous_hash=previous_hash,
            event_hash=event_hash
        )

        db.session.add(audit)
        db.session.commit()

    except Exception:
        db.session.rollback()
        app.logger.exception("Audit logging failed")


# --------------------------------------------------
# VERIFY AUDIT LOG INTEGRITY
# --------------------------------------------------

def verify_audit_logs():

    logs = AuditLog.query.order_by(
        AuditLog.id.asc()
    ).all()

    expected_previous_hash = ""

    event_errors = []
    chain_errors = []

    for log in logs:

        # Check previous hash connection

        if (log.previous_hash or "") != expected_previous_hash:
            chain_errors.append(log.id)

        # Recreate the original event data

        event_data = {
            "actor_id": log.actor_id,
            "document_id": log.document_id,
            "target_user_id": log.target_user_id,
            "action": log.action,
            "status": log.status,
            "details": log.details,
            "ip_address": log.ip_address,
            "created_at": log.created_at.isoformat()
        }

        event_string = json.dumps(
            event_data,
            sort_keys=True
        )

        calculated_hash = hashlib.sha256(
            (
                (log.previous_hash or "") + event_string
            ).encode("utf-8")
        ).hexdigest()

        # Check event hash

        if calculated_hash != log.event_hash:
            event_errors.append(log.id)

        # Continue checking the complete chain

        expected_previous_hash = log.event_hash or ""

    # Prepare complete verification report

    if event_errors or chain_errors:

        message = (
            f"Audit verification failed. "
            f"Total records: {len(logs)}. "
            f"Event hash mismatches: {event_errors}. "
            f"Previous hash mismatches: {chain_errors}."
        )

        return False, message

    return True, (
        f"All {len(logs)} audit records verified successfully."
    )


# --------------------------------------------------
# FILE VALIDATION
# --------------------------------------------------

def allowed_file(filename):

    return (
        "." in filename
        and filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# --------------------------------------------------
# DOCUMENT ACCESS CHECK
# --------------------------------------------------

def get_document_access(document):

    if current_user.role == "Admin":
        return "admin"

    if document.owner_id == current_user.id:
        return "owner"

    permission = DocumentPermission.query.filter_by(
        document_id=document.id,
        user_id=current_user.id
    ).first()

    if permission:
        return permission.permission.lower()

    return None


# --------------------------------------------------
# DENY UNAUTHORIZED ACCESS
# --------------------------------------------------

def deny_access(action, document_id=None, details=None):

    record_audit(
        action=action,
        status="DENIED",
        document_id=document_id,
        details=details or "Unauthorized access attempt"
    )

    abort(403)


# --------------------------------------------------
# OWNER ACCESS CHECK
# --------------------------------------------------

def owner_required(document):

    if (
        current_user.role == "Admin"
        or document.owner_id == current_user.id
    ):
        return

    deny_access(
        action="ACCESS_DOCUMENT",
        document_id=document.id,
        details=(
            "Only the document owner or Admin can perform this action"
        )
    )


# --------------------------------------------------
# HOME PAGE
# --------------------------------------------------

@app.route("/")
def home():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# --------------------------------------------------
# LOGIN
# --------------------------------------------------

@app.route("/login", methods=["GET", "POST"])
def login():

    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))

    if request.method == "POST":

        email = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        user = User.query.filter_by(email=email).first()

        if user and user.check_password(password):

            login_user(user)

            record_audit(
                action="LOGIN",
                status="SUCCESS",
                details="User logged in successfully"
            )

            return redirect(url_for("dashboard"))

        record_audit(
            action="LOGIN",
            status="FAILED",
            details="Invalid email or password"
        )

        flash("Invalid email or password")

    return render_template("login.html")


# --------------------------------------------------
# DASHBOARD
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    if current_user.role == "Admin":

        my_documents = Document.query.all()
        shared_documents = []

    else:

        my_documents = Document.query.filter_by(
            owner_id=current_user.id
        ).all()

        permissions = DocumentPermission.query.filter_by(
            user_id=current_user.id
        ).all()

        shared_documents = [
            permission.document
            for permission in permissions
            if permission.document is not None
        ]

    return render_template(
        "dashboard.html",
        my_documents=my_documents,
        shared_documents=shared_documents
    )


# --------------------------------------------------
# UPLOAD DOCUMENT
# --------------------------------------------------

@app.route("/upload", methods=["GET", "POST"])
@login_required
def upload():

    if current_user.role not in ["Admin", "Owner"]:

        record_audit(
            action="UPLOAD",
            status="DENIED",
            details="Viewer attempted to upload a document"
        )

        abort(403)

    if request.method == "POST":

        if "file" not in request.files:
            flash("Please select a document")
            return redirect(url_for("upload"))

        file = request.files["file"]

        category = request.form.get(
            "category", ""
        ).strip()

        if file.filename == "":
            flash("No file selected")
            return redirect(url_for("upload"))

        if not allowed_file(file.filename):

            record_audit(
                action="UPLOAD",
                status="DENIED",
                details="Invalid file extension"
            )

            flash("Only PDF, DOCX and TXT files are allowed")
            return redirect(url_for("upload"))

        if category not in [
            "Personal",
            "Education",
            "Work",
            "Other"
        ]:
            flash("Please select a valid category")
            return redirect(url_for("upload"))

        original_filename = secure_filename(file.filename)

        if not original_filename:
            flash("Invalid filename")
            return redirect(url_for("upload"))

        stored_filename = original_filename

        name, extension = os.path.splitext(original_filename)
        counter = 1

        while os.path.exists(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                stored_filename
            )
        ):
            stored_filename = f"{name}_{counter}{extension}"
            counter += 1

        file.save(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                stored_filename
            )
        )

        document = Document(
            filename=original_filename,
            stored_filename=stored_filename,
            category=category,
            owner_id=current_user.id
        )

        db.session.add(document)
        db.session.commit()

        record_audit(
            action="UPLOAD",
            status="SUCCESS",
            document_id=document.id,
            details="Document uploaded successfully"
        )

        flash("Document uploaded successfully")

        return redirect(url_for("dashboard"))

    return render_template("upload.html")


# --------------------------------------------------
# SHARE DOCUMENT
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/share",
    methods=["GET", "POST"]
)
@login_required
def share_document(document_id):

    document = db.session.get(Document, document_id)

    if not document:

        record_audit(
            action="SHARE_PERMISSION",
            status="DENIED",
            document_id=document_id,
            details="Document not found"
        )

        abort(404)

    owner_required(document)

    if request.method == "POST":

        email = request.form.get("email", "").strip()

        permission_type = request.form.get(
            "permission", ""
        )

        target_user = User.query.filter_by(
            email=email
        ).first()

        if not target_user:
            flash("User not found")
            return redirect(
                url_for(
                    "share_document",
                    document_id=document.id
                )
            )

        if target_user.role != "Viewer":
            flash(
                "You can share documents only with Viewer accounts"
            )
            return redirect(
                url_for(
                    "share_document",
                    document_id=document.id
                )
            )

        if permission_type not in ["read", "edit"]:
            flash("Invalid permission")
            return redirect(
                url_for(
                    "share_document",
                    document_id=document.id
                )
            )

        if target_user.id == current_user.id:
            flash("You cannot share a document with yourself")
            return redirect(
                url_for(
                    "share_document",
                    document_id=document.id
                )
            )

        permission = DocumentPermission.query.filter_by(
            document_id=document.id,
            user_id=target_user.id
        ).first()

        if permission:
            permission.permission = permission_type

        else:
            permission = DocumentPermission(
                document_id=document.id,
                user_id=target_user.id,
                permission=permission_type
            )

            db.session.add(permission)

        db.session.commit()

        record_audit(
            action="SHARE_PERMISSION",
            status="SUCCESS",
            document_id=document.id,
            target_user_id=target_user.id,
            details=f"Permission set to {permission_type}"
        )

        flash("Document shared successfully")

        return redirect(
            url_for(
                "share_document",
                document_id=document.id
            )
        )

    permissions = DocumentPermission.query.filter_by(
        document_id=document.id
    ).all()

    return render_template(
        "share.html",
        document=document,
        permissions=permissions
    )


# --------------------------------------------------
# REVOKE DOCUMENT PERMISSION
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/revoke/<int:permission_id>",
    methods=["POST"]
)
@login_required
def revoke_access(document_id, permission_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:
        abort(404)

    owner_required(document)

    permission = db.session.get(
        DocumentPermission,
        permission_id
    )

    if (
        not permission
        or permission.document_id != document.id
    ):
        abort(404)

    target_user_id = permission.user_id

    db.session.delete(permission)
    db.session.commit()

    record_audit(
        action="REVOKE_PERMISSION",
        status="SUCCESS",
        document_id=document.id,
        target_user_id=target_user_id,
        details="Document permission revoked"
    )

    flash("Permission revoked successfully")

    return redirect(
        url_for(
            "share_document",
            document_id=document.id
        )
    )


# --------------------------------------------------
# EDIT DOCUMENT
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/edit",
    methods=["GET", "POST"]
)
@login_required
def edit_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:

        record_audit(
            action="EDIT",
            status="DENIED",
            document_id=document_id,
            details="Document not found"
        )

        abort(404)

    access = get_document_access(document)

    if access not in ["owner", "edit", "admin"]:

        deny_access(
            action="EDIT",
            document_id=document.id,
            details="User does not have edit permission"
        )

    if request.method == "POST":

        new_filename = request.form.get(
            "filename", ""
        ).strip()

        new_category = request.form.get(
            "category", ""
        ).strip()

        if not new_filename:
            flash("Document name cannot be empty")
            return redirect(
                url_for(
                    "edit_document",
                    document_id=document.id
                )
            )

        if new_category not in [
            "Personal",
            "Education",
            "Work",
            "Other"
        ]:
            flash("Invalid category")
            return redirect(
                url_for(
                    "edit_document",
                    document_id=document.id
                )
            )

        document.filename = new_filename
        document.category = new_category

        db.session.commit()

        record_audit(
            action="EDIT",
            status="SUCCESS",
            document_id=document.id,
            details="Document information updated"
        )

        flash("Document updated successfully")

        return redirect(url_for("dashboard"))

    return render_template(
        "edit.html",
        document=document
    )


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/download",
    methods=["GET"]
)
@login_required
def download_document(document_id):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:

        record_audit(
            action="DOWNLOAD",
            status="DENIED",
            document_id=document_id,
            details="Document not found"
        )

        abort(404)

    access = get_document_access(document)

    if access not in [
        "owner",
        "read",
        "edit",
        "admin"
    ]:

        deny_access(
            action="DOWNLOAD",
            document_id=document.id,
            details="User does not have read permission"
        )

    upload_folder = app.config["UPLOAD_FOLDER"]

    file_path = os.path.join(
        upload_folder,
        document.stored_filename
    )

    if not os.path.isfile(file_path):

        record_audit(
            action="DOWNLOAD",
            status="FAILED",
            document_id=document.id,
            details="Stored file was not found on the server"
        )

        abort(404)

    record_audit(
        action="DOWNLOAD",
        status="SUCCESS",
        document_id=document.id,
        details="Document download requested"
    )

    return send_from_directory(
        upload_folder,
        document.stored_filename,
        as_attachment=True,
        download_name=document.filename
    )


# --------------------------------------------------
# ADMIN AUDIT HISTORY
# --------------------------------------------------

@app.route("/admin/audit")
@login_required
def audit_history():

    if current_user.role != "Admin":

        record_audit(
            action="VIEW_AUDIT",
            status="DENIED",
            details="Non-admin attempted to view audit history"
        )

        abort(403)

    logs = (
        AuditLog.query
        .order_by(AuditLog.id.desc())
        .limit(200)
        .all()
    )

    return render_template(
        "audit.html",
        logs=logs
    )


# --------------------------------------------------
# VERIFY AUDIT HISTORY
# --------------------------------------------------

@app.route("/admin/audit/verify")
@login_required
def verify_audit_history():

    if current_user.role != "Admin":

        record_audit(
            action="VERIFY_AUDIT",
            status="DENIED",
            details="Non-admin attempted to verify audit history"
        )

        abort(403)

    is_valid, message = verify_audit_logs()

    if is_valid:
        flash(message, "success")

    else:
        flash(message, "warning")

    return redirect(url_for("audit_history"))


# --------------------------------------------------
# LOGOUT
# --------------------------------------------------

@app.route("/logout", methods=["POST"])
@login_required
def logout():

    record_audit(
        action="LOGOUT",
        status="SUCCESS",
        details="User logged out"
    )

    logout_user()

    flash("Logged out successfully")

    return redirect(url_for("login"))


# --------------------------------------------------
# ERROR HANDLERS
# --------------------------------------------------

@app.errorhandler(403)
def forbidden(error):

    return render_template(
        "403.html",
        message="You do not have permission to access this resource."
    ), 403


@app.errorhandler(404)
def not_found(error):

    return "404 - Page not found", 404


@app.errorhandler(413)
def file_too_large(error):

    return "File is too large. Maximum size is 10 MB.", 413


# --------------------------------------------------
# RUN APPLICATION
# --------------------------------------------------

if __name__ == "__main__":

    app.run(debug=True)
