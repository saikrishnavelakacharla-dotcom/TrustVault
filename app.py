
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
# CREATE DATABASE TABLES AND ACCOUNTS
# --------------------------------------------------

with app.app_context():

    db.create_all()

    # --------------------------------------------------
    # AUTOMATIC ADMIN ACCOUNT CREATION
    # --------------------------------------------------

    admin_email = os.environ.get(
        "ADMIN_EMAIL", ""
    ).strip().lower()

    admin_password = os.environ.get(
        "ADMIN_PASSWORD", ""
    )

    if admin_email and admin_password:

        existing_admin = User.query.filter_by(
            email=admin_email
        ).first()

        if existing_admin is None:

            if len(admin_password) < 8:

                app.logger.error(
                    "Admin password must be at least 8 characters."
                )

            else:

                admin = User(
                    name="Admin",
                    email=admin_email,
                    role="Admin"
                )

                admin.set_password(admin_password)

                db.session.add(admin)
                db.session.commit()

                app.logger.info(
                    "Initial Admin account created successfully."
                )

        elif existing_admin.role != "Admin":

            app.logger.warning(
                "The configured Admin email belongs to a non-Admin user. "
                "No account changes were made."
            )

        else:

            app.logger.info(
                "Admin account already exists."
            )

    # --------------------------------------------------
    # AUTOMATIC VIEWER ACCOUNT CREATION
    # --------------------------------------------------

    viewer_email = os.environ.get(
        "VIEWER_EMAIL", ""
    ).strip().lower()

    viewer_password = os.environ.get(
        "VIEWER_PASSWORD", ""
    )

    if viewer_email and viewer_password:

        existing_viewer = User.query.filter_by(
            email=viewer_email
        ).first()

        if existing_viewer is None:

            if len(viewer_password) < 8:

                app.logger.error(
                    "Viewer password must be at least 8 characters."
                )

            else:

                viewer = User(
                    name="Viewer",
                    email=viewer_email,
                    role="Viewer"
                )

                viewer.set_password(viewer_password)

                db.session.add(viewer)
                db.session.commit()

                app.logger.info(
                    "Viewer account created successfully."
                )

        elif existing_viewer.role != "Viewer":

            app.logger.warning(
                "The configured Viewer email belongs to another role."
            )

        else:

            app.logger.info(
                "Viewer account already exists."
            )


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

        app.logger.exception(
            "Audit logging failed"
        )


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

        if (log.previous_hash or "") != expected_previous_hash:

            chain_errors.append(log.id)

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

        if calculated_hash != log.event_hash:

            event_errors.append(log.id)

        expected_previous_hash = log.event_hash or ""

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
# GET ACTIVE DOCUMENT
# --------------------------------------------------

def get_active_document(document_id, action):

    document = db.session.get(
        Document,
        document_id
    )

    if not document:

        record_audit(
            action=action,
            status="DENIED",
            document_id=document_id,
            details="Document not found"
        )

        abort(404)

    if document.is_deleted:

        record_audit(
            action=action,
            status="DENIED",
            document_id=document.id,
            details="Attempted to access a deleted document"
        )

        abort(404)

    return document


# --------------------------------------------------
# DENY UNAUTHORIZED ACCESS
# --------------------------------------------------

def deny_access(
    action,
    document_id=None,
    details=None
):

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

        email = request.form.get(
            "email", ""
        ).strip()

        password = request.form.get(
            "password", ""
        )

        user = User.query.filter_by(
            email=email
        ).first()

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
# DASHBOARD WITH DOCUMENT SEARCH
# --------------------------------------------------

@app.route("/dashboard")
@login_required
def dashboard():

    search_query = request.args.get(
        "q", ""
    ).strip().casefold()

    if current_user.role == "Admin":

        my_documents = Document.query.filter_by(
            is_deleted=False
        ).all()

        shared_documents = []

    else:

        my_documents = Document.query.filter_by(
            owner_id=current_user.id,
            is_deleted=False
        ).all()

        permissions = DocumentPermission.query.filter_by(
            user_id=current_user.id
        ).all()

        shared_documents = [
            permission.document
            for permission in permissions
            if (
                permission.document is not None
                and not permission.document.is_deleted
            )
        ]

    if search_query:

        def matches_search(document):

            filename = (
                document.filename or ""
            ).casefold()

            category = (
                document.category or ""
            ).casefold()

            owner_name = (
                document.owner.name or ""
                if document.owner else ""
            ).casefold()

            owner_email = (
                document.owner.email or ""
                if document.owner else ""
            ).casefold()

            return (
                search_query in filename
                or search_query in category
                or search_query in owner_name
                or search_query in owner_email
            )

        my_documents = [
            document
            for document in my_documents
            if matches_search(document)
        ]

        shared_documents = [
            document
            for document in shared_documents
            if matches_search(document)
        ]

    return render_template(
        "dashboard.html",
        my_documents=my_documents,
        shared_documents=shared_documents,
        search_query=search_query
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

        original_filename = secure_filename(
            file.filename
        )

        if not original_filename:

            flash("Invalid filename")

            return redirect(url_for("upload"))

        stored_filename = original_filename

        name, extension = os.path.splitext(
            original_filename
        )

        counter = 1

        while os.path.exists(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                stored_filename
            )
        ):

            stored_filename = (
                f"{name}_{counter}{extension}"
            )

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

    document = get_active_document(
        document_id,
        "SHARE_PERMISSION"
    )

    owner_required(document)

    if request.method == "POST":

        email = request.form.get(
            "email", ""
        ).strip()

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

    document = get_active_document(
        document_id,
        "REVOKE_PERMISSION"
    )

    owner_required(document)

    permission = db.session.get(
        DocumentPermission,
        permission_id
    )

    if (
        not permission
        or permission.document_id != document.id
    ):

        record_audit(
            action="REVOKE_PERMISSION",
            status="DENIED",
            document_id=document.id,
            details="Permission record not found"
        )

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

    document = get_active_document(
        document_id,
        "EDIT"
    )

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
# DELETE DOCUMENT - SOFT DELETE
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/delete",
    methods=["POST"]
)
@login_required
def delete_document(document_id):

    document = get_active_document(
        document_id,
        "DELETE"
    )

    if (
        current_user.role != "Admin"
        and document.owner_id != current_user.id
    ):

        deny_access(
            action="DELETE",
            document_id=document.id,
            details=(
                "Unauthorized user attempted to delete document"
            )
        )

    document.is_deleted = True

    db.session.commit()

    record_audit(
        action="DELETE",
        status="SUCCESS",
        document_id=document.id,
        details="Document soft deleted successfully"
    )

    flash("Document deleted successfully")

    return redirect(url_for("dashboard"))


# --------------------------------------------------
# DOWNLOAD DOCUMENT
# --------------------------------------------------

@app.route(
    "/documents/<int:document_id>/download",
    methods=["GET"]
)
@login_required
def download_document(document_id):

    document = get_active_document(
        document_id,
        "DOWNLOAD"
    )

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

    debug_mode = os.environ.get(
        "FLASK_DEBUG", "0"
    ) == "1"

    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=debug_mode
    )
