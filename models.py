
from datetime import datetime

from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()


# =====================================
# USER MODEL
# =====================================
class User(UserMixin, db.Model):

    id = db.Column(db.Integer, primary_key=True)

    name = db.Column(db.String(100), nullable=False)

    email = db.Column(db.String(120), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


# =====================================
# DOCUMENT MODEL
# =====================================
class Document(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    filename = db.Column(db.String(255), nullable=False)

    stored_filename = db.Column(db.String(255), unique=True, nullable=False)

    category = db.Column(db.String(100))

    uploaded_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    owner_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    owner = db.relationship("User", backref="documents")


# =====================================
# DOCUMENT PERMISSION MODEL
# =====================================
class DocumentPermission(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=False
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=False
    )

    permission = db.Column(
        db.String(20),
        nullable=False
    )

    granted_at = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    document = db.relationship("Document")

    user = db.relationship("User")

    __table_args__ = (
        db.UniqueConstraint(
            "document_id",
            "user_id",
            name="unique_document_user"
        ),
    )


# =====================================
# AUDIT LOG MODEL
# =====================================
class AuditLog(db.Model):

    id = db.Column(db.Integer, primary_key=True)

    actor_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    document_id = db.Column(
        db.Integer,
        db.ForeignKey("document.id"),
        nullable=True
    )

    target_user_id = db.Column(
        db.Integer,
        db.ForeignKey("user.id"),
        nullable=True
    )

    action = db.Column(db.String(100), nullable=False)

    status = db.Column(db.String(20), nullable=False)

    details = db.Column(db.Text)

    ip_address = db.Column(db.String(45))

    created_at = db.Column(
        db.DateTime,
        default=datetime.utcnow,
        nullable=False
    )

    # Hash chain fields
    previous_hash = db.Column(db.String(64))

    event_hash = db.Column(db.String(64))

    actor = db.relationship(
        "User",
        foreign_keys=[actor_id]
    )

    target_user = db.relationship(
        "User",
        foreign_keys=[target_user_id]
    )

    document = db.relationship("Document")
