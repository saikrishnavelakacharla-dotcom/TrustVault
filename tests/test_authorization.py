
import pytest
from pathlib import Path
from sqlalchemy import or_

from app import app
from models import (
    db,
    User,
    Document,
    DocumentPermission,
    AuditLog
)


@pytest.fixture
def setup_test_data(tmp_path):

    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False

    # Create temporary upload folder
    upload_folder = tmp_path / "uploads"
    upload_folder.mkdir()

    # Set the folder used by Flask
    app.config["UPLOAD_FOLDER"] = str(upload_folder)

    with app.app_context():

        test_emails = [
            "pytest-admin@example.com",
            "pytest-owner@example.com",
            "pytest-viewer@example.com"
        ]

        # Remove previous test data
        old_users = User.query.filter(
            User.email.in_(test_emails)
        ).all()

        old_user_ids = [user.id for user in old_users]

        old_documents = Document.query.filter(
            Document.owner_id.in_(old_user_ids)
        ).all()

        old_document_ids = [doc.id for doc in old_documents]

        if old_user_ids or old_document_ids:

            AuditLog.query.filter(
                or_(
                    AuditLog.actor_id.in_(old_user_ids),
                    AuditLog.target_user_id.in_(old_user_ids),
                    AuditLog.document_id.in_(old_document_ids)
                )
            ).delete(synchronize_session=False)

            DocumentPermission.query.filter(
                or_(
                    DocumentPermission.user_id.in_(old_user_ids),
                    DocumentPermission.document_id.in_(old_document_ids)
                )
            ).delete(synchronize_session=False)

            Document.query.filter(
                Document.id.in_(old_document_ids)
            ).delete(synchronize_session=False)

            User.query.filter(
                User.id.in_(old_user_ids)
            ).delete(synchronize_session=False)

            db.session.commit()

        # Create Admin
        admin = User(
            name="Test Admin",
            email="pytest-admin@example.com",
            role="Admin"
        )
        admin.set_password("TestAdmin123")

        # Create Owner
        owner = User(
            name="Test Owner",
            email="pytest-owner@example.com",
            role="Owner"
        )
        owner.set_password("TestOwner123")

        # Create Viewer
        viewer = User(
            name="Test Viewer",
            email="pytest-viewer@example.com",
            role="Viewer"
        )
        viewer.set_password("TestViewer123")

        db.session.add_all([admin, owner, viewer])
        db.session.commit()

        # Create a sample file
        filename = "test_document.txt"
        file_path = upload_folder / filename

        file_path.write_text(
            "This is a test document.",
            encoding="utf-8"
        )

        # Create document record
        document = Document(
            filename=filename,
            stored_filename=filename,
            category="Education",
            owner_id=owner.id
        )

        db.session.add(document)
        db.session.commit()

        # Give Viewer read permission
        permission = DocumentPermission(
            document_id=document.id,
            user_id=viewer.id,
            permission="read"
        )

        db.session.add(permission)
        db.session.commit()

        # Save IDs
        admin_id = admin.id
        owner_id = owner.id
        viewer_id = viewer.id
        document_id = document.id

        test_data = {
            "admin_id": admin_id,
            "owner_id": owner_id,
            "viewer_id": viewer_id,
            "document_id": document_id,
            "upload_folder": str(upload_folder)
        }

        yield test_data

        # Clean up test audit records
        AuditLog.query.filter(
            or_(
                AuditLog.actor_id.in_(
                    [admin_id, owner_id, viewer_id]
                ),
                AuditLog.target_user_id.in_(
                    [admin_id, owner_id, viewer_id]
                ),
                AuditLog.document_id == document_id
            )
        ).delete(synchronize_session=False)

        # Clean up permissions
        DocumentPermission.query.filter(
            or_(
                DocumentPermission.document_id == document_id,
                DocumentPermission.user_id.in_(
                    [admin_id, owner_id, viewer_id]
                )
            )
        ).delete(synchronize_session=False)

        # Clean up document and users
        Document.query.filter_by(
            id=document_id
        ).delete()

        User.query.filter(
            User.id.in_([admin_id, owner_id, viewer_id])
        ).delete(synchronize_session=False)

        db.session.commit()


@pytest.fixture
def client():
    return app.test_client()


# Login helper
def login(client, email, password):

    return client.post(
        "/login",
        data={
            "email": email,
            "password": password
        },
        follow_redirects=True
    )


# TEST 1: Owner can download their document
def test_owner_can_download_document(client, setup_test_data):

    login(
        client,
        "pytest-owner@example.com",
        "TestOwner123"
    )

    document_id = setup_test_data["document_id"]

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 200


# TEST 2: Viewer can download with read permission
def test_viewer_can_download_with_read_permission(
    client,
    setup_test_data
):

    login(
        client,
        "pytest-viewer@example.com",
        "TestViewer123"
    )

    document_id = setup_test_data["document_id"]

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 200


# TEST 3: Viewer cannot edit document
def test_viewer_cannot_edit_document(client, setup_test_data):

    login(
        client,
        "pytest-viewer@example.com",
        "TestViewer123"
    )

    document_id = setup_test_data["document_id"]

    response = client.get(
        f"/documents/{document_id}/edit"
    )

    assert response.status_code == 403


# TEST 4: Viewer cannot download after permission is removed
def test_viewer_without_permission_cannot_download(
    client,
    setup_test_data
):

    document_id = setup_test_data["document_id"]
    viewer_id = setup_test_data["viewer_id"]

    # Remove Viewer permission
    with app.app_context():

        permission = DocumentPermission.query.filter_by(
            document_id=document_id,
            user_id=viewer_id
        ).first()

        if permission:
            db.session.delete(permission)
            db.session.commit()

    login(
        client,
        "pytest-viewer@example.com",
        "TestViewer123"
    )

    response = client.get(
        f"/documents/{document_id}/download"
    )

    assert response.status_code == 403
