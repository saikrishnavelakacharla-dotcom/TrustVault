
from getpass import getpass
from app import app
from models import db, User


def create_user(name, role):

    print("\n------------------------------")
    print(f"Create {role} Account")
    print("------------------------------")

    email = input("Enter email address: ").strip().lower()

    if not email:
        print("Email cannot be empty.")
        return

    # Check whether email already exists
    existing_user = User.query.filter_by(email=email).first()

    if existing_user:
        print("This email already exists!")
        return

    # Get password
    password = input("Enter password: ")
    confirm_password = input("Confirm password: ")

    if password != confirm_password:
        print("Passwords do not match!")
        return

    if len(password) < 8:
        print("Password must contain at least 8 characters.")
        return

    # Create new user
    user = User(
        name=name,
        email=email,
        role=role
    )

    # Hash the password
    user.set_password(password)

    # Save user in database
    db.session.add(user)
    db.session.commit()

    print(f"{role} account created successfully!")


# Main program
with app.app_context():

    db.create_all()

    print("\n================================")
    print("       TRUSTVAULT USER SETUP")
    print("================================")

    create_user("Admin", "Admin")

    create_user("Owner", "Owner")

    create_user("Viewer", "Viewer")

    print("\nAll account setup steps completed!")
