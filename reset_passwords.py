# secure_health_app/reset_passwords.py

from app import create_app  
from database import db, bcrypt  
from models import User  

def reset_user_password(email, new_password):
    """
    Resets the password for a user with the given email.
    """
    user = User.query.filter_by(email=email).first()
    if user:
        # Encrypt the new password
        hashed_password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        user.password = hashed_password # Set the new hashed password
        db.session.commit() # Save changes to the database  
        print(f"Password for user '{email}' has been successfully reset.")
    else:
        print(f"User with email '{email}' not found.")

if __name__ == '__main__':
    # Initialize Flask application within Application Context
    # This allows us to access db, bcrypt, and models
    app = create_app()
    with app.app_context():
        print("Starting password reset process...")

        # Reset admin password
        reset_user_password('admin@securehealth.com', 'NewAdmin@123') # 'NewAdmin@123'

        # Reset Doctor 1 password
        reset_user_password('doctor@securehealth.com', 'NewDoctor@123') # 'NewDoctor@123'

        # Reset Doctor 2 password
        reset_user_password('doctor2@securehealth.com', 'NewDoctor@123') # 'NewDoctor@123'

        print("Password reset process completed.")