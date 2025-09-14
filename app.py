# secure_health_app/app.py
from flask import Flask, render_template, redirect, url_for, request, session
from flask_jwt_extended import JWTManager, get_jwt, get_jwt_identity, verify_jwt_in_request
from database import db, bcrypt
from models import User, Doctor # Import Doctor model for initial data creation
from config import Config
# Import blueprints and helper functions
from routes.auth import auth_bp, set_google_client # Import set_google_client for initialization
from routes.admin import admin_bp
from routes.doctor import doctor_bp
from routes.patient import patient_bp
from routes import force_https, register_error_handlers, log_action
from google_auth_oauthlib.flow import Flow
from requests_oauthlib import OAuth2Session
from datetime import datetime
import os

# Global variable for Google OAuth client (will be initialized in create_app)
google_client = None

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)

    # --- JWT Configuration for Cookies ---
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
  
    app.config["JWT_COOKIE_CSRF_PROTECT"] = False
    app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token"
    # Initialize extensions
    db.init_app(app)
    jwt = JWTManager(app)


    # --- JWT Custom Claims and User Lookup ---
    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        """
        Callback function to load a user from the database given their identity (user_id)
        stored in the JWT. This is used by jwt_required() and other JWT functions.
        """
        identity = jwt_data["sub"]
        return db.session.get(User, identity)

    @jwt.additional_claims_loader
    def add_claims_to_access_token(identity):
       
        """
        Add custom claims (like 'role') to the JWT access token.
        This allows checking user roles directly from the token.
        """
        user = db.session.get(User, identity) # Use db.session.get for SQLAlchemy 2.x
        if user:
            return {"role": user.role, "full_name": user.full_name}
        return {} # Return empty dict if user not found
    
    
    # --- Register Jinja2 Filters ---
    @app.template_filter('datetimeformat')
    def format_datetime(value, format="%Y-%m-%dT%H:%M"): # Updated default format to include 'T'
        if isinstance(value, str) and value.lower() == 'now':
            value = datetime.utcnow() # Use UTC time for consistency
        if value is None:
            return ""
        return value.strftime(format)
    
    
    # --- Register Blueprints ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(doctor_bp)
    app.register_blueprint(patient_bp)

    # --- Register Error Handlers (from routes/__init__.py) ---
    register_error_handlers(app)

    # --- Google OAuth Configuration ---
    # This block needs an application context because it uses url_for
    with app.app_context():
        global google_client # Declare google_client as global here
          
        google_client = Flow.from_client_secrets_file(
            app.config['GOOGLE_CLIENT_SECRETS_FILE'],
            scopes=[
                'https://www.googleapis.com/auth/userinfo.email',
                'https://www.googleapis.com/auth/userinfo.profile',
                'openid'
            ],
            redirect_uri=url_for('auth.google_callback', _external=True, _scheme='https' if app.config['DEBUG'] else 'https')
        )
        # Pass the initialized google_client to the auth blueprint
        # We can also pass it using a function to avoid direct global modification in auth.py
        set_google_client(google_client)

    # --- Request Hooks ---
    @app.before_request
    def check_https():
        """
        Ensure all requests are over HTTPS in production.
        """
        if not app.config['DEBUG']:
            force_https(app)

    @app.after_request
    def add_security_headers(response):
        # Implement security headers if needed (e.g., CSP, HSTS, X-Frame-Options)
        # This is a placeholder for demonstration.
        # response.headers['X-Frame-Options'] = 'DENY'
        # response.headers['Content-Security-Policy'] = "default-src 'self'"
        return response

    return app

# In your main app.py, outside of create_app if it's called directly
if __name__ == '__main__':
    app = create_app()

    # --- Initial Data Creation (for development/testing) ---
    with app.app_context():
        db.create_all() # Create database tables if they don't exist

        # Create a default admin user if one doesn't exist
        if not User.query.filter_by(email='admin@securehealth.com').first():
            admin_user = User(email='admin@securehealth.com', full_name='Admin User', role='admin')
            admin_user.set_password('Admin@123') # CHANGE THIS IN PRODUCTION!
            db.session.add(admin_user)
            db.session.commit()
            print("Sample admin@securehealth.com created with password 'Admin@123'.")
            log_action(admin_user.id, 'System Init', 'Default admin user created.')
        
        # Create a sample patient user if one doesn't exist
        if not User.query.filter_by(email='patient@securehealth.com').first():
            pat_user = User(email='patient@securehealth.com', full_name='Patient One', role='patient')
            pat_user.set_password('Patient@123') # Sample password
            db.session.add(pat_user)
            db.session.commit()
            # Create a patient profile linked to the user
            from models import Patient # Import Patient here to avoid circular dependency
            patient_profile = Patient(user_id=pat_user.id)
            db.session.add(patient_profile)
            db.session.commit()
            print("Sample patient@securehealth.com created with password 'Patient@123'.")
            log_action(pat_user.id, 'System Init', 'Sample patient created.')

        # Create a sample doctor user if one doesn't exist
        if not User.query.filter_by(email='doctor@securehealth.com').first():
            doc_user = User(email='doctor@securehealth.com', full_name='Dr. John Doe', role='doctor')
            doc_user.set_password('Doctor@123') # Sample password
            db.session.add(doc_user)
            db.session.commit()
            # Create a doctor profile linked to the user
            doctor_profile = Doctor(user_id=doc_user.id, specialization='General Practice', phone_number='01012345678')
            db.session.add(doctor_profile)
            db.session.commit()
            print("Sample doctor@securehealth.com created with password 'Doctor@123'.")
            log_action(doc_user.id, 'System Init', 'Sample doctor created.')

        # Create another sample doctor user if one doesn't exist
        if not User.query.filter_by(email='doctor2@securehealth.com').first():
            doc2_user = User(email='doctor2@securehealth.com', full_name='Dr. Sara Mohamed', role='doctor')
            doc2_user.set_password('Doctor@123') # Sample password
            db.session.add(doc2_user)
            db.session.commit()
            doctor2_profile = Doctor(user_id=doc2_user.id, specialization='Pediatrics', phone_number='01198765432')
            db.session.add(doctor2_profile)
            db.session.commit()
            print("Sample doctor2@securehealth.com created with password 'Doctor@123'.")
            log_action(doc2_user.id, 'System Init', 'Sample doctor2 created.')

    # --- Run the Flask Application ---
    # To run with HTTPS locally (requires cert.pem and key.pem in the same directory as app.py)
    # Generate them using: openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365
    # Then uncomment the line below and comment out the app.run(debug=True) line.
    
    print(f"Running Flask app in debug mode: {app.config['DEBUG']}")
    if app.config['DEBUG'] and os.path.exists(app.config['SSL_CERT_PATH']) and os.path.exists(app.config['SSL_KEY_PATH']):
        print(f"Attempting to run with HTTPS using {app.config['SSL_CERT_PATH']} and {app.config['SSL_KEY_PATH']}")
        # app.run(debug=True, ssl_context=(app.config['SSL_CERT_PATH'], app.config['SSL_KEY_PATH']))
        # Using a more robust development server like Waitress or Gunicorn for production HTTPS
        # For development, you can use:
        app.run(debug=True, ssl_context='adhoc') # 'adhoc' generates temporary certs for development
    else:
        app.run(debug=True) # Run without HTTPS if not in debug or certs not found