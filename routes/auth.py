# secure_health_app/routes/auth.py
import re

def is_strong_password(password):
    """Check password strength: min 8 chars, upper, lower, digit, special char"""
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

from flask import Blueprint, render_template, request, redirect, url_for, flash, session, current_app
from markupsafe import escape
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity, get_jwt, unset_jwt_cookies
from models import db, User, Patient, Doctor
from database import bcrypt
import pyotp # For TOTP (Time-based One-Time Password)
import qrcode # To generate QR codes for 2FA setup
import base64
import io
import requests # For OAuth requests
from config import Config
from routes import log_action # Import log_action from __init__.py
#from oauthlib.integrations.requests_client import OAuth2Session
from requests_oauthlib import OAuth2Session

from google_auth_oauthlib.flow import Flow # For Google OAuth
import os # Make sure os is imported if you use os.urandom

# Create a Blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

# Flask-Limiter instance (will be initialized in app context)
limiter = Limiter(key_func=get_remote_address)

# Global variable for Google OAuth client (will be initialized in app.py)
google_client = None

def set_google_client(client_flow):
    """Sets the global google_client with the initialized Flow object."""
    global google_client
    google_client = client_flow

# --- Helper Functions ---

def is_strong_password(password):
    """
    Checks if a password meets strength requirements:
    - Minimum 8 characters
    - At least one uppercase letter
    - At least one lowercase letter
    - At least one digit
    - At least one special character
    """
    if len(password) < 8:
        return False
    if not any(char.isupper() for char in password):
        return False
    if not any(char.islower() for char in password):
        return False
    if not any(char.isdigit() for char in password):
        return False
    # Check for at least one special character (non-alphanumeric)
    if not any(not char.isalnum() for char in password):
        return False
    return True

def create_auth_token(user):
    """Creates a JWT access token for the given user."""
    # additional_claims are automatically added via @jwt.additional_claims_loader in app.py
    return create_access_token(identity=str(user.id))

# --- Routes ---

@auth_bp.route('/callback')
def generic_callback():
    flash('You have reached a generic callback route. Please use the correct OAuth login flow.', 'warning')
    return redirect(url_for('auth.login'))

@auth_bp.route('/')
@auth_bp.route('/home')
def home():
    """Renders the home page, redirecting logged-in users to their dashboard."""
    try:
        verify_jwt_in_request(optional=True)
        current_user_id = get_jwt_identity()
        if current_user_id:
            user = db.session.get(User, current_user_id)
            if user:
                # Redirect to the appropriate dashboard based on the user's role
                if user.role == 'admin':
                    return redirect(url_for('admin.dashboard'))
                elif user.role == 'doctor':
                    return redirect(url_for('doctor.dashboard'))
                elif user.role == 'patient':
                    return redirect(url_for('patient.dashboard'))
    except Exception as e:
        # JWT verification failed (e.g., token expired, invalid). Treat as not logged in.
        pass
    return render_template('home.html')

@auth_bp.route('/register', methods=['GET', 'POST'])
def register():
    """Handles user registration for patients."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')

        if not email or not password or not full_name:
            flash('All fields are required.', 'danger')
            return redirect(url_for('auth.register'))
        
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.', 'danger')
            return redirect(url_for('auth.register'))

        if User.query.filter_by(email=email).first():
            flash('Email already registered. Please choose a different one.', 'danger')
            log_action(None, 'Registration Attempt Failed', f'Attempt to register with existing email: {email}.')
            return redirect(url_for('auth.register'))

        # Hash password and create new user
        if isinstance(password, str):
            password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed_password = bcrypt.hashpw(password, salt).decode('utf-8')
        new_user = User(email=email, password=hashed_password, full_name=full_name, role='patient')
        db.session.add(new_user)
        db.session.commit()

        # Create a patient profile associated with the new user
        patient_profile = Patient(user_id=new_user.id)
        db.session.add(patient_profile)
        db.session.commit()

        flash('Registration successful! Please login.', 'success')
        log_action(new_user.id, 'User Registration', f'New patient user registered: {email}.')
        return redirect(url_for('auth.login'))
    
    return render_template('register.html')

@auth_bp.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute", override_defaults=False)
def login():
    """Handles user login and 2FA with rate-limiting and input sanitization."""
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        otp_code = request.form.get('otp_code') # For 2FA
        # Input sanitization unless in vulnerable mode
        if not vulnerable_mode:
            email = escape(email) if email else ''
            password = escape(password) if password else ''
            # Ensure email is not a Markup object for DB query
            if hasattr(email, 'unescape'):
                email = email.unescape()
            elif hasattr(email, 'striptags'):
                email = email.striptags()
            elif hasattr(email, '__str__'):
                email = str(email)
            otp_code = escape(otp_code) if otp_code else ''
        user = User.query.filter_by(email=email).first()
        try:
            if not user or not user.check_password(password):
                flash('Invalid email or password.', 'danger')
                log_action(None, 'Failed Login', f'Failed login attempt for email: {email} from IP: {request.remote_addr}')
                return redirect(url_for('auth.login'))
        except ValueError as e:
            # If there's a ValueError (like Invalid salt), log it and handle gracefully
            flash('Invalid email or password.', 'danger')
            log_action(None, 'Failed Login', f'Failed login attempt for email: {email} from IP: {request.remote_addr}. Error: {str(e)}')
            return redirect(url_for('auth.login'))
        if not user.is_active:
            flash('Your account is deactivated. Please contact an administrator.', 'danger')
            log_action(user.id, 'Inactive Login Attempt', f'Inactive user {user.email} tried to log in from IP: {request.remote_addr}')
            return redirect(url_for('auth.login'))
        # 2FA check for doctors and admins
        if user.role in ['doctor', 'admin'] and user.google_authenticator_secret:
            if not otp_code:
                flash('2FA code required for login.', 'info')
                session['2fa_user_id'] = user.id
                return render_template('login.html', email=email, requires_2fa=True)
            totp = pyotp.TOTP(user.google_authenticator_secret)
            if not totp.verify(otp_code):
                flash('Invalid 2FA code.', 'danger')
                log_action(user.id, 'Failed 2FA', f'Failed 2FA attempt for user: {user.email} from IP: {request.remote_addr}')
                return redirect(url_for('auth.login'))
        # Successful login
        app_access_token = create_auth_token(user)
        resp = redirect(url_for(f'{user.role}.dashboard'))
        resp.set_cookie('access_token', app_access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
        flash('Login successful!', 'success')
        log_action(user.id, 'Login', f'User {user.email} logged in from IP: {request.remote_addr}.')
        return resp
    return render_template('login.html')

@auth_bp.route('/logout')
@jwt_required(optional=True)
def logout():
    """Handles user logout."""
    current_user_id = get_jwt_identity()
    user_email = "Unknown"
    if current_user_id:
        user = db.session.get(User, current_user_id)
        if user:
            user_email = user.email

    resp = redirect(url_for('auth.home'))
    unset_jwt_cookies(resp)
    flash('You have been logged out.', 'info')
    log_action(current_user_id, 'User Logout', f'User {user_email} logged out.')
    return resp

@auth_bp.route('/setup_2fa', methods=['GET', 'POST'])
@jwt_required()
def setup_2fa():
    """Allows a logged-in user to set up 2FA."""
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)
    if not user:
        flash('User not found. Please log in again.', 'danger')
        return redirect(url_for('auth.login')) 

    # In models.py, the field is user.google_authenticator_secret
    # In auth.py, user.totp_secret is used. This is inconsistent.
    # I will stick to user.google_authenticator_secret based on models.py.

    if request.method == 'POST':
        otp_code = request.form.get('otp_code')
        
        temp_secret = session.get('2fa_secret') # Secret is stored in session during setup
        if not temp_secret:
            flash('2FA setup session expired. Please try again.', 'danger')
            return redirect(url_for('auth.setup_2fa'))

        totp = pyotp.TOTP(temp_secret)
        
        if totp.verify(otp_code):
            user.google_authenticator_secret = temp_secret # Save the secret to the database
            db.session.commit()
            flash('2FA setup successfully!', 'success')
            log_action(user.id, '2FA Setup', f'User {user.email} successfully enabled 2FA.')
            session.pop('2fa_secret', None) # Remove from session
            return redirect(url_for(f'{user.role}.dashboard'))
        else:
            flash('Invalid 2FA code. Please try again.', 'danger')
            log_action(user.id, '2FA Setup Failed', f'User {user.email} failed 2FA setup with invalid code.')
            # Re-show QR with the same secret
            qrcode_svg = generate_qrcode(user.email, temp_secret)
            return render_template('setup_2fa.html', secret=temp_secret, qrcode_svg=qrcode_svg)

    # GET request: Generate a new secret and QR code for setup
    # If user already has a secret, they are re-setting. We should prompt or require password.
    # For now, if they visit, generate a new one for setup.
    totp_secret = pyotp.random_base32()
    session['2fa_secret'] = totp_secret # Store in session temporarily
    
    if user.google_authenticator_secret:
         flash('You are re-setting up 2FA. Previous 2FA will be overwritten upon successful verification. Scan the new QR code.', 'info')

    qrcode_svg = generate_qrcode(user.email, totp_secret)
    return render_template('setup_2fa.html', secret=totp_secret, qrcode_svg=qrcode_svg)


def generate_qrcode(email, secret):
    """Generates a TOTP QR code as an SVG string."""
    app_name = "SecureHealthApp"
    provisioning_uri = pyotp.totp.TOTP(secret).provisioning_uri(email, issuer_name=app_name)
    qr_img = qrcode.make(provisioning_uri)
    img_buffer = io.BytesIO()
    qr_img.save(img_buffer, 'SVG')
    img_buffer.seek(0)
    return img_buffer.getvalue().decode('utf-8')

@auth_bp.route('/disable_2fa', methods=['GET', 'POST'])
@jwt_required()
def disable_2fa():
    """Allows a logged-in user to disable 2FA."""
    current_user_id = get_jwt_identity()
    user = db.session.get(User, current_user_id)

    if not user.google_authenticator_secret:
        flash('2FA is not enabled for your account.', 'info')
        return redirect(url_for(f'{user.role}.dashboard'))

    if request.method == 'POST':
        password = request.form.get('password')
        otp_code = request.form.get('otp_code')

        if not user.check_password(password): # Use check_password method
            flash('Incorrect password.', 'danger')
            log_action(user.id, '2FA Disable Failed', f'User {user.email} failed to disable 2FA (incorrect password).')
            return render_template('disable_2fa.html')
        
        totp = pyotp.TOTP(user.google_authenticator_secret)
        if not totp.verify(otp_code):
            flash('Invalid 2FA code.', 'danger')
            log_action(user.id, '2FA Disable Failed', f'User {user.email} failed to disable 2FA (invalid OTP).')
            return render_template('disable_2fa.html')

        user.google_authenticator_secret = None
        db.session.commit()
        flash('2FA has been successfully disabled.', 'success')
        log_action(user.id, '2FA Disable', f'User {user.email} successfully disabled 2FA.')
        return redirect(url_for(f'{user.role}.dashboard'))
    
    return render_template('disable_2fa.html')

@auth_bp.route('/choose_role')
def choose_role():
    """Renders a page for users to choose their role or confirms it."""
    # You might want to add logic here to determine if a user
    # actually needs to choose a role, or just show a simple page.
    # For now, a placeholder template rendering.
    return render_template('choose_role.html') # You'll need to create this template

# --- Google OAuth Routes ---

@auth_bp.route('/login/google')
def google_login():
    if google_client is None:
        flash('Google OAuth not configured. Please contact administrator.', 'danger')
        return redirect(url_for('auth.login'))

    authorization_url, state = google_client.authorization_url()
    session['google_oauth_state'] = state
    log_action(None, 'Google OAuth Init', 'Initiating Google OAuth login.')
    return redirect(authorization_url)

@auth_bp.route('/login/google/authorized')
def google_callback():
    if google_client is None:
        flash('Google OAuth not configured. Please contact administrator.', 'danger')
        return redirect(url_for('auth.login'))

    if 'google_oauth_state' not in session or session['google_oauth_state'] != request.args.get('state'):
        flash('Invalid state parameter during Google OAuth. Please try again.', 'danger')
        log_action(None, 'Google OAuth Error', 'Invalid state parameter during Google OAuth.')
        return redirect(url_for('auth.login'))
    
    session.pop('google_oauth_state', None)

    try:
        google_client.fetch_token(authorization_response=request.url)
        user_info = google_client.id_token
        email = user_info['email']
        full_name = user_info.get('name', email.split('@')[0])

        user = User.query.filter_by(email=email).first()

        if user:
            if user.role == 'patient' and not user.patient_profile:
                patient = Patient(user_id=user.id)
                db.session.add(patient)
                db.session.commit()
                log_action(user.id, 'Patient Profile Creation', f'Patient profile created for existing user {user.email} via Google OAuth.')
            
            if user.google_authenticator_secret: # Check 2FA
                flash('Google login successful. Please enter your 2FA code.', 'info')
                session['2fa_user_id'] = user.id
                log_action(user.id, 'Google Login (2FA Pending)', f'User {user.email} logged in via Google, awaiting 2FA.')
                return render_template('login.html', email=user.email, requires_2fa=True)
            
            app_access_token = create_auth_token(user)
            resp = redirect(url_for(f'{user.role}.dashboard'))
            resp.set_cookie('access_token', app_access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
            flash('Login with Google successful!', 'success')
            log_action(user.id, 'Google Login', f'User {user.email} logged in via Google.')
            return resp
        else:
            # New user via Google
            # The user model uses 'password' for the hashed password field
            # and has set_password method.
            new_user = User(email=email, full_name=full_name, role='patient')
            # Set a random strong password as it won't be used for Google login
            # but the field is non-nullable.
            random_password = bcrypt.generate_password_hash(os.urandom(32)).decode('utf-8')
            new_user.password = random_password # Assign directly to the password field
            db.session.add(new_user)
            db.session.commit()

            patient = Patient(user_id=new_user.id)
            db.session.add(patient)
            db.session.commit()

            app_access_token = create_auth_token(new_user)
            resp = redirect(url_for('patient.dashboard'))
            resp.set_cookie('access_token', app_access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
            flash('Registration and login with Google successful!', 'success')
            log_action(new_user.id, 'Google Registration & Login', f'New user {new_user.email} registered and logged in via Google.')
            return resp

    except Exception as e:
        flash(f'Google login failed: {e}', 'danger')
        log_action(None, 'Google OAuth Error', f'Error during Google OAuth callback: {e}. Request args: {request.args}.')
        return redirect(url_for('auth.login'))

@auth_bp.route('/2fa_verify', methods=['POST'])
def two_factor_verify():
    """Endpoint to verify 2FA code after an OAuth login or normal login needing 2FA."""
    user_id_from_session = session.get('2fa_user_id')
    # Also handle direct 2FA form submission not from OAuth
    email_from_form = request.form.get('email_for_2fa') # Assuming login form can pass this if 2FA is required
    otp_code = request.form.get('otp_code')

    user = None
    if user_id_from_session:
        user = User.query.get(user_id_from_session)
    elif email_from_form: # This part is for direct login 2FA.
        user = User.query.filter_by(email=email_from_form).first()

    if not user or not otp_code:
        flash('Invalid 2FA verification attempt.', 'danger')
        session.pop('2fa_user_id', None)
        return redirect(url_for('auth.login'))

    if not user.google_authenticator_secret:
        flash('2FA not configured for this user.', 'danger')
        session.pop('2fa_user_id', None)
        return redirect(url_for('auth.login'))

    totp = pyotp.TOTP(user.google_authenticator_secret)
    if totp.verify(otp_code):
        session.pop('2fa_user_id', None)
        access_token = create_auth_token(user)
        resp = redirect(url_for(f'{user.role}.dashboard'))
        resp.set_cookie('access_token', access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
        flash('2FA verification successful! Login complete.', 'success')
        log_action(user.id, 'User Login (2FA Complete)', f'User {user.email} completed 2FA verification.')
        return resp
    else:
        flash('Invalid 2FA code. Please try again.', 'danger')
        log_action(user.id, '2FA Verification Failed', f'User {user.email} failed 2FA verification with invalid OTP.')
        # If it was a direct login attempt, show login page again with 2FA fields
        # If it was OAuth, it might need different handling or just redirect to login
        return render_template('login.html', email=user.email, requires_2fa=True)


# --- GitHub OAuth Routes ---
GITHUB_CLIENT_ID = Config.GITHUB_CLIENT_ID
GITHUB_CLIENT_SECRET = Config.GITHUB_CLIENT_SECRET
GITHUB_AUTHORIZATION_BASE_URL = "https://github.com/login/oauth/authorize"
GITHUB_TOKEN_URL = "https://github.com/login/oauth/access_token"
GITHUB_USER_API_URL = "https://api.github.com/user"


@auth_bp.route('/login/github')
def github_login():
    github_oauth = OAuth2Session(GITHUB_CLIENT_ID, scope=['user:email'])
    authorization_url, state = github_oauth.authorization_url(GITHUB_AUTHORIZATION_BASE_URL)
    session['github_oauth_state'] = state
    log_action(None, 'GitHub OAuth Init', 'Initiating GitHub OAuth login.')
    return redirect(authorization_url)

@auth_bp.route('/login/github/authorized')
def github_callback():
    if 'github_oauth_state' not in session or session['github_oauth_state'] != request.args.get('state'):
        flash('Invalid state parameter during GitHub OAuth. Please try again.', 'danger')
        log_action(None, 'GitHub OAuth Error', 'Invalid state parameter during GitHub OAuth.')
        return redirect(url_for('auth.login'))
    
    session.pop('github_oauth_state', None)

    try:
        github_oauth = OAuth2Session(GITHUB_CLIENT_ID)
        token = github_oauth.fetch_token(GITHUB_TOKEN_URL, client_secret=GITHUB_CLIENT_SECRET,
                                         authorization_response=request.url)
        
        github_user_info = github_oauth.get(GITHUB_USER_API_URL).json()
        email = github_user_info.get('email')
        full_name = github_user_info.get('name', github_user_info.get('login', 'Unknown'))

        if not email:
            emails_response = github_oauth.get(f"{GITHUB_USER_API_URL}/emails").json()
            for email_data in emails_response:
                if email_data.get('verified') and email_data.get('primary'):
                    email = email_data.get('email')
                    break
            if not email:
                flash('Could not retrieve a primary verified email from GitHub.', 'danger')
                log_action(None, 'GitHub OAuth Error', 'Could not retrieve email from GitHub user profile.')
                return redirect(url_for('auth.login'))

        user = User.query.filter_by(email=email).first()

        if user:
            if user.role == 'patient' and not user.patient_profile:
                patient = Patient(user_id=user.id)
                db.session.add(patient)
                db.session.commit()
                log_action(user.id, 'Patient Profile Creation', f'Patient profile created for existing user {user.email} via GitHub OAuth.')

            if user.google_authenticator_secret: # Check 2FA
                flash('GitHub login successful. Please enter your 2FA code.', 'info')
                session['2fa_user_id'] = user.id
                log_action(user.id, 'GitHub Login (2FA Pending)', f'User {user.email} logged in via GitHub, awaiting 2FA.')
                return render_template('login.html', email=user.email, requires_2fa=True)

            app_access_token = create_auth_token(user)
            resp = redirect(url_for(f'{user.role}.dashboard'))
            resp.set_cookie('access_token', app_access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
            flash('Login with GitHub successful!', 'success')
            log_action(user.id, 'GitHub Login', f'User {user.email} logged in via GitHub.')
            return resp
        else:
            new_user = User(email=email, full_name=full_name, role='patient')
            random_password = bcrypt.generate_password_hash(os.urandom(32)).decode('utf-8')
            new_user.password = random_password # Assign directly to the password field
            db.session.add(new_user)
            db.session.commit()

            patient = Patient(user_id=new_user.id)
            db.session.add(patient)
            db.session.commit()

            app_access_token = create_auth_token(new_user)
            resp = redirect(url_for('patient.dashboard'))
            resp.set_cookie('access_token', app_access_token, httponly=True, secure=request.is_secure, samesite='Lax', max_age=Config.JWT_ACCESS_TOKEN_EXPIRES.total_seconds())
            flash('Registration and login with GitHub successful!', 'success')
            log_action(new_user.id, 'GitHub Registration & Login', f'New user {new_user.email} registered and logged in via GitHub.')
            return resp

    except Exception as e:
        flash(f'GitHub login failed: {e}', 'danger')
        log_action(None, 'GitHub OAuth Error', f'Error during GitHub OAuth callback: {e}. Request args: {request.args}.')
        return redirect(url_for('auth.login'))