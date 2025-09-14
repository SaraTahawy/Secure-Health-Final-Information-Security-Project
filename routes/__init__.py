# secure_health_app/routes/__init__.py
from functools import wraps
from flask import redirect, url_for, flash, request, abort, render_template
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from models import User, Log, db
import os

# Decorator to ensure a user has required roles to access a route
def role_required(required_roles):
    def wrapper(fn):
        @wraps(fn)
        def decorator(*args, **kwargs):
            try:
                # Verify JWT token in the request
                verify_jwt_in_request()
                current_user_id = get_jwt_identity()
                current_user_claims = get_jwt() # Get all claims from the JWT

                # Check if the 'role' claim exists and is in the required_roles list
                if 'role' not in current_user_claims or current_user_claims['role'] not in required_roles:
                    flash('You do not have permission to access this page.', 'danger')
                    log_action(current_user_id, 'Unauthorized Access Attempt', 
                               f'User {current_user_id} (Role: {current_user_claims.get("role")}) attempted to access restricted resource requiring roles: {", ".join(required_roles)}.')
                    # Redirect to a generic unauthorized page or login
                    return redirect(url_for('auth.home')) # Redirect to home or 403 page
                
                # Optionally, you could also check the database for the user's active status and role
                # to ensure consistency, though JWT claims are typically sufficient once issued.
                # user_from_db = User.query.get(current_user_id)
                # if not user_from_db or user_from_db.role != current_user_claims['role'] or not user_from_db.is_active:
                #     flash('Your account status or role has changed. Please re-login.', 'danger')
                #     return redirect(url_for('auth.logout'))

            except Exception as e:
                # If JWT verification fails (e.g., token expired, invalid, missing)
                flash(f'Authentication required: {e}', 'danger')
                log_action(None, 'Authentication Error', f'JWT verification failed: {e} for IP: {request.remote_addr}.')
                return redirect(url_for('auth.login'))
            return fn(*args, **kwargs)
        return decorator
    return wrapper

# Helper function to log actions to the database
def log_action(user_id, action, details=None):
    """
    Logs an action performed by a user or the system.
    :param user_id: ID of the user performing the action (can be None for unauthenticated actions).
    :param action: A brief description of the action (e.g., 'User Login', 'Medical Record Created').
    :param details: Optional, more detailed information about the action.
    """
    # Get the client's IP address
    ip_address = request.remote_addr if request else 'N/A'
    
    log_entry = Log(user_id=user_id, action=action, details=details, ip_address=ip_address)
    try:
        db.session.add(log_entry)
        db.session.commit()
    except Exception as e:
        db.session.rollback() # Rollback if logging fails
        print(f"Error logging action: {e}") # Print error for debugging

# Function to force HTTPS redirect (for production or local SSL setup)
def force_https(app):
    """
    Forces all HTTP requests to redirect to HTTPS.
    Should only be used when SSL is properly configured on the server.
    """
    if not app.debug: # Only force HTTPS in non-debug (production) mode
        @app.before_request
        def redirect_to_https():
            if request.url.startswith('http://'):
                url = request.url.replace('http://', 'https://', 1)
                code = 301 # Permanent redirect
                return redirect(url, code=code)

# Function to register custom error handlers for the Flask app
def register_error_handlers(app):
    """Registers custom error pages for common HTTP error codes."""

    @app.errorhandler(401)
    def unauthorized(error):
        flash('Unauthorized Access. Please login.', 'danger')
        log_action(None, 'HTTP Error', f'401 Unauthorized access detected for URL: {request.path}.')
        return redirect(url_for('auth.login'))

    @app.errorhandler(403)
    def forbidden(error):
        flash('Forbidden. You do not have permission to access this resource.', 'danger')
        user_id = get_jwt_identity() if get_jwt_identity() else 'Unknown'
        log_action(user_id, 'HTTP Error', f'403 Forbidden access detected for URL: {request.path}.')
        return redirect(url_for('auth.home')) # Redirect to a generic home or dashboard

    @app.errorhandler(404)
    def not_found(error):
        # A simple error page, can be improved with a template
        log_action(None, 'HTTP Error', f'404 Not Found for URL: {request.path}.')
        return render_template('errors.html', error_code=404, error_message="The page you requested could not be found."), 404

    @app.errorhandler(500)
    def internal_server_error(error):
        db.session.rollback() # Rollback any pending database transactions to prevent stale state
        flash('An internal server error occurred. Please try again later.', 'danger')
        user_id = get_jwt_identity() if get_jwt_identity() else 'Unknown'
        log_action(user_id, 'HTTP Error', f'500 Internal Server Error: {error}. URL: {request.path}.')
        return render_template('errors.html', error_code=500, error_message="Something went wrong on our end."), 500