# secure_health_app/routes/admin.py
from markupsafe import escape
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_file, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity, get_jwt
from models import db, User, Doctor, Patient, Log, Appointment, MedicalRecord
from routes import role_required, log_action
import os
import csv
import io
from database import bcrypt

# Create a Blueprint for admin routes
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

# --- Admin Dashboard ---
@admin_bp.route('/dashboard')
@jwt_required()
@role_required(['admin'])
def dashboard():
    """Renders the admin dashboard with summary statistics."""
    current_user_id = get_jwt_identity()
    admin_user = db.session.get(User, current_user_id) # Fetch the admin user object

    # Get counts for various entities
    total_users = User.query.count()
    total_doctors = Doctor.query.count()
    total_patients = Patient.query.count()
    total_appointments = Appointment.query.count()
    
    return render_template('admin_dashboard.html', admin_user=admin_user, 
                           total_users=total_users, total_doctors=total_doctors,
                           total_patients=total_patients, total_appointments=total_appointments)

# --- User Management ---
@admin_bp.route('/manage_users', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def manage_users():
    """
    Allows admin to view, activate/deactivate, delete users, and change user roles.
    Includes adding new doctors.
    """
    users = User.query.all() # Fetch all users
    current_admin_id = get_jwt_identity()
    current_admin = db.session.get(User, current_admin_id)

    if request.method == 'POST':
        user_id = request.form.get('user_id')
        action = request.form.get('action')
        
        user = User.query.get(user_id)
        if not user:
            flash('User not found.', 'danger')
            log_action(get_jwt_identity(), 'Manage Users Failed', f'Attempted action on non-existent user ID: {user_id}.')
            return redirect(url_for('admin.manage_users'))

        current_admin_id = get_jwt_identity() # Get the ID of the logged-in admin

        if action == 'toggle_active':
            # Prevent admin from deactivating their own account
            if user.id == current_admin_id:
                flash('You cannot deactivate your own admin account.', 'danger')
                log_action(current_admin_id, 'User Status Change Failed', f'Attempted to deactivate own admin account: {user.email}.')
                return redirect(url_for('admin.manage_users'))
            
            user.is_active = not user.is_active # Toggle active status
            db.session.commit()
            flash(f'User {user.email} active status toggled to {user.is_active}.', 'success')
            log_action(current_admin_id, 'User Status Change', f'User {user.email} active status set to {user.is_active}.')
        
        elif action == 'delete':
            # Prevent admin from deleting their own account
            if user.id == current_admin_id:
                flash('You cannot delete your own admin account.', 'danger')
                log_action(current_admin_id, 'User Deletion Failed', f'Attempted to delete own admin account: {user.email}.')
                return redirect(url_for('admin.manage_users'))
            
            user_email_deleted = user.email # Store email before deletion for logging
            db.session.delete(user) # Delete the user and associated profiles (due to cascade)
            db.session.commit()
            flash(f'User {user_email_deleted} deleted.', 'success')
            log_action(current_admin_id, 'User Deletion', f'User {user_email_deleted} deleted by admin.')
        
        elif action == 'change_role':
            new_role = request.form.get('new_role')
            if new_role not in ['admin', 'doctor', 'patient']:
                flash('Invalid role selected.', 'danger')
                return redirect(url_for('admin.manage_users'))
            
            if user.id == current_admin_id and new_role != 'admin':
                flash('You cannot change your own role from admin.', 'danger')
                log_action(current_admin_id, 'User Role Change Failed', f'Attempted to change own admin role for {user.email}.')
                return redirect(url_for('admin.manage_users'))
            
            old_role = user.role
            if old_role != new_role: # Only process if role is actually changing
                # Handle changing associated profiles if role changes
                if old_role == 'doctor' and user.doctor_profile:
                    # Get all appointments for this doctor
                    appointments = Appointment.query.filter_by(doctor_id=user.id).all()
                    if appointments:
                        # Instead of setting to None, we'll mark these appointments as cancelled
                        for appointment in appointments:
                            appointment.status = 'cancelled'
                            appointment.reason = 'Doctor profile removed'
                        db.session.commit()
                    # Now safe to delete the doctor profile
                    db.session.delete(user.doctor_profile)
                elif old_role == 'patient' and user.patient_profile:
                    # Get all appointments for this patient
                    appointments = Appointment.query.filter_by(patient_id=user.id).all()
                    if appointments:
                        # Instead of setting to None, we'll mark these appointments as cancelled
                        for appointment in appointments:
                            appointment.status = 'cancelled'
                            appointment.reason = 'Patient profile removed'
                        db.session.commit()
                    db.session.delete(user.patient_profile)
                
                user.role = new_role # Update the user's role
                db.session.commit()
                
                # Create new profile if needed for the new role
                if new_role == 'doctor' and not user.doctor_profile:
                    doctor_profile = Doctor(user_id=user.id, specialization="General")
                    db.session.add(doctor_profile)
                    db.session.commit()
                elif new_role == 'patient' and not user.patient_profile:
                    patient_profile = Patient(user_id=user.id)
                    db.session.add(patient_profile)
                    db.session.commit()

                flash(f'User {user.email} role changed from {old_role} to {new_role}.', 'success')
                log_action(current_admin_id, 'User Role Change', f'User {user.email} role changed to {new_role}.')
            else:
                flash(f'User {user.email} already has the role {new_role}. No change made.', 'info')

        return redirect(url_for('admin.manage_users'))
    
    return render_template('manage_users.html', users=users, current_user=current_admin)

@admin_bp.route('/add_doctor', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def add_doctor():
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    """Allows admin to add a new doctor account."""
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        full_name = request.form.get('full_name')
        specialization = request.form.get('specialization')

        # Validate all required fields
        if not email or not password or not full_name or not specialization:
            flash('All fields are required.', 'danger')
            return render_template('add_doctor.html')


        # Import is_strong_password from auth_bp to reuse validation logic
        from routes.auth import is_strong_password
        if not is_strong_password(password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, numbers, and special characters.', 'danger')
            return render_template('add_doctor.html')

        existing_user = User.query.filter_by(email=email).first()
        if existing_user:
            flash('Email already registered. Please use a different email.', 'danger')
            return render_template('add_doctor.html')

        # Create the user and doctor profile
        user = User(email=email, role='doctor', is_active=True, full_name=full_name)
        user.set_password(password) # Hash the password
        db.session.add(user)
        db.session.commit() # Commit to get user.id

        # Create the doctor profile
        doctor = Doctor(user_id=user.id, specialization=specialization)
        db.session.add(doctor)
        db.session.commit()

        flash('Doctor added successfully!', 'success')
        log_action(get_jwt_identity(), 'Doctor Added', f'New doctor {user.email} added by admin {User.query.get(get_jwt_identity()).email}.')
        return redirect(url_for('admin.manage_users'))
    return render_template('add_doctor.html')

# --- Audit Logging ---
@admin_bp.route('/audit_logs')
@jwt_required()
@role_required(['admin'])
def audit_logs():
    """Displays system audit logs."""
    logs = Log.query.order_by(Log.timestamp.desc()).all() # Fetch all logs, newest first
    return render_template('audit_logs.html', logs=logs)

@admin_bp.route('/download_logs')
@jwt_required()
@role_required(['admin'])
def download_logs():
    """Allows admin to download audit logs as a CSV file."""
    logs = Log.query.order_by(Log.timestamp.desc()).all()
    
    # Create an in-memory text buffer for CSV
    output = io.StringIO()
    writer = csv.writer(output)

    # Write CSV header row
    writer.writerow(['ID', 'User ID', 'Action', 'Details', 'IP Address', 'Timestamp'])
    # Write log data
    for log in logs:
        writer.writerow([log.id, log.user_id, log.action, log.details, log.ip_address, log.timestamp])
    
    output.seek(0) # Rewind the buffer to the beginning
    
    # Send the CSV file as an attachment
    return send_file(io.BytesIO(output.getvalue().encode('utf-8')),
                     mimetype='text/csv',
                     as_attachment=True,
                     download_name='secure_health_logs.csv')

# --- Admin CRUD on All Data (Example: Medical Records) ---
# Admins have full CRUD access to ALL data across the system.

@admin_bp.route('/view_all_medical_records')
@jwt_required()
@role_required(['admin'])
def view_all_medical_records():
    """Admin view: Displays all medical records in the system."""
    records = MedicalRecord.query.all()
    return render_template('admin_view_all_medical_records.html', records=records)

@admin_bp.route('/edit_medical_record/<int:record_id>', methods=['GET', 'POST'])
@jwt_required()
@role_required(['admin'])
def edit_medical_record_admin(record_id):
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    """Admin view: Allows admin to edit any medical record."""
    record = MedicalRecord.query.get_or_404(record_id)
    
    if request.method == 'POST':
        # Update encrypted fields using properties that handle encryption/decryption
        diagnosis = request.form['diagnosis']
        if not vulnerable_mode:
            diagnosis = escape(diagnosis)
        record.decrypted_diagnosis = diagnosis
        prescription = request.form.get('prescription')
        if not vulnerable_mode:
            prescription = escape(prescription) if prescription else ''
        record.decrypted_prescription = prescription
        notes = request.form.get('notes')
        if not vulnerable_mode:
            notes = escape(notes) if notes else ''
        record.decrypted_notes = notes
        db.session.commit()
        flash('Medical record updated successfully by Admin!', 'success')
        log_action(get_jwt_identity(), 'Medical Record Update (Admin)', f'Admin updated medical record {record.id} for patient {record.patient.user.email}.')
        return redirect(url_for('admin.view_all_medical_records'))
    
    # GET request: Display current record data (decrypted for editing)
    return render_template('edit_medical_record.html', record=record)

@admin_bp.route('/delete_medical_record/<int:record_id>', methods=['POST'])
@jwt_required()
@role_required(['admin'])
def delete_medical_record_admin(record_id):
    """Admin view: Allows admin to delete any medical record."""
    record = MedicalRecord.query.get_or_404(record_id)
    
    db.session.delete(record)
    db.session.commit()
    flash('Medical record deleted successfully by Admin!', 'success')
    log_action(get_jwt_identity(), 'Medical Record Deletion (Admin)', f'Admin deleted medical record {record.id} for patient {record.patient.user.email}.')
    return redirect(url_for('admin.view_all_medical_records'))

# You can add similar CRUD routes for Appointments, Doctors, Patients here for full admin control.
# For example:
# @admin_bp.route('/view_all_appointments')
# @jwt_required()
# @role_required(['admin'])
# def view_all_appointments():
#     appointments = Appointment.query.all()
#     return render_template('admin_all_appointments.html', appointments=appointments)

# And so on for other full CRUD functionalities.