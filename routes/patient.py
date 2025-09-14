# secure_health_app/routes/patient.py
import re

def is_strong_password(password):
    """Checks that the password has at least 8 characters, including uppercase, lowercase, number, and special char"""
    if (len(password) < 8 or
        not re.search(r"[A-Z]", password) or
        not re.search(r"[a-z]", password) or
        not re.search(r"[0-9]", password) or
        not re.search(r"[!@#$%^&*(),.?\":{}|<>]", password)):
        return False
    return True

from markupsafe import escape
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Patient, Appointment, MedicalRecord, Doctor
from routes import role_required, log_action
from datetime import datetime

# Create a Blueprint for patient routes
patient_bp = Blueprint('patient', __name__, url_prefix='/patient')

# --- Patient Dashboard ---
@patient_bp.route('/dashboard')
@jwt_required()
@role_required(['patient'])
def dashboard():
    """Renders the patient's dashboard with their appointments and recent prescriptions."""
    current_user_id = get_jwt_identity()
    patient_user = db.session.get(User, current_user_id)
    patient_profile = patient_user.patient_profile # Get the patient's profile

    if not patient_profile:
        flash('Patient profile not found. Please contact an administrator.', 'danger')
        log_action(current_user_id, 'Patient Profile Missing', f'Patient user {patient_user.email} has no associated profile.')
        return redirect(url_for('auth.logout')) # Log them out as their profile is incomplete

    # Fetch upcoming appointments for this patient
    upcoming_appointments = Appointment.query.filter(
        Appointment.patient_id == patient_profile.id,
        Appointment.appointment_date >= datetime.utcnow(),
        Appointment.status.in_(['pending', 'confirmed'])
    ).order_by(Appointment.appointment_date).all()

    # Fetch recent medical records that have a prescription for this patient
    recent_prescriptions = MedicalRecord.query.filter(
        MedicalRecord.patient_id == patient_profile.id,
        MedicalRecord.prescription.isnot(None) # Only retrieve records that have a prescription
    ).order_by(MedicalRecord.record_date.desc()).limit(5).all()

    return render_template('patient_dashboard.html', patient_user=patient_user, patient_profile=patient_profile,
                           upcoming_appointments=upcoming_appointments, recent_prescriptions=recent_prescriptions)

# --- Patient Profile Management ---
@patient_bp.route('/profile', methods=['GET', 'POST'])
@jwt_required()
@role_required(['patient'])
def edit_profile():
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    """Allows a patient to view and update their personal profile information."""
    current_user_id = get_jwt_identity()
    patient_user = db.session.get(User, current_user_id)
    patient_profile = patient_user.patient_profile

    if not patient_profile:
        flash('Patient profile not found. Please contact an administrator.', 'danger')
        return redirect(url_for('patient.dashboard'))

    if request.method == 'POST':
        # Update user's full name (from User table)
        full_name = request.form['full_name']
        if not vulnerable_mode:
            full_name = escape(full_name)
        patient_user.full_name = full_name
        
        # Update patient profile details (from Patient table)
        dob_str = request.form['date_of_birth']
        if not vulnerable_mode:
            dob_str = escape(dob_str)
        patient_profile.date_of_birth = datetime.strptime(dob_str, '%Y-%m-%d').date() if dob_str else None
        gender = request.form.get('gender')
        if not vulnerable_mode:
            gender = escape(gender) if gender else ''
        patient_profile.gender = gender
        address = request.form.get('address')
        if not vulnerable_mode:
            address = escape(address) if address else ''
            # Ensure address is not a Markup object
            if hasattr(address, 'unescape'):
                address = address.unescape()
            elif hasattr(address, 'striptags'):
                address = address.striptags()
            elif hasattr(address, '__str__'):
                address = str(address)
        patient_profile.address = address
        
        phone_number = request.form.get('phone_number')
        if not vulnerable_mode:
            phone_number = escape(phone_number) if phone_number else ''
            # Ensure phone_number is not a Markup object
            if hasattr(phone_number, 'unescape'):
                phone_number = phone_number.unescape()
            elif hasattr(phone_number, 'striptags'):
                phone_number = phone_number.striptags()
            elif hasattr(phone_number, '__str__'):
                phone_number = str(phone_number)
        patient_profile.phone_number = phone_number
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        log_action(current_user_id, 'Profile Update (Patient)', f'Patient {patient_user.email} updated profile.')
        return redirect(url_for('patient.dashboard'))
    
    return render_template('patient_profile.html', patient_user=patient_user, patient_profile=patient_profile)

@patient_bp.route('/change_password', methods=['GET', 'POST'])
@jwt_required()
@role_required(['patient'])
def change_password():
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    """Allows a patient to change their password."""
    current_user_id = get_jwt_identity()
    patient_user = db.session.get(User, current_user_id)

    if request.method == 'POST':
        current_password = request.form['current_password']
        if not vulnerable_mode:
            current_password = escape(current_password)
        new_password = request.form['new_password']
        if not vulnerable_mode:
            new_password = escape(new_password)
        confirm_password = request.form['confirm_password']
        if not vulnerable_mode:
            confirm_password = escape(confirm_password)

        # Verify current password
        if not patient_user.check_password(current_password):
            flash('Current password is incorrect.', 'danger')
            return redirect(url_for('patient.change_password'))
        if new_password != confirm_password:
            flash('New passwords do not match.', 'danger')
            return redirect(url_for('patient.change_password'))
        if not is_strong_password(new_password):
            flash('Password must be at least 8 characters long and include uppercase, lowercase, digit, and special character.', 'danger')
            return redirect(url_for('patient.change_password'))
        # Hash and update password
        patient_user.password = bcrypt.generate_password_hash(new_password).decode('utf-8')
        db.session.commit()
        flash('Password changed successfully!', 'success')
        return redirect(url_for('patient.dashboard'))
    
    return render_template('change_password.html')

# --- Appointment Management for Patient ---
@patient_bp.route('/book_appointment', methods=['GET', 'POST'])
@jwt_required()
@role_required(['patient'])
def book_appointment():
    from config import Config
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    """Allows a patient to book a new appointment with a doctor."""
    current_user_id = get_jwt_identity()
    patient_profile = Patient.query.filter_by(user_id=current_user_id).first()
    doctors = Doctor.query.join(User).filter(User.is_active == True).all() # Get all active doctors

    if not patient_profile:
        flash('Patient profile not found. Please contact an administrator.', 'danger')
        return redirect(url_for('patient.dashboard'))

    if request.method == 'POST':
        doctor_id = request.form.get('doctor_id')
        if not vulnerable_mode:
            doctor_id = escape(doctor_id) if doctor_id else ''
            # Ensure doctor_id is a plain integer, not a Markup object
            if hasattr(doctor_id, 'unescape'):
                doctor_id = doctor_id.unescape()
            elif hasattr(doctor_id, 'striptags'):
                doctor_id = doctor_id.striptags()
            elif hasattr(doctor_id, '__str__'):
                doctor_id = str(doctor_id)
        appointment_date_str = request.form.get('appointment_date')
        reason = str(request.form.get('reason', ''))
        # Validate input
        if not doctor_id or not appointment_date_str or not reason:
            flash('All fields are required.', 'danger')
            return render_template('book_appointment.html', doctors=doctors)
        # Convert doctor_id to integer
        try:
            doctor_id = int(doctor_id)
        except (ValueError, TypeError):
            flash('Invalid doctor selected.', 'danger')
            return render_template('book_appointment.html', doctors=doctors)
        # Convert appointment_date_str to datetime
        try:
            appointment_date = datetime.strptime(appointment_date_str, '%Y-%m-%dT%H:%M')
        except ValueError:
            flash('Invalid date format.', 'danger')
            return render_template('book_appointment.html', doctors=doctors)
        # Check for existing appointment at the same time with the same doctor
        existing_appointment = Appointment.query.filter(
            Appointment.doctor_id == doctor_id,
            Appointment.appointment_date == appointment_date,
            Appointment.status.in_(['pending', 'confirmed'])
        ).first()
        if existing_appointment:
            flash('This doctor already has an appointment at the selected time.', 'danger')
            return render_template('book_appointment.html', doctors=doctors)

        # Ensure reason is a plain string (not Markup)
        if hasattr(reason, '__html__'):
            reason = str(reason)

        new_appointment = Appointment(
            patient_id=patient_profile.id,
            doctor_id=doctor_id,
            appointment_date=appointment_date,
            reason=reason,
            status='pending' # Doctor needs to confirm
        )
        db.session.add(new_appointment)
        db.session.commit()
        flash('Appointment booked successfully! Awaiting doctor confirmation.', 'success')
        log_action(current_user_id, 'Appointment Booked', f'Patient {patient_profile.user.email} booked appointment {new_appointment.id} with Doctor {new_appointment.doctor.user.full_name}.')
        return redirect(url_for('patient.view_appointments'))
    
    return render_template('book_appointment.html', doctors=doctors)

@patient_bp.route('/appointments')
@jwt_required()
@role_required(['patient'])
def view_appointments():
    """Displays all appointments for the current patient."""
    current_user_id = get_jwt_identity()
    patient_profile = Patient.query.filter_by(user_id=current_user_id).first()
    
    if not patient_profile:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    # Fetch all appointments associated with this patient, ordered by date
    appointments = Appointment.query.filter_by(patient_id=patient_profile.id).order_by(Appointment.appointment_date.desc()).all()
    return render_template('patient_appointments.html', appointments=appointments)

@patient_bp.route('/cancel_appointment/<int:appointment_id>', methods=['POST'])
@jwt_required()
@role_required(['patient'])
def cancel_appointment(appointment_id):
    """Allows a patient to cancel their own appointment."""
    current_user_id = get_jwt_identity()
    patient_profile = Patient.query.filter_by(user_id=current_user_id).first()
    
    if not patient_profile:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('patient.dashboard'))

    appointment = Appointment.query.get_or_404(appointment_id)

    # **Security Check: Enforce data-level RBAC**
    # Patient can only cancel their own appointments.
    if appointment.patient_id != patient_profile.id:
        flash('You do not have permission to cancel this appointment.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Modification', 
                   f'Patient {patient_profile.user.email} attempted to cancel unauthorized appointment {appointment.id}.')
        return redirect(url_for('patient.view_appointments'))
    
    # Prevent cancelling appointments that are already completed or cancelled
    if appointment.status in ['completed', 'cancelled']:
        flash('This appointment cannot be cancelled as its status is already final.', 'warning')
        log_action(current_user_id, 'Appointment Cancel Failed', f'Patient {patient_profile.user.email} tried to cancel final appointment {appointment.id}.')
    else:
        appointment.status = 'cancelled' # Set status to cancelled
        db.session.commit()
        flash('Appointment cancelled successfully.', 'success')
        log_action(current_user_id, 'Appointment Cancelled', f'Patient {patient_profile.user.email} cancelled appointment {appointment.id}.')
    
    return redirect(url_for('patient.view_appointments'))

# --- Patient Medical Records Access ---
@patient_bp.route('/prescriptions')
@jwt_required()
@role_required(['patient'])
def view_prescriptions():
    """Displays all prescriptions issued to the current patient."""
    current_user_id = get_jwt_identity()
    patient_profile = Patient.query.filter_by(user_id=current_user_id).first()

    if not patient_profile:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    # Fetch medical records for this patient that contain a prescription
    medical_records_with_prescriptions = MedicalRecord.query.filter(
        MedicalRecord.patient_id == patient_profile.id,
        MedicalRecord.prescription.isnot(None) # Filter for non-null prescription field
    ).order_by(MedicalRecord.record_date.desc()).all()

    return render_template('patient_prescriptions.html', records=medical_records_with_prescriptions)

@patient_bp.route('/medical_history')
@jwt_required()
@role_required(['patient'])
def view_medical_history():
    """Displays the full medical history (all records) for the current patient."""
    current_user_id = get_jwt_identity()
    patient_profile = Patient.query.filter_by(user_id=current_user_id).first()

    if not patient_profile:
        flash('Patient profile not found.', 'danger')
        return redirect(url_for('patient.dashboard'))
    
    # Fetch all medical records for this patient
    medical_records = MedicalRecord.query.filter_by(patient_id=patient_profile.id).order_by(MedicalRecord.record_date.desc()).all()
    return render_template('patient_medical_history.html', records=medical_records)