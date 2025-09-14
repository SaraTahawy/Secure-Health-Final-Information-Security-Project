# secure_health_app/routes/doctor.py
from flask import Blueprint, render_template, redirect, url_for, flash, request
from flask_jwt_extended import jwt_required, get_jwt_identity
from models import db, User, Doctor, Patient, MedicalRecord, Appointment
from routes import role_required, log_action
from datetime import datetime
from config import Config
from markupsafe import escape

# Create a Blueprint for doctor routes
doctor_bp = Blueprint('doctor', __name__, url_prefix='/doctor')

# --- Doctor Dashboard ---
@doctor_bp.route('/dashboard')
@jwt_required()
@role_required(['doctor'])
def dashboard():
    """Renders the doctor's dashboard with relevant information."""
    current_user_id = get_jwt_identity()
    doctor_user = User.query.get(current_user_id)
    doctor_profile = doctor_user.doctor_profile # Get the doctor's profile

    if not doctor_profile:
        flash('Doctor profile not found. Please contact an administrator.', 'danger')
        log_action(current_user_id, 'Doctor Profile Missing', f'Doctor user {doctor_user.email} has no associated profile.')
        return redirect(url_for('auth.logout')) # Log them out as their profile is incomplete

    # Fetch upcoming appointments for this doctor
    upcoming_appointments = Appointment.query.filter(
        Appointment.doctor_id == doctor_profile.id,
        Appointment.appointment_date >= datetime.utcnow(),
        Appointment.status.in_(['pending', 'confirmed']) # Only show pending/confirmed
    ).order_by(Appointment.appointment_date).all()

    # Fetch recent medical records created by this doctor
    recent_medical_records = MedicalRecord.query.filter(
        MedicalRecord.doctor_id == doctor_profile.id
    ).order_by(MedicalRecord.record_date.desc()).limit(10).all()

    return render_template('doctor_dashboard.html', doctor_user=doctor_user, doctor_profile=doctor_profile,
                           upcoming_appointments=upcoming_appointments,
                           recent_medical_records=recent_medical_records)

# --- Patient Management for Doctor ---
@doctor_bp.route('/patients')
@jwt_required()
@role_required(['doctor'])
def view_my_patients():
    """
    Displays a list of patients the doctor has interacted with (through records or appointments).
    This serves as the 'assigned patients' list.
    """
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))

    # Get distinct patient IDs from medical records created by this doctor
    patient_ids_from_records = db.session.query(MedicalRecord.patient_id).filter_by(doctor_id=doctor_profile.id).distinct()
    # Get distinct patient IDs from appointments with this doctor
    patient_ids_from_appointments = db.session.query(Appointment.patient_id).filter_by(doctor_id=doctor_profile.id).distinct()

    # Combine and get unique patient IDs
    all_patient_ids = [p.patient_id for p in patient_ids_from_records] + [p.patient_id for p in patient_ids_from_appointments]
    all_patient_ids = list(set(all_patient_ids)) # Remove duplicates

    # Fetch patient objects based on the unique IDs
    patients = Patient.query.filter(Patient.id.in_(all_patient_ids)).all()
    
    return render_template('doctor_patients.html', patients=patients)

@doctor_bp.route('/patient_records/<int:patient_id>')
@jwt_required()
@role_required(['doctor'])
def view_patient_records(patient_id):
    """
    Displays medical records for a specific patient.
    Doctors can only view records for patients they are 'assigned' to
    (i.e., have created records for or had appointments with).
    """
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))

    patient = Patient.query.get_or_404(patient_id) # Get the patient object

    # **Security Check: Enforce data-level RBAC**
    # Check if the current doctor has any record or appointment with this patient
    can_access_patient = db.session.query(Appointment).filter_by(doctor_id=doctor_profile.id, patient_id=patient.id).first() or \
                         db.session.query(MedicalRecord).filter_by(doctor_id=doctor_profile.id, patient_id=patient.id).first()
    
    if not can_access_patient:
        flash('You do not have permission to view records for this patient.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Access', 
                   f'Doctor {doctor_profile.user.email} attempted to view unauthorized patient {patient.user.email} records (Patient ID: {patient_id}).')
        return redirect(url_for('doctor.view_my_patients')) # Redirect to their patient list

    # Fetch medical records for the specific patient
    medical_records = MedicalRecord.query.filter_by(patient_id=patient.id).order_by(MedicalRecord.record_date.desc()).all()
    return render_template('doctor_view_patient_records.html', patient=patient, medical_records=medical_records)

@doctor_bp.route('/add_record/<int:patient_id>', methods=['GET', 'POST'])
@jwt_required()
@role_required(['doctor'])
def add_medical_record(patient_id):
    """
    Allows a doctor to add a new medical record for a specific patient.
    Doctors can only add records for patients they are 'assigned' to.
    """
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    patient = Patient.query.get_or_404(patient_id)

    # **Security Check: Enforce data-level RBAC**
    # Check if the current doctor has any record or appointment with this patient
    can_access_patient = db.session.query(Appointment).filter_by(doctor_id=doctor_profile.id, patient_id=patient.id).first() or \
                         db.session.query(MedicalRecord).filter_by(doctor_id=doctor_profile.id, patient_id=patient.id).first()

    if not can_access_patient:
        flash('You do not have permission to add records for this patient.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Modification', 
                   f'Doctor {doctor_profile.user.email} attempted to add record for unauthorized patient {patient.user.email} (Patient ID: {patient_id}).')
        return redirect(url_for('doctor.view_my_patients'))

    if request.method == 'POST':
        diagnosis = request.form['diagnosis']
        if not vulnerable_mode:
            diagnosis = escape(diagnosis)
        prescription = request.form.get('prescription')
        if not vulnerable_mode:
            prescription = escape(prescription) if prescription else ''
        notes = request.form.get('notes')
        if not vulnerable_mode:
            notes = escape(notes) if notes else ''

        # Create new MedicalRecord. Properties handle encryption.
        new_record = MedicalRecord(
            patient_id=patient.id,
            doctor_id=doctor_profile.id,
            decrypted_diagnosis=diagnosis, # Will be encrypted automatically
            decrypted_prescription=prescription, # Will be encrypted automatically
            decrypted_notes=notes # Will be encrypted automatically
        )
        db.session.add(new_record)
        db.session.commit()
        flash('Medical record added successfully!', 'success')
        log_action(current_user_id, 'Medical Record Creation', f'Doctor {doctor_profile.user.email} added record {new_record.id} for patient {patient.user.email}.')
        return redirect(url_for('doctor.view_patient_records', patient_id=patient.id))
    
    return render_template('add_record.html', patient=patient)

@doctor_bp.route('/edit_record/<int:record_id>', methods=['GET', 'POST'])
@jwt_required()
@role_required(['doctor'])
def edit_medical_record(record_id):
    """
    Allows a doctor to edit a medical record.
    Doctors can only edit records they have created.
    """
    vulnerable_mode = getattr(Config, 'VULNERABLE_MODE', False)
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))

    record = MedicalRecord.query.get_or_404(record_id)

    # **Security Check: Enforce data-level RBAC**
    # Doctor can only edit records they are the creator of.
    if record.doctor_id != doctor_profile.id:
        flash('You do not have permission to edit this medical record.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Modification', 
                   f'Doctor {doctor_profile.user.email} attempted to edit unauthorized medical record {record.id}.')
        return redirect(url_for('doctor.view_my_patients')) # Redirect away from unauthorized action
    
    if request.method == 'POST':
        diagnosis = request.form['diagnosis']
        prescription = request.form.get('prescription')
        notes = request.form.get('notes')

        # Update encrypted fields
        record.decrypted_diagnosis = diagnosis
        record.decrypted_prescription = prescription if prescription else ''
        record.decrypted_notes = notes if notes else ''

        if not vulnerable_mode:
            record.decrypted_diagnosis = escape(diagnosis)
            record.decrypted_prescription = escape(prescription) if prescription else ''
            record.decrypted_notes = escape(notes) if notes else ''

        db.session.commit()
        flash('Medical record updated successfully!', 'success')
        log_action(current_user_id, 'Medical Record Update (Doctor)', f'Doctor {doctor_profile.user.email} updated record {record.id} for patient {record.patient.user.email}.')
        return redirect(url_for('doctor.view_patient_records', patient_id=record.patient_id))
    
    # GET request: Display current record data (decrypted for editing)
    return render_template('edit_medical_record.html', record=record)

@doctor_bp.route('/delete_record/<int:record_id>', methods=['POST'])
@jwt_required()
@role_required(['doctor'])
def delete_medical_record(record_id):
    """
    Allows a doctor to delete a medical record.
    Doctors can only delete records they have created.
    """
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))

    # Fetch record with patient relationship
    record = db.session.query(MedicalRecord).options(db.joinedload(MedicalRecord.patient).joinedload(Patient.user)).get_or_404(record_id)

    # **Security Check: Enforce data-level RBAC**
    # Doctor can only delete records they are the creator of.
    if record.doctor_id != doctor_profile.id:
        flash('You do not have permission to delete this medical record.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Modification', 
                   f'Doctor {doctor_profile.user.email} attempted to delete unauthorized medical record {record.id}.')
        return redirect(url_for('doctor.view_my_patients')) # Redirect away from unauthorized action
    
    # Get patient email before deletion
    patient_email = record.patient.user.email if record.patient and record.patient.user else 'unknown'
    
    db.session.delete(record)
    db.session.commit()
    flash('Medical record deleted successfully!', 'success')
    log_action(current_user_id, 'Medical Record Deletion (Doctor)', f'Doctor {doctor_profile.user.email} deleted record {record.id} for patient {patient_email}.')
    return redirect(url_for('doctor.view_my_patients'))

# --- Appointment Management for Doctor ---
@doctor_bp.route('/appointments')
@jwt_required()
@role_required(['doctor'])
def view_appointments():
    """Displays all appointments for the current doctor."""
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    # Fetch all appointments associated with this doctor, ordered by date
    appointments = Appointment.query.filter_by(doctor_id=doctor_profile.id).order_by(Appointment.appointment_date).all()
    return render_template('doctor_appointments.html', appointments=appointments)

@doctor_bp.route('/appointments/<int:appointment_id>/<action>', methods=['POST'])
@jwt_required()
@role_required(['doctor'])
def update_appointment_status(appointment_id, action):
    """
    Allows doctor to update the status of an appointment (confirm, complete, cancel).
    Doctors can only modify their own appointments.
    """
    current_user_id = get_jwt_identity()
    doctor_profile = Doctor.query.filter_by(user_id=current_user_id).first()
    if not doctor_profile:
        flash('Doctor profile not found.', 'danger')
        return redirect(url_for('doctor.dashboard'))
    
    appointment = Appointment.query.get_or_404(appointment_id)

    # **Security Check: Enforce data-level RBAC**
    # Doctor can only update appointments assigned to them.
    if appointment.doctor_id != doctor_profile.id:
        flash('You do not have permission to modify this appointment.', 'danger')
        log_action(current_user_id, 'Unauthorized Data Modification', 
                   f'Doctor {doctor_profile.user.email} attempted to modify unauthorized appointment {appointment.id}.')
        return redirect(url_for('doctor.view_appointments'))

    # Update appointment status based on action
    if action == 'confirm':
        appointment.status = 'confirmed'
        flash(f'Appointment {appointment.id} confirmed.', 'success')
        log_action(current_user_id, 'Appointment Status Update', f'Doctor {doctor_profile.user.email} confirmed appointment {appointment.id}.')
    elif action == 'complete':
        appointment.status = 'completed'
        flash(f'Appointment {appointment.id} marked as completed.', 'success')
        log_action(current_user_id, 'Appointment Status Update', f'Doctor {doctor_profile.user.email} marked appointment {appointment.id} as completed.')
    elif action == 'cancel':
        appointment.status = 'cancelled'
        flash(f'Appointment {appointment.id} cancelled.', 'info')
        log_action(current_user_id, 'Appointment Status Update', f'Doctor {doctor_profile.user.email} cancelled appointment {appointment.id}.')
    else:
        flash('Invalid action for appointment status.', 'danger')
    
    db.session.commit()
    return redirect(url_for('doctor.view_appointments'))