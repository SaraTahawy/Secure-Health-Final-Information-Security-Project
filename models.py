# secure_health_app/models.py
import os
import base64
from datetime import datetime
from database import db, bcrypt
from config import Config
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from sqlalchemy import Text, UnicodeText

# --- AES Encryption/Decryption Helper Functions ---
# These functions handle the encryption and decryption of sensitive data.
# They use AES-256 in CBC mode with PKCS7 padding.
# The IV (Initialization Vector) is prepended to the ciphertext for storage.

def encrypt_data(data):
    """Encrypts a string using AES-256 CBC mode."""
    if not data: # Handle empty or None data
        return None
    try:
        # Convert hex string encryption key from config to bytes
        key = base64.b16decode(Config.ENCRYPTION_KEY.upper())
        # Generate a random 16-byte (128-bit) IV for each encryption to ensure uniqueness
        iv = os.urandom(16)
        
        # Create AES cipher with CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # Apply PKCS7 padding to the data to match block size
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data.encode('utf-8')) + padder.finalize()

        # Encrypt the padded data
        encrypted_text = encryptor.update(padded_data) + encryptor.finalize()
        
        # Prepend IV to ciphertext and base64 encode the result for storage
        return base64.b64encode(iv + encrypted_text).decode('utf-8')
    except Exception as e:
        print(f"Encryption error: {e}")
        return None

def decrypt_data(encrypted_data):
    """Decrypts a base64-encoded AES-256 CBC ciphertext."""
    if not encrypted_data: # Handle empty or None encrypted data
        return None
    try:
        # Convert hex string encryption key from config to bytes
        key = base64.b16decode(Config.ENCRYPTION_KEY.upper())
        # Base64 decode the stored data
        decoded_data = base64.b64decode(encrypted_data)
        
        # Extract IV (first 16 bytes) and actual encrypted text
        iv = decoded_data[:16]
        encrypted_text = decoded_data[16:]

        # Create AES cipher with CBC mode using the extracted IV
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()

        # Decrypt the data
        decrypted_padded_data = decryptor.update(encrypted_text) + decryptor.finalize()

        # Unpad the decrypted data
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()

        return unpadded_data.decode('utf-8')
    except Exception as e:
        print(f"Decryption error: {e}")
        return None

# --- Database Models ---

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    full_name = db.Column(db.String(255), nullable=False)
    role = db.Column(db.Enum('admin', 'doctor', 'patient'), nullable=False) # User role
    is_active = db.Column(db.Boolean, default=True) # Account active status
    google_authenticator_secret = db.Column(db.String(255), nullable=True) # Stores 2FA secret
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Define relationships with other tables
    doctor_profile = db.relationship('Doctor', backref='user', uselist=False, cascade="all, delete-orphan")
    patient_profile = db.relationship('Patient', backref='user', uselist=False, cascade="all, delete-orphan")
    logs = db.relationship('Log', backref='user', lazy=True) # Relationship with logs

    def set_password(self, password):
        """Hashes the given password using bcrypt and stores it."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password, salt)
        self.password = hashed.decode('utf-8')

    def check_password(self, password):
        """Checks if the given password matches the hashed password."""
        if isinstance(password, str):
            password = password.encode('utf-8')
        if isinstance(self.password, str):
            self.password = self.password.encode('utf-8')
        return bcrypt.checkpw(password, self.password)

    def __repr__(self):
        return f'<User {self.email} ({self.role})>'

class Doctor(db.Model):
    __tablename__ = 'doctors'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    specialization = db.Column(db.String(255), nullable=False)
    phone_number = db.Column(db.String(20))

    # Relationships
    appointments = db.relationship('Appointment', backref='doctor', lazy=True)
    medical_records = db.relationship('MedicalRecord', backref='doctor', lazy=True)

    def __repr__(self):
        return f'<Doctor {self.user.full_name}>'

class Patient(db.Model):
    __tablename__ = 'patients'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), unique=True, nullable=False)
    date_of_birth = db.Column(db.Date)
    gender = db.Column(db.Enum('Male', 'Female', 'Other'))
    address = db.Column(db.Text)
    phone_number = db.Column(db.String(20))

    # Relationships
    appointments = db.relationship('Appointment', backref='patient', lazy=True)
    medical_records = db.relationship('MedicalRecord', backref='patient', lazy=True)

    def __repr__(self):
        return f'<Patient {self.user.full_name}>'

class Appointment(db.Model):
    __tablename__ = 'appointments'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id', ondelete='SET NULL'), nullable=True)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id', ondelete='SET NULL'), nullable=True)
    appointment_date = db.Column(db.DateTime, nullable=False)
    reason = db.Column(db.Text)
    status = db.Column(db.Enum('pending', 'confirmed', 'cancelled', 'completed'), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    __table_args__ = (
        db.CheckConstraint('patient_id IS NOT NULL OR doctor_id IS NOT NULL', name='check_not_both_null'),
    )

    def __repr__(self):
        return f'<Appointment {self.id} on {self.appointment_date}>'

class MedicalRecord(db.Model):
    __tablename__ = 'medical_records'
    id = db.Column(db.Integer, primary_key=True)
    patient_id = db.Column(db.Integer, db.ForeignKey('patients.id'), nullable=False)
    doctor_id = db.Column(db.Integer, db.ForeignKey('doctors.id'), nullable=False)
    diagnosis = db.Column(UnicodeText, nullable=False)
    prescription = db.Column(UnicodeText) 
    notes = db.Column(UnicodeText)
    record_date = db.Column(db.DateTime, default=datetime.utcnow)

    # Properties to handle encryption/decryption transparently
    @property
    def decrypted_diagnosis(self):
        """Returns the decrypted diagnosis."""
        return decrypt_data(self.diagnosis)

    @decrypted_diagnosis.setter
    def decrypted_diagnosis(self, value):
        """Encrypts and sets the diagnosis."""
        self.diagnosis = encrypt_data(value)

    @property
    def decrypted_prescription(self):
        """Returns the decrypted prescription."""
        return decrypt_data(self.prescription)

    @decrypted_prescription.setter
    def decrypted_prescription(self, value):
        """Encrypts and sets the prescription."""
        self.prescription = encrypt_data(value)

    @property
    def decrypted_notes(self):
        """Returns the decrypted notes."""
        return decrypt_data(self.notes)

    @decrypted_notes.setter
    def decrypted_notes(self, value):
        """Encrypts and sets the notes."""
        self.notes = encrypt_data(value)

    def __repr__(self):
        return f'<MedicalRecord {self.id} for Patient {self.patient_id}>'

class Log(db.Model):
    __tablename__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True) # Nullable for unauthenticated actions
    action = db.Column(db.String(255), nullable=False) # Description of the action
    details = db.Column(db.Text) # More detailed information about the action
    ip_address = db.Column(db.String(45)) # IP address of the user
    timestamp = db.Column(db.DateTime, default=datetime.utcnow) # When the action occurred

    def __repr__(self):
        return f'<Log {self.id} - {self.action} by User {self.user_id} at {self.timestamp}>'