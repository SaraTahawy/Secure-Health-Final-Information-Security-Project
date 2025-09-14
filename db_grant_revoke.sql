-- Example SQL for database-level GRANT/REVOKE
-- Replace 'secure_health' with your database name and 'doctor_user', 'patient_user', etc. with your DB users

-- Grant all privileges to admin
GRANT ALL PRIVILEGES ON secure_health.* TO 'admin_user'@'localhost';

-- Doctors: Only SELECT/UPDATE on assigned patients (example, needs to be implemented with views or app logic)
GRANT SELECT, UPDATE ON secure_health.patients TO 'doctor_user'@'localhost';
GRANT SELECT, UPDATE ON secure_health.medical_records TO 'doctor_user'@'localhost';

-- Patients: Only SELECT on their own records (enforced by app, but can restrict at table level)
GRANT SELECT ON secure_health.patients TO 'patient_user'@'localhost';
GRANT SELECT ON secure_health.medical_records TO 'patient_user'@'localhost';

-- Revoke all privileges (example)
REVOKE ALL PRIVILEGES ON secure_health.* FROM 'doctor_user'@'localhost';
REVOKE ALL PRIVILEGES ON secure_health.* FROM 'patient_user'@'localhost';

-- You may need to FLUSH PRIVILEGES after changes
FLUSH PRIVILEGES;

-- Note: For true row-level security, use app logic or a DB supporting RLS (like PostgreSQL).
