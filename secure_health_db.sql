-- secure_health_db.sql

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";

--
-- Database: `secure_health_db`
--
CREATE DATABASE IF NOT EXISTS `secure_health_db` DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci;
USE `secure_health_db`;

-- --------------------------------------------------------

--
-- Table structure for table `users`
--

CREATE TABLE `users` (
  `id` INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `email` VARCHAR(255) NOT NULL UNIQUE,
  `password` VARCHAR(255) NOT NULL,
  `full_name` VARCHAR(255) NOT NULL,
  `role` ENUM('admin', 'doctor', 'patient') NOT NULL,
  `is_active` BOOLEAN NOT NULL DEFAULT TRUE,
  `google_authenticator_secret` VARCHAR(255) DEFAULT NULL,
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Default Admin User (Password will be 'Admin@123' after hashing - change it immediately in production)
-- The password '$2b$12$R2R/J.X.H.Q.P.L.0.B.0.A.1.C.2.D.3.E.4.F.5.G.6.H.7.I.8.J.9.K.L.M.N.O.P.Q.R.S.T.U.V.W.X.Y.Z.' is a placeholder.
-- Flask's `app.py` will generate the actual hash for 'Admin@123' and insert it on first run.
--
INSERT INTO `users` (`email`, `password`, `full_name`, `role`, `google_authenticator_secret`) VALUES
('admin@securehealth.com', '$2b$12$ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789./.placeholder.hash.DoNotUseThisInProduction', 'Secure Health Admin', 'admin', NULL);


-- --------------------------------------------------------

--
-- Table structure for table `doctors`
--

CREATE TABLE `doctors` (
  `id` INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL UNIQUE,
  `specialization` VARCHAR(255) NOT NULL,
  `phone_number` VARCHAR(20) DEFAULT NULL,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

--
-- Sample Doctors (Linked to users table) - initial data for `app.py`
-- These will be inserted by `app.py` on first run if they don't exist.
--
-- INSERT INTO `users` (`email`, `password`, `full_name`, `role`, `google_authenticator_secret`) VALUES
-- ('doctor1@securehealth.com', '$2b$12$YourHashedDoctor1PasswordHere', 'Dr. Ahmed Ali', 'doctor', NULL),
-- ('doctor2@securehealth.com', '$2b$12$YourHashedDoctor2PasswordHere', 'Dr. Sara Mohamed', 'doctor', NULL);

-- INSERT INTO `doctors` (`user_id`, `specialization`, `phone_number`) VALUES
-- ((SELECT id FROM users WHERE email = 'doctor1@securehealth.com'), 'Cardiology', '01012345678'),
-- ((SELECT id FROM users WHERE email = 'doctor2@securehealth.com'), 'Pediatrics', '01198765432');

-- --------------------------------------------------------

--
-- Table structure for table `patients`
--

CREATE TABLE `patients` (
  `id` INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `user_id` INT(11) NOT NULL UNIQUE,
  `date_of_birth` DATE DEFAULT NULL,
  `gender` ENUM('Male', 'Female', 'Other') DEFAULT NULL,
  `address` TEXT DEFAULT NULL,
  `phone_number` VARCHAR(20) DEFAULT NULL,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `appointments`
--

CREATE TABLE `appointments` (
  `id` INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `patient_id` INT(11) NOT NULL,
  `doctor_id` INT(11) NOT NULL,
  `appointment_date` DATETIME NOT NULL,
  `reason` TEXT,
  `status` ENUM('pending', 'confirmed', 'cancelled', 'completed') DEFAULT 'pending',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`patient_id`) REFERENCES `patients`(`id`) ON DELETE CASCADE,
  FOREIGN KEY (`doctor_id`) REFERENCES `doctors`(`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `medical_records`
--

CREATE TABLE `medical_records` (
  `id` INT(11) NOT NULL AUTO_INCREMENT,
  `patient_id` INT(11) NOT NULL,
  `doctor_id` INT(11) NOT NULL,
  `diagnosis` BLOB NOT NULL,         -- Encrypted field
  `prescription` BLOB,               -- Encrypted field
  `notes` BLOB,                      -- Encrypted field
  `record_date` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  INDEX (`patient_id`),
  INDEX (`doctor_id`),
  FOREIGN KEY (`patient_id`) REFERENCES `patients`(`id`) ON DELETE CASCADE ON UPDATE CASCADE,
  FOREIGN KEY (`doctor_id`) REFERENCES `doctors`(`id`) ON DELETE CASCADE ON UPDATE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- --------------------------------------------------------

--
-- Table structure for table `logs`
--

CREATE TABLE `logs` (
  `id` INT(11) NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `user_id` INT(11) DEFAULT NULL,
  `action` VARCHAR(255) NOT NULL,
  `details` TEXT,
  `ip_address` VARCHAR(45),
  `timestamp` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

COMMIT;



