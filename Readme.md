# Secure Health  
A Security-Focused Medical Web App with Ethical Hacking & Full Access Control  

## 📌 Project Overview  
**Secure Health** is a comprehensive, security-oriented medical appointment and records system designed for **Cyber Security students (Information Management Security)**.  
The project simulates a real-world healthcare application where students **develop, secure, and attack their own system**, reinforcing theoretical knowledge through practical implementation.  

The system includes:  
- Multiple user roles (**Admin, Doctor, Patient**)  
- **Role-Based Access Control (RBAC)** at both the application and database levels  
- Secure API endpoints with **JWT authentication**  
- **2FA using Google Authenticator** for Admins & Doctors  
- **Logging & encryption mechanisms**  
- Protection against **SQL Injection, XSS, brute-force attacks**  
- An **ethical hacking phase** to test and harden the system  

---

## 👥 User Roles & Capabilities  

### **Admin**
- Full CRUD (Create, Read, Update, Delete) on all data  
- Manage users, assign/revoke privileges  
- Grant/ revoke SQL permissions via secure web interface  
- Enable/disable accounts  
- Monitor & export logs  

### **Doctor**
- **Create:** Add diagnoses, write prescriptions  
- **Read:** View assigned patients’ records  
- **Update:** Modify treatment notes  
- **Delete:** Remove draft records (if allowed)  

### **Patient**
- **Create:** Book appointments  
- **Read:** View own profile & prescriptions  
- **Update:** Edit contact info, change password  
- **Delete:** Cancel appointments  

---

## 🔐 Security Requirements  

### **Authentication & Authorization**
- JWT-based login for all roles  
- 2FA (Google Authenticator) for Admin & Doctor  

### **Web Security**
- Token checks & role guards on all routes  
- Protections against:  
  - **SQL Injection** → parameterized queries  
  - **XSS** → output escaping & input sanitization  
- HTTPS enforced with OpenSSL-generated certificates  

### **Logging & Monitoring**
- Log all: login attempts, data changes, privilege updates  
- Logs exportable to `.log` or `.csv`  
- Admins can audit & download logs  

### **Encryption**
- Encrypt sensitive fields (diagnoses, notes, prescriptions)  
- Enforce HTTPS on all endpoints  

---

## ⚔️ Ethical Hacking Phase  

After deployment, students will release a **vulnerable version** of the app and simulate attacks using **Kali Linux tools**.  

### **Attacks to Simulate**
- SQL Injection (login/search forms) → SQLMap  
- XSS (comment/message inputs) → manual payloads  
- Port scanning → Nmap  
- Brute-force login attacks → custom scripts  

### **Defenses to Implement**
- Input validation & escaping  
- Proper SQL binding (prepared statements)  
- Strong password policies  
- 2FA on login  

---

## 📂 Tech Stack  
- **Backend:** Python Flask  
- **Database:** MySQL / phpMyAdmin  
- **Frontend:** HTML, CSS, JavaScript  
- **Security Tools:** OpenSSL, SQLMap, Nmap, Kali Linux  
- **Auth:** JWT + Google Authenticator  

---

## ✅ Learning Outcomes  
By completing **Secure Health**, students will:  
- Apply **RBAC** at both application & DB levels  
- Implement **secure authentication & encryption**  
- Conduct **ethical hacking** on their own system  
- Strengthen defense mechanisms against cyber threats  
- Gain hands-on experience in **secure web development**  

---

