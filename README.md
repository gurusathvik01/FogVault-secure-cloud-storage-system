# FogVault — Secure Cloud Storage System

FogVault is a security-focused cloud storage web application built using Django.
The project is inspired by real-world platforms like Google Drive and focuses
heavily on authentication security, audit logging, and safe file management.

This project was designed as an academic + job-ready backend system demonstrating
cloud security, OTP authentication, and audit compliance.

---

## 🔐 Key Features

### Authentication & Security
- Email OTP verification during account registration
- OTP-based password reset flow
- OTP expiry and resend cooldown protection
- Secure password hashing (Django authentication)
- Live password strength validation (frontend)
- Email alerts for account creation and login

### File Management
- Secure file upload system
- SHA-256 integrity verification
- File open tracking
- Star / unstar important files
- Soft delete (Trash) with restore option
- Permanent deletion support

### Audit & Monitoring
- Complete audit logging for:
  - File upload
  - File open
  - Star / unstar
  - Delete
  - Restore
  - Permanent delete
- Central audit history page for accountability

### Cloud / Fog Computing Concept
- Designed with distributed storage concepts in mind
- Emphasis on data integrity and secure access
- Scalable backend architecture

---

## 🧰 Tech Stack

- **Backend:** Django (Python)
- **Frontend:** HTML, CSS, JavaScript
- **Database:** SQLite (development)
- **Security:** OTP, SHA-256, session-based validation
- **Email:** SMTP (Gmail)

---

## 📁 Project Structure

FogVault/
├── core/
├── vaultapp/
├── templates/
├── static/
├── requirements.txt
├── .gitignore
└── manage.py


---

## 🚀 How to Run Locally

```bash
git clone https://github.com/yourusername/fogvault.git
cd fogvault
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python manage.py migrate
python manage.py runserver
```
```bash
Open browser:
http://127.0.0.1:8000/
```

---


🛡️ Security Highlights
No user account is created until OTP verification is complete
Temporary data stored securely in sessions
OTP attempts and expiry enforced
Sensitive actions are fully audited

---

🎯 Purpose of This Project
This project was built to:
Demonstrate real-world backend development skills
Showcase secure authentication flows
Apply cloud and fog computing concepts
Prepare for backend / cloud / security roles

---

📌 Author
Koduru Guru Sathvik
Backend Developer | Django | Cloud & Security Enthusiast
