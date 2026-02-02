# 🔒 Secure Exam Paper Upload Portal

A secure web-based system for controlled storage and release of examination papers using modern cryptographic techniques, multi-factor authentication, and role-based access control.

---

## 📌 Overview

The **Secure Exam Paper Upload Portal** is designed to ensure confidentiality, integrity, and controlled access to examination papers throughout their lifecycle — from upload to final release.

The system implements **industry-standard cryptographic mechanisms**, **policy-based authorization**, and **comprehensive audit logging** to mitigate common security threats such as unauthorized access, brute-force attacks, and data tampering.

This project demonstrates the **practical application of information security concepts** including encryption, hashing, digital signatures, authentication, authorization, and attack prevention.

---

## ✨ Key Features

* Secure storage of exam papers using **AES-256-GCM**
* Secure AES key exchange using **RSA-2048**
* **SHA-256 password hashing** with per-user random salt
* **Digital signatures** to ensure paper authenticity and integrity
* **Multi-factor authentication (MFA)** using Twilio SMS OTP
* **Role-Based Access Control (RBAC)** with Access Control Lists (ACL)
* Comprehensive **audit logging**
* Rate limiting and session management
* Responsive dark-themed UI with cybersecurity-inspired design

---

## 🔐 Security Features Mapping

| Security Requirement         | Implementation                       |
| ---------------------------- | ------------------------------------ |
| Single-factor authentication | Username & password (SHA-256 + salt) |
| Multi-factor authentication  | Password + Twilio SMS OTP            |
| Authorization                | Role-Based Access Control (ACL)      |
| Policy enforcement           | Explicit role–resource permissions   |
| File encryption              | AES-256-GCM                          |
| Key exchange                 | RSA-2048                             |
| Password protection          | SHA-256 with random salt             |
| Data integrity               | Digital signatures (RSA)             |
| Storage encoding             | Base64                               |
| Attack mitigation            | Rate limiting, secure sessions       |

---

## 👥 User Roles & Permissions

### **Admin**

* Manage user accounts (create, update, delete)
* View all exam papers
* Access audit logs
* Monitor system-wide security events

### **Exam Controller**

* Upload exam papers (automatically encrypted)
* Release exam papers to faculty
* View and download all papers
* Digitally sign papers upon upload

### **Faculty**

* View only released exam papers
* Download and decrypt released papers
* No upload or release permissions

---

## 🚀 Installation & Setup

### Prerequisites

* Node.js v16 or higher
* npm or yarn

### Installation Steps

1. **Install dependencies**

```bash
npm install
```

2. **Configure environment variables**

The `.env` file must contain Twilio credentials:

```
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_VERIFY_SERVICE_SID=your_verify_service_sid
```

3. **Start the server**

```bash
npm start
```

4. **Access the application**

```
http://localhost:3000
```

---

## 🔑 Authentication Flow

1. User enters username and password
2. Server verifies password using SHA-256 + salt
3. OTP is sent via Twilio SMS
4. User submits OTP
5. OTP is verified via Twilio Verify API
6. Secure session is created upon success

---

## 🔐 Encryption Workflow

### Upload (Exam Controller)

1. Generate RSA-2048 key pair
2. Generate random AES-256 key
3. Encrypt exam paper using AES-256-GCM
4. Encrypt AES key using RSA public key
5. Digitally sign encrypted data using RSA private key
6. Encode encrypted content using Base64
7. Store encrypted data and metadata in database

### Download (Faculty / Controller)

1. Retrieve encrypted data from database
2. Decode Base64 content
3. Decrypt AES key using RSA private key
4. Decrypt exam paper using AES-256-GCM
5. Verify digital signature
6. Provide decrypted file to authorized user

---

## 🛂 Access Control Policy

* Only **Exam Controllers** can upload and release exam papers
* Only **released** papers are accessible to Faculty
* Admin has read-only access to papers but full access to logs and users
* All permissions are enforced at every request

---

## 🛡️ Attack Prevention Mechanisms

### Brute Force Attacks

* Login rate limiting (5 attempts per 15 minutes)
* Account lockout on repeated failures
* IP logging in audit logs

### Replay Attacks

* Secure session tokens with expiration
* Timestamp validation
* Nonce usage for sensitive actions

### SQL Injection

* Parameterized queries (prepared statements)
* Input validation

### Cross-Site Scripting (XSS)

* Content Security Policy headers
* Input sanitization
* Output encoding

---

## 📊 Database Schema

### Tables

* **users** – User credentials and roles
* **exam_papers** – Encrypted papers and metadata
* **access_control** – Role-resource permission mapping
* **audit_logs** – Security and activity logs
* **otp_sessions** – Temporary OTP verification data

---

## 🧪 Testing Checklist

* Single-factor authentication
* Multi-factor authentication (OTP)
* Role-based access enforcement
* AES-256-GCM encryption/decryption
* RSA-2048 key exchange
* Digital signature generation & verification
* Audit log creation
* Rate limiting
* Secure session handling

---

## 📁 Project Structure

```
focs-2/
├── server.js              # Express server
├── database.js            # Database initialization
├── auth.js                # Authentication & authorization
├── crypto-utils.js        # Cryptographic utilities
├── package.json           # Project dependencies
├── .env                   # Environment variables
├── public/
│   ├── index.html
│   ├── styles.css
│   └── app.js
└── README.md
```

---

## 🛠️ Technologies Used

* **Backend:** Node.js, Express
* **Database:** SQLite (better-sqlite3)
* **Authentication:** Twilio Verify API
* **Cryptography:** Node.js `crypto` module
* **Security:** Helmet, express-rate-limit
* **Frontend:** HTML5, CSS3, Vanilla JavaScript

---

## 🎓 Academic Relevance

This project demonstrates:

* Practical cryptography implementation
* Secure authentication and authorization
* Defense against common web attacks
* Real-world security architecture design

---

