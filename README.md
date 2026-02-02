
---

````markdown
# 🔒 Secure Exam Paper Release Portal

A secure web-based system for controlled storage and release of examination papers using modern cryptographic techniques, multi-factor authentication, and role-based access control.

---

## 📌 Overview

The **Secure Exam Paper Release Portal** ensures **confidentiality, integrity, and controlled access** to examination papers throughout their lifecycle — from upload to final release.

The system implements **industry-standard cryptographic mechanisms**, **policy-based authorization**, and **comprehensive audit logging** to mitigate common security threats such as:

- Unauthorized access  
- Brute-force attacks  
- Data tampering  
- Insider misuse  

This project demonstrates the **practical application of information security concepts**, including encryption, hashing, digital signatures, authentication, authorization, and attack prevention.

---

## ✨ Key Features

- 🔐 Secure storage using **AES-256-GCM**
- 🔑 Secure AES key exchange using **RSA-2048**
- 🔒 Password hashing using **SHA-256 with per-user random salt**
- ✍️ Digital signatures for authenticity & integrity
- 📱 Multi-Factor Authentication (MFA) using **Twilio SMS OTP**
- 🛂 Role-Based Access Control (RBAC) with **ACL**
- 📜 Comprehensive audit logging
- 🚦 Rate limiting & secure session management
- 🌙 Responsive dark-themed cybersecurity UI

---

## 🔐 Security Features Mapping

| Security Requirement | Implementation |
|---------------------|----------------|
| Single-factor authentication | Username & password (SHA-256 + salt) |
| Multi-factor authentication | Password + SMS OTP (Twilio Verify) |
| Authorization | Role-Based Access Control (ACL) |
| Policy enforcement | Explicit role–resource permissions |
| File encryption | AES-256-GCM |
| Key exchange | RSA-2048 |
| Password protection | SHA-256 with random salt |
| Data integrity | Digital signatures (RSA) |
| Storage encoding | Base64 |
| Attack mitigation | Rate limiting, secure sessions |

---

## 👥 User Roles & Permissions

### 🛠 Admin
- Manage user accounts (create, update, delete)
- View all exam papers
- Access audit logs
- Monitor system-wide security events

### 📝 Exam Controller
- Upload exam papers (automatically encrypted)
- Release exam papers to faculty
- View and download all papers
- Digitally sign papers upon upload

### 👨‍🏫 Faculty
- View **only released** exam papers
- Download and decrypt released papers
- No upload or release permissions

---

## 🚀 Installation & Setup

### ✅ Prerequisites
- Node.js **v16 or higher**
- npm or yarn

---

### 📥 Installation Steps

#### 1️⃣ Clone the repository
```bash
git clone https://github.com/your-username/secure-exam-paper-portal.git
cd secure-exam-paper-portal
````

#### 2️⃣ Install dependencies

```bash
npm install
```

#### 3️⃣ Configure environment variables

Create a `.env` file in the root directory:

```env
TWILIO_ACCOUNT_SID=your_account_sid
TWILIO_AUTH_TOKEN=your_auth_token
TWILIO_VERIFY_SERVICE_SID=your_verify_service_sid
```

#### 4️⃣ Start the server

```bash
npm start
```

#### 5️⃣ Access the application

```
http://localhost:3000
```

---

## 🔑 Authentication Flow

1. User enters **username & password**
2. Server verifies password using **SHA-256 + salt**
3. OTP is sent via **Twilio SMS**
4. User submits OTP
5. OTP is verified using **Twilio Verify API**
6. Secure session is created upon success

---

## 🔐 Encryption Workflow

### 📤 Upload (Exam Controller)

1. Generate **RSA-2048 key pair**
2. Generate random **AES-256 key**
3. Encrypt exam paper using **AES-256-GCM**
4. Encrypt AES key using **RSA public key**
5. Digitally sign encrypted data using **RSA private key**
6. Encode encrypted content using **Base64**
7. Store encrypted data and metadata in database

### 📥 Download (Faculty / Controller)

1. Retrieve encrypted data from database
2. Decode Base64 content
3. Decrypt AES key using **RSA private key**
4. Decrypt exam paper using **AES-256-GCM**
5. Verify digital signature
6. Provide decrypted file to authorized user

---

## 🛂 Access Control Policy

* Only **Exam Controllers** can upload and release papers
* Only **released papers** are accessible to Faculty
* **Admin** has read-only access to papers
* All permissions are enforced **on every request**

---

## 🛡️ Attack Prevention Mechanisms

### 🔓 Brute Force Attacks

* Login rate limiting (5 attempts / 15 minutes)
* Account lockout after repeated failures
* IP address logging in audit logs

### 🔁 Replay Attacks

* Secure session tokens with expiration
* Timestamp validation
* Nonce usage for sensitive operations

### 💉 SQL Injection

* Parameterized queries (prepared statements)
* Strict input validation

### 🧼 Cross-Site Scripting (XSS)

* Content Security Policy (CSP)
* Input sanitization
* Output encoding

---

## 📊 Database Schema

### Tables

* **users** – User credentials and roles
* **exam_papers** – Encrypted papers and metadata
* **access_control** – Role–resource permission mapping
* **audit_logs** – Security and activity logs
* **otp_sessions** – Temporary OTP verification data

---

## 🧪 Testing Checklist

* ✅ Single-factor authentication
* ✅ Multi-factor authentication (OTP)
* ✅ Role-based access enforcement
* ✅ AES-256-GCM encryption/decryption
* ✅ RSA-2048 key exchange
* ✅ Digital signature generation & verification
* ✅ Audit log creation
* ✅ Rate limiting
* ✅ Secure session handling

---

## 📁 Project Structure

```
Secure-Exam-Paper-Upload-Portal/
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

## 🛠 Technologies Used

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
* Defense against common web application attacks
* Real-world secure system architecture design

---
