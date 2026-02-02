import express from 'express';
import session from 'express-session';
import helmet from 'helmet';
import rateLimit from 'express-rate-limit';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs';

import { initializeDatabase, query, queryOne, execute, getLastInsertId, logAudit, checkPermission, getFacultyUsers } from './database.js';
import {
    verifyCredentials,
    sendOTP,
    verifyOTP,
    requireAuth,
    requireRole,
    createSession,
    destroySession
} from './auth.js';
import {
    encryptExamPaper,
    decryptExamPaper,
    hashPassword,
    generateSalt
} from './crypto-utils.js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// SECURITY MIDDLEWARE

// Helmet for security headers
app.use(helmet({
    contentSecurityPolicy: false // Allow inline scripts for demo
}));

// CORS
app.use(cors({
    origin: true,
    credentials: true
}));

// Rate limiting to prevent brute force attacks
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 50, // 50 attempts (increased for testing)
    message: JSON.stringify({ error: 'Too many login attempts, please try again later' }),
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        res.status(429).json({ error: 'Too many login attempts, please try again later' });
    }
});

// Body parser with increased limit for file uploads
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Session management
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: false, // Set to true in production with HTTPS
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000 // 24 hours
    }
}));

// Serve static files
app.use(express.static('public'));

//  INITIALIZE DATABASE 
await initializeDatabase();

// AUTHENTICATION ENDPOINTS 

//Public signup endpoint
app.post('/api/auth/signup', async (req, res) => {
    const { username, password, phoneNumber, role } = req.body;

    if (!username || !password || !phoneNumber || !role) {
        return res.status(400).json({ error: 'All fields required' });
    }

    // Only allow faculty and controller roles for public signup
    if (!['faculty', 'controller'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role. Only faculty and controller can self-register.' });
    }

    if (password.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);

    try {
        execute(`
      INSERT INTO users (username, password_hash, salt, phone_number, role)
      VALUES (?, ?, ?, ?, ?)
    `, [username, passwordHash, salt, phoneNumber, role]);

        logAudit(null, username, 'SIGNUP', 'authentication', `New user registered with role: ${role}`, req.ip);

        res.json({ success: true, message: 'Account created successfully' });
    } catch (error) {
        res.status(400).json({ error: 'Username already exists' });
    }
});


//Step 1: Login with username and password (single-factor)

app.post('/api/auth/login', loginLimiter, async (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ error: 'Username and password required' });
    }

    const result = await verifyCredentials(username, password);

    if (!result.success) {
        logAudit(null, username, 'LOGIN_FAILED', 'authentication', result.error, req.ip);
        return res.status(401).json({ error: result.error });
    }

    // Store user info temporarily for OTP verification
    req.session.pendingUser = result.user;

    logAudit(result.user.id, username, 'LOGIN_STEP1_SUCCESS', 'authentication', 'Password verified, awaiting OTP', req.ip);

    res.json({
        success: true,
        message: 'Password verified. OTP will be sent to your phone.',
        phoneNumber: result.user.phone_number
    });
});

//Step 2: Send OTP to phone number
app.post('/api/auth/send-otp', async (req, res) => {
    const { phoneNumber } = req.body;

    if (!phoneNumber) {
        return res.status(400).json({ error: 'Phone number required' });
    }

    const result = await sendOTP(phoneNumber);

    if (!result.success) {
        return res.status(500).json({ error: result.error });
    }

    res.json({ success: true, message: 'OTP sent to your phone' });
});

//Step 3: Verify OTP and complete login (multi-factor)
 
app.post('/api/auth/verify-otp', async (req, res) => {
    const { phoneNumber, otpCode } = req.body;

    if (!phoneNumber || !otpCode) {
        return res.status(400).json({ error: 'Phone number and OTP code required' });
    }

    if (!req.session.pendingUser) {
        return res.status(400).json({ error: 'Please login with username and password first' });
    }

    const result = await verifyOTP(phoneNumber, otpCode);

    if (!result.success) {
        logAudit(req.session.pendingUser.id, req.session.pendingUser.username, 'OTP_VERIFICATION_FAILED', 'authentication', result.error, req.ip);
        return res.status(401).json({ error: result.error });
    }

    // OTP verified - create session
    const user = req.session.pendingUser;
    delete req.session.pendingUser;
    createSession(req, user);

    res.json({
        success: true,
        message: 'Login successful',
        user: {
            username: user.username,
            role: user.role
        }
    });
});

//Logout
 
app.post('/api/auth/logout', (req, res) => {
    destroySession(req, res);
    res.json({ success: true, message: 'Logged out successfully' });
});

//Forgot Password - Step 1: Initiate password reset
 
app.post('/api/auth/forgot-password/initiate', loginLimiter, async (req, res) => {
    const { username } = req.body;

    if (!username) {
        return res.status(400).json({ error: 'Username required' });
    }

    try {
        // Look up user by username
        const user = queryOne('SELECT id, username, phone_number FROM users WHERE username = ?', [username]);

        // Always return success to prevent user enumeration
        if (!user) {
            logAudit(null, username, 'FORGOT_PASSWORD_FAILED', 'authentication', 'Invalid username', req.ip);
            // Still return success to not reveal user existence
            return res.json({ success: true, message: 'If the username exists, an OTP has been sent to the registered phone number' });
        }

        // Send OTP to user's phone
        const otpResult = await sendOTP(user.phone_number);

        if (!otpResult.success) {
            return res.status(500).json({ error: 'Failed to send OTP' });
        }

        // Store username temporarily for password reset
        req.session.passwordResetUser = user.username;

        logAudit(user.id, username, 'FORGOT_PASSWORD_INITIATED', 'authentication', 'Password reset OTP sent', req.ip);

        res.json({
            success: true,
            message: 'OTP has been sent to your registered phone number',
            phoneNumber: user.phone_number
        });
    } catch (error) {
        console.error('Forgot password error:', error);
        res.status(500).json({ error: 'An error occurred' });
    }
});

//Forgot Password - Step 2: Verify OTP and reset password
app.post('/api/auth/forgot-password/verify', async (req, res) => {
    const { username, otpCode, newPassword } = req.body;

    if (!username || !otpCode || !newPassword) {
        return res.status(400).json({ error: 'All fields required' });
    }

    if (newPassword.length < 6) {
        return res.status(400).json({ error: 'Password must be at least 6 characters' });
    }

    // Verify session has password reset initiated
    if (!req.session.passwordResetUser || req.session.passwordResetUser !== username) {
        return res.status(400).json({ error: 'Please initiate password reset first' });
    }

    try {
        // Look up user
        const user = queryOne('SELECT id, username, phone_number FROM users WHERE username = ?', [username]);

        if (!user) {
            return res.status(400).json({ error: 'Invalid request' });
        }

        // Verify OTP
        const otpResult = await verifyOTP(user.phone_number, otpCode);

        if (!otpResult.success) {
            logAudit(user.id, username, 'PASSWORD_RESET_FAILED', 'authentication', 'Invalid OTP', req.ip);
            return res.status(401).json({ error: 'Invalid OTP code' });
        }

        // Generate new salt and hash
        const salt = generateSalt();
        const passwordHash = hashPassword(newPassword, salt);

        // Update password
        execute(`
            UPDATE users 
            SET password_hash = ?, salt = ?
            WHERE id = ?
        `, [passwordHash, salt, user.id]);

        // Clear password reset session
        delete req.session.passwordResetUser;

        logAudit(user.id, username, 'PASSWORD_RESET_SUCCESS', 'authentication', 'Password successfully reset', req.ip);

        res.json({ success: true, message: 'Password reset successfully. Please login with your new password.' });
    } catch (error) {
        console.error('Password reset error:', error);
        res.status(500).json({ error: 'Failed to reset password' });
    }
});

//Get current user
 
app.get('/api/auth/me', requireAuth, (req, res) => {
    res.json({ user: req.session.user });
});

// USER MANAGEMENT (Admin only) 

//Get all users
 
app.get('/api/users', requireAuth, requireRole('admin'), (req, res) => {
    const users = query('SELECT id, username, phone_number, role, created_at FROM users');

    logAudit(req.session.user.id, req.session.user.username, 'VIEW_USERS', 'users', 'Viewed all users', req.ip);

    res.json({ users });
});

//Create new user
 
app.post('/api/users', requireAuth, requireRole('admin'), (req, res) => {
    const { username, password, phoneNumber, role } = req.body;

    if (!username || !password || !phoneNumber || !role) {
        return res.status(400).json({ error: 'All fields required' });
    }

    if (!['admin', 'controller', 'faculty'].includes(role)) {
        return res.status(400).json({ error: 'Invalid role' });
    }

    const salt = generateSalt();
    const passwordHash = hashPassword(password, salt);

    try {
        execute(`
      INSERT INTO users (username, password_hash, salt, phone_number, role)
      VALUES (?, ?, ?, ?, ?)
    `, [username, passwordHash, salt, phoneNumber, role]);

        const result = { lastInsertRowid: getLastInsertId() };

        logAudit(req.session.user.id, req.session.user.username, 'CREATE_USER', 'users', `Created user: ${username} with role: ${role}`, req.ip);

        res.json({ success: true, message: 'User created successfully', userId: result.lastInsertRowid });
    } catch (error) {
        res.status(400).json({ error: 'Username already exists' });
    }
});

//Delete user
 
app.delete('/api/users/:id', requireAuth, requireRole('admin'), (req, res) => {
    const userId = req.params.id;

    execute('DELETE FROM users WHERE id = ?', [userId]);

    logAudit(req.session.user.id, req.session.user.username, 'DELETE_USER', 'users', `Deleted user ID: ${userId}`, req.ip);

    res.json({ success: true, message: 'User deleted successfully' });
});

//Get all faculty users (Controller only)
app.get('/api/faculty', requireAuth, requireRole('controller'), (req, res) => {
    const faculty = getFacultyUsers();

    logAudit(req.session.user.id, req.session.user.username, 'VIEW_FACULTY', 'users', 'Viewed faculty list', req.ip);

    res.json({ faculty });
});

//  EXAM PAPER MANAGEMENT 

//Upload exam paper (Controller only)
 
app.post('/api/papers/upload', requireAuth, requireRole('controller'), async (req, res) => {
    const { title, subject, fileContent, filename } = req.body;

    if (!title || !subject || !fileContent || !filename) {
        return res.status(400).json({ error: 'All fields required' });
    }

    // Check permission
    const permission = checkPermission(req.session.user.role, 'exam_papers', 'create');
    if (!permission.allowed) {
        return res.status(403).json({ error: 'Permission denied', reason: permission.justification });
    }

    try {
        // Convert base64 file content to buffer
        const fileBuffer = Buffer.from(fileContent, 'base64');

        // Encrypt the exam paper
        const encrypted = encryptExamPaper(fileBuffer, filename);

        // Store in database
        execute(`
      INSERT INTO exam_papers (
        title, subject, original_filename, encrypted_data, iv, auth_tag,
        encrypted_aes_key, public_key, private_key, digital_signature, uploaded_by
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
            title,
            subject,
            encrypted.originalFilename,
            encrypted.encryptedData,
            encrypted.iv,
            encrypted.authTag,
            encrypted.encryptedAESKey,
            encrypted.publicKey,
            encrypted.privateKey,
            encrypted.signature,
            req.session.user.id
        ]);

        const result = { lastInsertRowid: getLastInsertId() };

        logAudit(
            req.session.user.id,
            req.session.user.username,
            'UPLOAD_PAPER',
            'exam_papers',
            `Uploaded paper: ${title} (${subject})`,
            req.ip
        );

        res.json({
            success: true,
            message: 'Exam paper uploaded and encrypted successfully',
            paperId: result.lastInsertRowid
        });
    } catch (error) {
        console.error('Upload error:', error);
        res.status(500).json({ error: 'Failed to upload exam paper' });
    }
});

//Get all exam papers
 
app.get('/api/papers', requireAuth, (req, res) => {
    let queryString = `
    SELECT 
      p.id, p.title, p.subject, p.original_filename, p.uploaded_at,
      p.is_released, p.released_at,
      u.username as uploaded_by_username
    FROM exam_papers p
    JOIN users u ON p.uploaded_by = u.id
  `;

    // Faculty can only see released papers
    if (req.session.user.role === 'faculty') {
        // Show papers that are either:
        // 1. Released to all (no specific faculty assignments)
        // 2. Specifically assigned to this faculty member
        queryString += `
      WHERE p.is_released = 1 
      AND (
        NOT EXISTS (SELECT 1 FROM paper_faculty_access WHERE paper_id = p.id)
        OR EXISTS (SELECT 1 FROM paper_faculty_access WHERE paper_id = p.id AND faculty_id = ${req.session.user.id})
      )
    `;
    }

    queryString += ' ORDER BY p.uploaded_at DESC';

    const papers = query(queryString);

    logAudit(req.session.user.id, req.session.user.username, 'VIEW_PAPERS', 'exam_papers', 'Viewed exam papers list', req.ip);

    res.json({ papers });
});

//Release exam paper (Controller only)
 
app.post('/api/papers/:id/release', requireAuth, requireRole('controller'), (req, res) => {
    const paperId = req.params.id;
    const { facultyIds } = req.body; // Array of faculty IDs, empty array means release to all

    // Check permission
    const permission = checkPermission(req.session.user.role, 'exam_papers', 'release');
    if (!permission.allowed) {
        return res.status(403).json({ error: 'Permission denied', reason: permission.justification });
    }

    // Mark paper as released
    execute(`
    UPDATE exam_papers 
    SET is_released = 1, released_at = CURRENT_TIMESTAMP, released_by = ?
    WHERE id = ?
  `, [req.session.user.id, paperId]);

    // If specific faculty IDs provided, add them to access table
    if (facultyIds && facultyIds.length > 0) {
        for (const facultyId of facultyIds) {
            try {
                execute(`
          INSERT OR IGNORE INTO paper_faculty_access (paper_id, faculty_id, granted_by)
          VALUES (?, ?, ?)
        `, [paperId, facultyId, req.session.user.id]);
            } catch (error) {
                console.error('Error granting access:', error);
            }
        }
    }

    // Get paper details for logging
    const paper = queryOne('SELECT title, subject FROM exam_papers WHERE id = ?', [paperId]);

    const releaseType = facultyIds && facultyIds.length > 0
        ? `to ${facultyIds.length} specific faculty members`
        : 'to all faculty';

    logAudit(
        req.session.user.id,
        req.session.user.username,
        'RELEASE_PAPER',
        'exam_papers',
        `Released paper: ${paper.title} (${paper.subject}) ${releaseType}`,
        req.ip
    );

    res.json({ success: true, message: 'Exam paper released successfully' });
});

//Download exam paper (Faculty and Controller)
app.get('/api/papers/:id/download', requireAuth, (req, res) => {
    const paperId = req.params.id;

    // Get paper from database
    const paper = queryOne('SELECT * FROM exam_papers WHERE id = ?', [paperId]);

    if (!paper) {
        return res.status(404).json({ error: 'Paper not found' });
    }

    // Faculty can only download released papers
    if (req.session.user.role === 'faculty' && !paper.is_released) {
        logAudit(
            req.session.user.id,
            req.session.user.username,
            'UNAUTHORIZED_DOWNLOAD_ATTEMPT',
            'exam_papers',
            `Attempted to download unreleased paper: ${paper.title}`,
            req.ip
        );
        return res.status(403).json({ error: 'This paper has not been released yet' });
    }

    try {
        console.log('Attempting to decrypt paper:', paperId);

        // Map database column names to expected format
        const encryptedPaper = {
            encryptedData: paper.encrypted_data,
            iv: paper.iv,
            authTag: paper.auth_tag,
            encryptedAESKey: paper.encrypted_aes_key,
            privateKey: paper.private_key
        };

        console.log('Mapped fields check:', {
            hasEncryptedData: !!encryptedPaper.encryptedData,
            hasIv: !!encryptedPaper.iv,
            hasAuthTag: !!encryptedPaper.authTag,
            hasEncryptedAESKey: !!encryptedPaper.encryptedAESKey,
            hasPrivateKey: !!encryptedPaper.privateKey
        });

        // Decrypt the paper
        const decryptedBuffer = decryptExamPaper(encryptedPaper);

        logAudit(
            req.session.user.id,
            req.session.user.username,
            'DOWNLOAD_PAPER',
            'exam_papers',
            `Downloaded paper: ${paper.title} (${paper.subject})`,
            req.ip
        );

        // Send decrypted file
        res.json({
            success: true,
            filename: paper.original_filename,
            fileContent: decryptedBuffer.toString('base64'),
            signature: paper.digital_signature,
            publicKey: paper.public_key
        });
    } catch (error) {
        console.error('Decryption error details:', {
            message: error.message,
            stack: error.stack,
            paperId: paperId
        });
        res.status(500).json({ error: 'Failed to decrypt exam paper', details: error.message });
    }
});

//AUDIT LOGS 

//Get audit logs (Admin only)
 
app.get('/api/audit-logs', requireAuth, requireRole('admin'), (req, res) => {
    const logs = query(`
    SELECT * FROM audit_logs 
    ORDER BY timestamp DESC 
    LIMIT 100
  `);

    res.json({ logs });
});

// ACCESS CONTROL POLICIES 

//Get all access control policies
 
app.get('/api/policies', requireAuth, requireRole('admin'), (req, res) => {
    const policies = query('SELECT * FROM access_control ORDER BY role, resource, action');

    res.json({ policies });
});

// START SERVER 

app.listen(PORT, () => {
    console.log('\n🔒 Secure Exam Paper Release Portal');
    console.log(`✓ Server running on http://localhost:${PORT}`);
    console.log('\n📋 Demo Credentials:');
    console.log('   Admin: admin / admin123');
    console.log('   Controller: controller1 / controller123');
    console.log('   Faculty: faculty1 / faculty123');
    console.log('\n🔐 Security Features Active:');
    console.log('   ✓ AES-256-GCM encryption');
    console.log('   ✓ RSA-2048 key exchange');
    console.log('   ✓ SHA-256 password hashing with salt');
    console.log('   ✓ Digital signatures');
    console.log('   ✓ Twilio phone OTP (MFA)');
    console.log('   ✓ Rate limiting (brute force protection)');
    console.log('   ✓ Access Control List (ACL)');
    console.log('   ✓ Audit logging\n');
});
