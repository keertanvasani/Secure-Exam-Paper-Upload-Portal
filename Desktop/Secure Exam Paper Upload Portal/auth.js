import twilio from 'twilio';
import dotenv from 'dotenv';
import { queryOne, logAudit } from './database.js';
import { verifyPassword } from './crypto-utils.js';

dotenv.config();

const twilioClient = twilio(
    process.env.TWILIO_ACCOUNT_SID,
    process.env.TWILIO_AUTH_TOKEN
);

//single factor aunthentication
export async function verifyCredentials(username, password) {
    const user = queryOne('SELECT * FROM users WHERE username = ?', [username]);

    if (!user) {
        return { success: false, error: 'Invalid username or password' };
    }

    const isValid = verifyPassword(password, user.salt, user.password_hash);

    if (!isValid) {
        return { success: false, error: 'Invalid username or password' };
    }

    return {
        success: true,
        user: {
            id: user.id,
            username: user.username,
            phone_number: user.phone_number,
            role: user.role
        }
    };
}

// otp management
export async function sendOTP(phoneNumber) {
    try {
        const verification = await twilioClient.verify.v2
            .services(process.env.TWILIO_VERIFY_SERVICE_SID)
            .verifications
            .create({ to: phoneNumber, channel: 'sms' });

        console.log(`✓ OTP sent to ${phoneNumber}, status: ${verification.status}`);

        return { success: true, message: 'OTP sent successfully' };
    } catch (error) {
        console.error('Twilio OTP error:', error.message);
        return { success: false, error: 'Failed to send OTP: ' + error.message };
    }
}

//verify otp
export async function verifyOTP(phoneNumber, otpCode) {
    try {
        const verificationCheck = await twilioClient.verify.v2
            .services(process.env.TWILIO_VERIFY_SERVICE_SID)
            .verificationChecks
            .create({ to: phoneNumber, code: otpCode });

        console.log(`✓ OTP verification status: ${verificationCheck.status}`);

        if (verificationCheck.status === 'approved') {
            return { success: true, message: 'OTP verified successfully' };
        } else {
            return { success: false, error: 'Invalid OTP code' };
        }
    } catch (error) {
        console.error('Twilio verification error:', error.message);
        return { success: false, error: 'OTP verification failed: ' + error.message };
    }
}


export function requireAuth(req, res, next) {
    if (!req.session || !req.session.user) {
        return res.status(401).json({ error: 'Authentication required' });
    }
    next();
}


export function requireRole(...roles) {
    return (req, res, next) => {
        if (!req.session || !req.session.user) {
            return res.status(401).json({ error: 'Authentication required' });
        }

        if (!roles.includes(req.session.user.role)) {
            logAudit(
                req.session.user.id,
                req.session.user.username,
                'UNAUTHORIZED_ACCESS_ATTEMPT',
                req.path,
                `User with role ${req.session.user.role} attempted to access resource requiring roles: ${roles.join(', ')}`,
                req.ip
            );
            return res.status(403).json({ error: 'Insufficient permissions' });
        }

        next();
    };
}


export function createSession(req, user) {
    req.session.user = {
        id: user.id,
        username: user.username,
        role: user.role,
        phone_number: user.phone_number
    };

    logAudit(
        user.id,
        user.username,
        'LOGIN_SUCCESS',
        'authentication',
        'User logged in successfully with MFA',
        req.ip
    );
}


export function destroySession(req, res) {
    const username = req.session?.user?.username || 'unknown';
    const userId = req.session?.user?.id || null;

    req.session.destroy((err) => {
        if (err) {
            console.error('Session destruction error:', err);
        }

        logAudit(
            userId,
            username,
            'LOGOUT',
            'authentication',
            'User logged out',
            req.ip
        );
    });
}

export default {
    verifyCredentials,
    sendOTP,
    verifyOTP,
    requireAuth,
    requireRole,
    createSession,
    destroySession
};
