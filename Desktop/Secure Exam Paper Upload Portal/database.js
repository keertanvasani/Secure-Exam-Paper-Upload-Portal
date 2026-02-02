import initSqlJs from 'sql.js';
import { hashPassword, generateSalt } from './crypto-utils.js';
import fs from 'fs';

let db;
const DB_FILE = 'exam_portal.db';

//Initialize database schema
//Creates tables for users, exam papers, access control, audit logs, and OTP sessions

export async function initializeDatabase() {
  const SQL = await initSqlJs();

  // Load existing database or create new one
  let buffer;
  try {
    buffer = fs.readFileSync(DB_FILE);
  } catch (e) {
    buffer = null;
  }

  db = new SQL.Database(buffer);

  // Users table with hashed passwords
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      phone_number TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('admin', 'controller', 'faculty')),
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  // Exam papers table with encryption metadata
  db.run(`
    CREATE TABLE IF NOT EXISTS exam_papers (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      subject TEXT NOT NULL,
      original_filename TEXT NOT NULL,
      encrypted_data TEXT NOT NULL,
      iv TEXT NOT NULL,
      auth_tag TEXT NOT NULL,
      encrypted_aes_key TEXT NOT NULL,
      public_key TEXT NOT NULL,
      private_key TEXT NOT NULL,
      digital_signature TEXT NOT NULL,
      uploaded_by INTEGER NOT NULL,
      uploaded_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      is_released BOOLEAN DEFAULT 0,
      released_at DATETIME,
      released_by INTEGER,
      FOREIGN KEY (uploaded_by) REFERENCES users(id),
      FOREIGN KEY (released_by) REFERENCES users(id)
    )
  `);

  // Paper-Faculty Access table for selective release
  db.run(`
    CREATE TABLE IF NOT EXISTS paper_faculty_access (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      paper_id INTEGER NOT NULL,
      faculty_id INTEGER NOT NULL,
      granted_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      granted_by INTEGER NOT NULL,
      FOREIGN KEY (paper_id) REFERENCES exam_papers(id),
      FOREIGN KEY (faculty_id) REFERENCES users(id),
      FOREIGN KEY (granted_by) REFERENCES users(id),
      UNIQUE(paper_id, faculty_id)
    )
  `);

  // Access Control List (ACL)
  db.run(`
    CREATE TABLE IF NOT EXISTS access_control (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      role TEXT NOT NULL,
      resource TEXT NOT NULL,
      action TEXT NOT NULL,
      allowed BOOLEAN NOT NULL,
      policy_justification TEXT NOT NULL,
      UNIQUE(role, resource, action)
    )
  `);

  // Audit logs
  db.run(`
    CREATE TABLE IF NOT EXISTS audit_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      username TEXT NOT NULL,
      action TEXT NOT NULL,
      resource TEXT,
      details TEXT,
      ip_address TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (user_id) REFERENCES users(id)
    )
  `);

  // OTP sessions
  db.run(`
    CREATE TABLE IF NOT EXISTS otp_sessions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phone_number TEXT NOT NULL,
      otp_code TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME NOT NULL,
      verified BOOLEAN DEFAULT 0
    )
  `);

  saveDatabase();
  console.log('✓ Database schema initialized');

  // Initialize access control policies
  initializeACL();

  // Create demo users
  // createDemoUsers(); // Commented out - function not defined
}

//save database to file
function saveDatabase() {
  const data = db.export();
  const buffer = Buffer.from(data);
  fs.writeFileSync(DB_FILE, buffer);
}

//Initialize Access Control List with policies
function initializeACL() {
  const policies = [
    // Admin policies
    {
      role: 'admin', resource: 'users', action: 'create', allowed: true,
      justification: 'Admin can create new user accounts for system management'
    },
    {
      role: 'admin', resource: 'users', action: 'read', allowed: true,
      justification: 'Admin can view all users for management purposes'
    },
    {
      role: 'admin', resource: 'users', action: 'update', allowed: true,
      justification: 'Admin can update user information and roles'
    },
    {
      role: 'admin', resource: 'users', action: 'delete', allowed: true,
      justification: 'Admin can remove users from the system'
    },
    {
      role: 'admin', resource: 'exam_papers', action: 'read', allowed: true,
      justification: 'Admin can view all exam papers for oversight'
    },
    {
      role: 'admin', resource: 'audit_logs', action: 'read', allowed: true,
      justification: 'Admin can view audit logs for security monitoring'
    },

    // Exam Controller policies
    {
      role: 'controller', resource: 'exam_papers', action: 'create', allowed: true,
      justification: 'Only Exam Controller can upload exam papers to ensure authenticity'
    },
    {
      role: 'controller', resource: 'exam_papers', action: 'read', allowed: true,
      justification: 'Controller can view all papers they manage'
    },
    {
      role: 'controller', resource: 'exam_papers', action: 'release', allowed: true,
      justification: 'Only Controller can release papers at scheduled time'
    },
    {
      role: 'controller', resource: 'users', action: 'read', allowed: false,
      justification: 'Controller cannot access user management'
    },

    // Faculty policies
    {
      role: 'faculty', resource: 'exam_papers', action: 'read', allowed: true,
      justification: 'Faculty can view released exam papers only'
    },
    {
      role: 'faculty', resource: 'exam_papers', action: 'download', allowed: true,
      justification: 'Faculty can download released papers for exam administration'
    },
    {
      role: 'faculty', resource: 'exam_papers', action: 'create', allowed: false,
      justification: 'Faculty cannot upload papers - only Controller can'
    },
    {
      role: 'faculty', resource: 'exam_papers', action: 'release', allowed: false,
      justification: 'Faculty cannot release papers - only Controller can'
    },
    {
      role: 'faculty', resource: 'users', action: 'read', allowed: false,
      justification: 'Faculty cannot access user management'
    }
  ];

  for (const policy of policies) {
    try {
      db.run(`
        INSERT OR IGNORE INTO access_control (role, resource, action, allowed, policy_justification)
        VALUES (?, ?, ?, ?, ?)
      `, [policy.role, policy.resource, policy.action, policy.allowed ? 1 : 0, policy.justification]);
    } catch (e) {
      // Ignore duplicates
    }
  }

  saveDatabase();
  console.log('✓ Access control policies initialized');
}



//Execute a query and return results
export function query(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);

  const results = [];
  while (stmt.step()) {
    results.push(stmt.getAsObject());
  }
  stmt.free();

  return results;
}

//Execute a query and return first result
export function queryOne(sql, params = []) {
  const results = query(sql, params);
  return results.length > 0 ? results[0] : null;
}

//Execute a query without returning results
export function execute(sql, params = []) {
  db.run(sql, params);
  saveDatabase();
}

//Get last insert ID
export function getLastInsertId() {
  const result = queryOne('SELECT last_insert_rowid() as id');
  return result ? result.id : null;
}

//Log audit event

export function logAudit(userId, username, action, resource, details, ipAddress) {
  execute(`
    INSERT INTO audit_logs (user_id, username, action, resource, details, ip_address)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [userId, username, action, resource, details, ipAddress]);
}

//Check if user has permission

export function checkPermission(role, resource, action) {
  const result = queryOne(`
    SELECT allowed, policy_justification FROM access_control
    WHERE role = ? AND resource = ? AND action = ?
  `, [role, resource, action]);

  return result ? { allowed: result.allowed === 1, justification: result.policy_justification } : { allowed: false, justification: 'No policy defined' };
}

//Get all faculty users

export function getFacultyUsers() {
  return query(`
    SELECT id, username, phone_number, created_at
    FROM users
    WHERE role = 'faculty'
    ORDER BY username
  `);
}

export { db };
export default { db, initializeDatabase, query, queryOne, execute, getLastInsertId, logAudit, checkPermission, getFacultyUsers };
