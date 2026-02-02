
let currentUser = null;
let currentView = 'login';

//Initialize 
document.addEventListener('DOMContentLoaded', async () => {
  setTimeout(() => {
    document.getElementById('loading-screen').classList.add('hidden');
  }, 1000);

  await checkAuth();
});

//authentication
async function checkAuth() {
  try {
    const response = await fetch('/api/auth/me', {
      credentials: 'include'
    });

    if (response.ok) {
      const data = await response.json();
      currentUser = data.user;
      showDashboard();
    } else {
      showLogin();
    }
  } catch (error) {
    showLogin();
  }
}

async function login(username, password) {
  try {
    const response = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    return data;
  } catch (error) {
    throw error;
  }
}

async function sendOTP(phoneNumber) {
  try {
    const response = await fetch('/api/auth/send-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ phoneNumber })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    return data;
  } catch (error) {
    throw error;
  }
}

async function verifyOTP(phoneNumber, otpCode) {
  try {
    const response = await fetch('/api/auth/verify-otp', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ phoneNumber, otpCode })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    currentUser = data.user;
    return data;
  } catch (error) {
    throw error;
  }
}

async function logout() {
  try {
    await fetch('/api/auth/logout', {
      method: 'POST',
      credentials: 'include'
    });

    currentUser = null;
    showLogin();
    showToast('Logged out successfully', 'success');
  } catch (error) {
    showToast('Logout failed', 'error');
  }
}

//UI
function render(html) {
  document.getElementById('content').innerHTML = html;
}

function showLogin() {
  currentView = 'login';
  render(`
    <div class="login-container">
      <div class="login-box">
        <div class="login-header">
          <div class="logo-icon" style="margin: 0 auto 20px; width: 80px; height: 80px; font-size: 40px;">
            🔒
          </div>
          <h1>SECURE EXAM PAPER UPLOAD PORTAL</h1>
          <p>Military-grade encryption for exam paper distribution</p>
        </div>
        
        <div class="card">
          <form id="login-form">
            <div class="form-group">
              <label class="form-label">USERNAME</label>
              <input type="text" class="form-input" id="username" required autocomplete="username">
            </div>
            
            <div class="form-group">
              <label class="form-label">PASSWORD</label>
              <input type="password" class="form-input" id="password" required autocomplete="current-password">
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
              PROCEED TO OTP VERIFICATION
            </button>
          </form>
          
          <div style="text-align: center; margin-top: 16px;">
            <a href="#" onclick="showForgotPassword(); return false;" style="color: var(--accent-primary); text-decoration: none; font-size: 14px;">
              Forgot Password?
            </a>
          </div>
          
          <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color);">
            <p style="color: var(--text-muted); font-size: 14px;">
              Don't have an account? 
              <a href="#" onclick="showSignup(); return false;" style="color: var(--accent-primary); text-decoration: none; font-weight: 600;">
                Sign Up
              </a>
            </p>
          </div>
        </div>
      </div>
    </div>
  `);

  document.getElementById('login-form').addEventListener('submit', handleLogin);
}

async function handleLogin(e) {
  e.preventDefault();

  const username = document.getElementById('username').value;
  const password = document.getElementById('password').value;

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'VERIFYING...';

  try {
    const data = await login(username, password);
    showToast('Password verified! Sending OTP...', 'success');

    // Send OTP
    await sendOTP(data.phoneNumber);
    showToast(`OTP sent to ${data.phoneNumber}`, 'success');

    // Show OTP verification screen
    showOTPVerification(data.phoneNumber);
  } catch (error) {
    showToast(error.message, 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'PROCEED TO OTP VERIFICATION';
  }
}

function showOTPVerification(phoneNumber) {
  render(`
    <div class="login-container">
      <div class="login-box">
        <div class="login-header">
          <div class="logo-icon" style="margin: 0 auto 20px; width: 80px; height: 80px; font-size: 40px;">
            📱
          </div>
          <h1>VERIFY OTP</h1>
          <p>Enter the 6-digit code sent to ${phoneNumber}</p>
        </div>
        
        <div class="card">
          <form id="otp-form">
            <div class="form-group">
              <label class="form-label">OTP CODE</label>
              <input 
                type="text" 
                class="form-input" 
                id="otp-code" 
                required 
                maxlength="6"
                pattern="[0-9]{6}"
                placeholder="000000"
                style="font-family: var(--font-mono); font-size: 24px; text-align: center; letter-spacing: 8px;"
              >
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
              VERIFY & LOGIN
            </button>
            
            <button type="button" class="btn btn-secondary" style="width: 100%; margin-top: 12px;" onclick="showLogin()">
              BACK TO LOGIN
            </button>
          </form>
        </div>
      </div>
    </div>
  `);

  document.getElementById('otp-form').addEventListener('submit', async (e) => {
    e.preventDefault();

    const otpCode = document.getElementById('otp-code').value;
    const submitBtn = e.target.querySelector('button[type="submit"]');
    submitBtn.disabled = true;
    submitBtn.textContent = 'VERIFYING...';

    try {
      await verifyOTP(phoneNumber, otpCode);
      showToast('Login successful!', 'success');
      showDashboard();
    } catch (error) {
      showToast(error.message, 'error');
      submitBtn.disabled = false;
      submitBtn.textContent = 'VERIFY & LOGIN';
    }
  });
}

function showDashboard() {
  currentView = 'dashboard';

  const header = `
    <div class="header">
      <div class="header-content">
        <div class="logo">
          <div class="logo-icon">🔒</div>
          <div class="logo-text">
            <h1>SECURE EXAM PAPER UPLOAD PORTAL</h1>
            <p>AES-256 | RSA-2048 | SHA-256</p>
          </div>
        </div>
        
        <div class="user-info">
          <div class="user-badge">
            <span>${currentUser.username}</span>
            <span class="role-badge ${currentUser.role}">${currentUser.role}</span>
          </div>
          <button class="btn btn-secondary" onclick="logout()">LOGOUT</button>
        </div>
      </div>
    </div>
  `;

  let content = '';

  if (currentUser.role === 'admin') {
    content = getAdminDashboard();
  } else if (currentUser.role === 'controller') {
    content = getControllerDashboard();
  } else if (currentUser.role === 'faculty') {
    content = getFacultyDashboard();
  }

  render(header + content);
}

//admin dashboard
function getAdminDashboard() {
  loadUsers();
  loadAuditLogs();

  return `
    <div class="container dashboard">
      <div class="dashboard-header">
        <h2>Admin Dashboard</h2>
        <p>User management and system oversight</p>
      </div>
      
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">User Management</h3>
          <button class="btn btn-primary" onclick="showCreateUserModal()">
            ➕ CREATE USER
          </button>
        </div>
        <div id="users-list">Loading...</div>
      </div>
      
      <div class="card mt-20">
        <div class="card-header">
          <h3 class="card-title">Audit Logs</h3>
        </div>
        <div id="audit-logs">Loading...</div>
      </div>
    </div>
  `;
}

async function loadUsers() {
  try {
    const response = await fetch('/api/users', { credentials: 'include' });
    const data = await response.json();

    const html = `
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Phone Number</th>
              <th>Role</th>
              <th>Created At</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${data.users.map(user => `
              <tr>
                <td>${user.id}</td>
                <td>${user.username}</td>
                <td>${user.phone_number}</td>
                <td><span class="role-badge ${user.role}">${user.role}</span></td>
                <td>${new Date(user.created_at).toLocaleString()}</td>
                <td>
                  <button class="btn btn-danger" onclick="deleteUser(${user.id})" style="padding: 6px 12px; font-size: 12px;">
                    DELETE
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    document.getElementById('users-list').innerHTML = html;
  } catch (error) {
    showToast('Failed to load users', 'error');
  }
}

async function loadAuditLogs() {
  try {
    const response = await fetch('/api/audit-logs', { credentials: 'include' });
    const data = await response.json();

    const html = `
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>User</th>
              <th>Action</th>
              <th>Resource</th>
              <th>Details</th>
              <th>IP Address</th>
            </tr>
          </thead>
          <tbody>
            ${data.logs.map(log => `
              <tr>
                <td style="font-family: var(--font-mono); font-size: 12px;">${new Date(log.timestamp).toLocaleString()}</td>
                <td>${log.username}</td>
                <td><span class="status-badge encrypted">${log.action}</span></td>
                <td>${log.resource || '-'}</td>
                <td style="max-width: 300px; overflow: hidden; text-overflow: ellipsis;">${log.details || '-'}</td>
                <td style="font-family: var(--font-mono); font-size: 12px;">${log.ip_address}</td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    document.getElementById('audit-logs').innerHTML = html;
  } catch (error) {
    showToast('Failed to load audit logs', 'error');
  }
}

function showCreateUserModal() {
  const modal = `
    <div class="modal-overlay" onclick="closeModal(event)">
      <div class="modal" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3>Create New User</h3>
          <button class="btn btn-secondary" onclick="closeModal()" style="padding: 8px 16px;">✕</button>
        </div>
        <div class="modal-body">
          <form id="create-user-form">
            <div class="form-group">
              <label class="form-label">Username</label>
              <input type="text" class="form-input" id="new-username" required>
            </div>
            
            <div class="form-group">
              <label class="form-label">Password</label>
              <input type="password" class="form-input" id="new-password" required>
            </div>
            
            <div class="form-group">
              <label class="form-label">Phone Number</label>
              <input type="tel" class="form-input" id="new-phone" required placeholder="+919876543210">
            </div>
            
            <div class="form-group">
              <label class="form-label">Role</label>
              <select class="form-select" id="new-role" required>
                <option value="faculty">Faculty</option>
                <option value="controller">Exam Controller</option>
                <option value="admin">Admin</option>
              </select>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onclick="closeModal()">CANCEL</button>
          <button class="btn btn-primary" onclick="createUser()">CREATE USER</button>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modal);
}

async function createUser() {
  const username = document.getElementById('new-username').value;
  const password = document.getElementById('new-password').value;
  const phoneNumber = document.getElementById('new-phone').value;
  const role = document.getElementById('new-role').value;

  try {
    const response = await fetch('/api/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password, phoneNumber, role })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    showToast('User created successfully', 'success');
    closeModal();
    loadUsers();
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function deleteUser(userId) {
  if (!confirm('Are you sure you want to delete this user?')) {
    return;
  }

  try {
    const response = await fetch(`/api/users/${userId}`, {
      method: 'DELETE',
      credentials: 'include'
    });

    if (!response.ok) {
      throw new Error('Failed to delete user');
    }

    showToast('User deleted successfully', 'success');
    loadUsers();
  } catch (error) {
    showToast(error.message, 'error');
  }
}

//controller dashboard
function getControllerDashboard() {
  loadPapers();

  return `
    <div class="container dashboard">
      <div class="dashboard-header">
        <h2>Exam Controller Dashboard</h2>
        <p>Upload and release encrypted exam papers</p>
      </div>
      
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Exam Papers</h3>
          <button class="btn btn-primary" onclick="showUploadModal()">
            ⬆️ UPLOAD PAPER
          </button>
        </div>
        <div id="papers-list">Loading...</div>
      </div>
    </div>
  `;
}

async function loadPapers() {
  try {
    const response = await fetch('/api/papers', { credentials: 'include' });
    const data = await response.json();

    const html = `
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Title</th>
              <th>Subject</th>
              <th>Uploaded By</th>
              <th>Uploaded At</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${data.papers.map(paper => `
              <tr>
                <td>${paper.id}</td>
                <td>${paper.title}</td>
                <td>${paper.subject}</td>
                <td>${paper.uploaded_by_username}</td>
                <td style="font-family: var(--font-mono); font-size: 12px;">${new Date(paper.uploaded_at).toLocaleString()}</td>
                <td>
                  ${paper.is_released
        ? `<span class="status-badge released">RELEASED</span>`
        : `<span class="status-badge pending">PENDING</span>`
      }
                </td>
                <td>
                  ${!paper.is_released && currentUser.role === 'controller'
        ? `<button class="btn btn-primary" onclick="releasePaper(${paper.id}, event); return false;" style="padding: 6px 12px; font-size: 12px;">RELEASE</button>`
        : paper.is_released || currentUser.role === 'controller'
          ? `<button class="btn btn-secondary" onclick="downloadPaper(${paper.id})" style="padding: 6px 12px; font-size: 12px;">DOWNLOAD</button>`
          : '-'
      }
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;

    document.getElementById('papers-list').innerHTML = html;
  } catch (error) {
    showToast('Failed to load papers', 'error');
  }
}

function showUploadModal() {
  const modal = `
    <div class="modal-overlay" onclick="closeModal(event)">
      <div class="modal" onclick="event.stopPropagation()">
        <div class="modal-header">
          <h3>Upload Exam Paper</h3>
          <button class="btn btn-secondary" onclick="closeModal()" style="padding: 8px 16px;">✕</button>
        </div>
        <div class="modal-body">
          <form id="upload-form">
            <div class="form-group">
              <label class="form-label">Paper Title</label>
              <input type="text" class="form-input" id="paper-title" required placeholder="e.g., Final Exam 2026">
            </div>
            
            <div class="form-group">
              <label class="form-label">Subject</label>
              <input type="text" class="form-input" id="paper-subject" required placeholder="e.g., Computer Science">
            </div>
            
            <div class="form-group">
              <label class="form-label">Exam Paper File</label>
              <input type="file" class="form-input" id="paper-file" required accept=".pdf,.doc,.docx,.txt">
            </div>
            
            <div style="background: var(--bg-tertiary); padding: 16px; border-radius: 8px; margin-top: 16px;">
              <p style="font-size: 12px; color: var(--text-muted); margin-bottom: 8px;">
                🔐 Security Features Applied:
              </p>
              <ul style="font-size: 12px; color: var(--text-secondary); margin-left: 20px;">
                <li>AES-256-GCM encryption</li>
                <li>RSA-2048 key generation</li>
                <li>Digital signature</li>
                <li>Base64 encoding</li>
              </ul>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button class="btn btn-secondary" onclick="closeModal()">CANCEL</button>
          <button class="btn btn-primary" onclick="uploadPaper()">ENCRYPT & UPLOAD</button>
        </div>
      </div>
    </div>
  `;

  document.body.insertAdjacentHTML('beforeend', modal);
}

async function uploadPaper() {
  const title = document.getElementById('paper-title').value;
  const subject = document.getElementById('paper-subject').value;
  const fileInput = document.getElementById('paper-file');

  if (!fileInput.files[0]) {
    showToast('Please select a file', 'error');
    return;
  }

  const file = fileInput.files[0];

  // Read file as base64
  const reader = new FileReader();
  reader.onload = async (e) => {
    const base64Content = e.target.result.split(',')[1];

    try {
      const response = await fetch('/api/papers/upload', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({
          title,
          subject,
          fileContent: base64Content,
          filename: file.name
        })
      });

      const data = await response.json();

      if (!response.ok) {
        throw new Error(data.error);
      }

      showToast('Paper uploaded and encrypted successfully!', 'success');
      closeModal();
      loadPapers();
    } catch (error) {
      showToast(error.message, 'error');
    }
  };

  reader.readAsDataURL(file);
}

async function releasePaper(paperId, event) {
  // Prevent default action and event bubbling
  if (event) {
    event.preventDefault();
    event.stopPropagation();
  }

  try {
    // Fetch faculty list
    const response = await fetch('/api/faculty', { credentials: 'include' });
    const data = await response.json();

    if (!response.ok) {
      throw new Error('Failed to load faculty list');
    }

    const facultyList = data.faculty;

    // Create faculty selection modal
    const modal = `
      <div class="modal-overlay" id="release-confirm-modal">
        <div class="modal" onclick="event.stopPropagation()" style="max-width: 600px;">
          <div class="modal-header">
            <h3>Release Exam Paper</h3>
            <button class="btn btn-secondary" onclick="closeReleaseModal()" style="padding: 8px 16px;">✕</button>
          </div>
          <div class="modal-body">
            <p style="font-size: 14px; color: var(--text-muted); margin-bottom: 16px;">
              Select specific faculty members to release this paper to, or release to all faculty.
            </p>
            
            <div style="margin-bottom: 16px;">
              <button class="btn btn-secondary" onclick="toggleAllFaculty()" style="padding: 8px 16px; font-size: 13px;">
                SELECT ALL / DESELECT ALL
              </button>
            </div>
            
            <div style="max-height: 300px; overflow-y: auto; background: var(--bg-tertiary); padding: 16px; border-radius: 8px;">
              ${facultyList.length > 0 ? facultyList.map(faculty => `
                <div style="margin-bottom: 12px;">
                  <label style="display: flex; align-items: center; cursor: pointer;">
                    <input 
                      type="checkbox" 
                      class="faculty-checkbox" 
                      value="${faculty.id}"
                      style="margin-right: 12px; width: 18px; height: 18px; cursor: pointer;"
                    >
                    <div>
                      <div style="font-weight: 600; color: var(--text-primary);">${faculty.username}</div>
                      <div style="font-size: 12px; color: var(--text-muted);">${faculty.phone_number}</div>
                    </div>
                  </label>
                </div>
              `).join('') : '<p style="color: var(--text-muted);">No faculty members found</p>'}
            </div>
          </div>
          <div class="modal-footer">
            <button class="btn btn-secondary" onclick="closeReleaseModal()">CANCEL</button>
            <button class="btn btn-primary" onclick="confirmRelease(${paperId}, 'all')">RELEASE TO ALL</button>
            <button class="btn btn-primary" onclick="confirmRelease(${paperId}, 'selected')" style="background: var(--accent-secondary);">RELEASE TO SELECTED</button>
          </div>
        </div>
      </div>
    `;

    document.body.insertAdjacentHTML('beforeend', modal);
  } catch (error) {
    showToast(error.message, 'error');
  }
}

function toggleAllFaculty() {
  const checkboxes = document.querySelectorAll('.faculty-checkbox');
  const allChecked = Array.from(checkboxes).every(cb => cb.checked);

  checkboxes.forEach(cb => {
    cb.checked = !allChecked;
  });
}

function closeReleaseModal() {
  const modal = document.getElementById('release-confirm-modal');
  if (modal) {
    modal.remove();
  }
}

async function confirmRelease(paperId, releaseType) {
  // Get selected faculty IDs if releasing to selected
  let facultyIds = [];

  if (releaseType === 'selected') {
    const checkboxes = document.querySelectorAll('.faculty-checkbox:checked');
    facultyIds = Array.from(checkboxes).map(cb => parseInt(cb.value));

    if (facultyIds.length === 0) {
      showToast('Please select at least one faculty member', 'error');
      return;
    }
  }

  closeReleaseModal();

  try {
    const response = await fetch(`/api/papers/${paperId}/release`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ facultyIds: releaseType === 'all' ? [] : facultyIds })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    const message = releaseType === 'all'
      ? 'Paper released to all faculty!'
      : `Paper released to ${facultyIds.length} faculty member(s)!`;

    showToast(message, 'success');
    loadPapers();
  } catch (error) {
    showToast(error.message, 'error');
  }
}

async function downloadPaper(paperId) {
  try {
    showToast('Decrypting paper...', 'info');

    const response = await fetch(`/api/papers/${paperId}/download`, {
      credentials: 'include'
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    // Convert base64 to blob and download
    const byteCharacters = atob(data.fileContent);
    const byteNumbers = new Array(byteCharacters.length);
    for (let i = 0; i < byteCharacters.length; i++) {
      byteNumbers[i] = byteCharacters.charCodeAt(i);
    }
    const byteArray = new Uint8Array(byteNumbers);
    const blob = new Blob([byteArray]);

    const url = window.URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = data.filename;
    document.body.appendChild(a);
    a.click();
    window.URL.revokeObjectURL(url);
    document.body.removeChild(a);

    showToast('Paper downloaded successfully!', 'success');
  } catch (error) {
    showToast(error.message, 'error');
  }
}

//faculty dashboard
function getFacultyDashboard() {
  loadPapers();

  return `
    <div class="container dashboard">
      <div class="dashboard-header">
        <h2>Faculty Dashboard</h2>
        <p>View and download released exam papers</p>
      </div>
      
      <div class="card">
        <div class="card-header">
          <h3 class="card-title">Released Exam Papers</h3>
        </div>
        <div id="papers-list">Loading...</div>
      </div>
    </div>
  `;
}

//signup
function showSignup() {
  currentView = 'signup';
  render(`
    <div class="login-container">
      <div class="login-box">
        <div class="login-header">
          <div class="logo-icon" style="margin: 0 auto 20px; width: 80px; height: 80px; font-size: 40px;">
            📝
          </div>
          <h1>CREATE ACCOUNT</h1>
          <p>Register for Secure Exam Paper Upload Portal access</p>
        </div>
        
        <div class="card">
          <form id="signup-form">
            <div class="form-group">
              <label class="form-label">USERNAME</label>
              <input type="text" class="form-input" id="signup-username" required autocomplete="username">
            </div>
            
            <div class="form-group">
              <label class="form-label">PASSWORD</label>
              <input type="password" class="form-input" id="signup-password" required autocomplete="new-password" minlength="6">
              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Minimum 6 characters</p>
            </div>
            
            <div class="form-group">
              <label class="form-label">PHONE NUMBER</label>
              <input type="tel" class="form-input" id="signup-phone" required placeholder="+919876543210">
              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Include country code (e.g., +91)</p>
            </div>
            
            <div class="form-group">
              <label class="form-label">ROLE</label>
              <select class="form-select" id="signup-role" required>
                <option value="">Select your role</option>
                <option value="faculty">Faculty</option>
                <option value="controller">Exam Controller</option>
              </select>
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
              CREATE ACCOUNT
            </button>
            
            <div style="text-align: center; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-color);">
              <p style="color: var(--text-muted); font-size: 14px;">
                Already have an account? 
                <a href="#" onclick="showLogin(); return false;" style="color: var(--accent-primary); text-decoration: none; font-weight: 600;">
                  Login
                </a>
              </p>
            </div>
          </form>
        </div>
      </div>
    </div>
  `);

  document.getElementById('signup-form').addEventListener('submit', handleSignup);
}

async function handleSignup(e) {
  e.preventDefault();

  const username = document.getElementById('signup-username').value;
  const password = document.getElementById('signup-password').value;
  const phoneNumber = document.getElementById('signup-phone').value;
  const role = document.getElementById('signup-role').value;

  if (!role) {
    showToast('Please select a role', 'error');
    return;
  }

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'CREATING ACCOUNT...';

  try {
    const response = await fetch('/api/auth/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, password, phoneNumber, role })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    showToast('Account created successfully! Please login.', 'success');
    setTimeout(() => showLogin(), 2000);
  } catch (error) {
    showToast(error.message, 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'CREATE ACCOUNT';
  }
}

//forgot password
function showForgotPassword() {
  currentView = 'forgot-password';
  render(`
    <div class="login-container">
      <div class="login-box">
        <div class="login-header">
          <div class="logo-icon" style="margin: 0 auto 20px; width: 80px; height: 80px; font-size: 40px;">
            🔑
          </div>
          <h1>RESET PASSWORD</h1>
          <p>Enter your username to receive an OTP</p>
        </div>
        
        <div class="card">
          <form id="forgot-password-form">
            <div class="form-group">
              <label class="form-label">USERNAME</label>
              <input type="text" class="form-input" id="forgot-username" required autocomplete="username">
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
              SEND OTP
            </button>
            
            <button type="button" class="btn btn-secondary" style="width: 100%; margin-top: 12px;" onclick="showLogin()">
              BACK TO LOGIN
            </button>
          </form>
        </div>
      </div>
    </div>
  `);

  document.getElementById('forgot-password-form').addEventListener('submit', handleForgotPasswordInitiate);
}

async function handleForgotPasswordInitiate(e) {
  e.preventDefault();

  const username = document.getElementById('forgot-username').value;

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'SENDING OTP...';

  try {
    const response = await fetch('/api/auth/forgot-password/initiate', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    showToast(data.message, 'success');

    // Show OTP verification and new password screen
    showForgotPasswordVerify(username, data.phoneNumber);
  } catch (error) {
    showToast(error.message, 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'SEND OTP';
  }
}

function showForgotPasswordVerify(username, phoneNumber) {
  render(`
    <div class="login-container">
      <div class="login-box">
        <div class="login-header">
          <div class="logo-icon" style="margin: 0 auto 20px; width: 80px; height: 80px; font-size: 40px;">
            🔐
          </div>
          <h1>VERIFY & RESET</h1>
          <p>Enter OTP sent to ${phoneNumber}</p>
        </div>
        
        <div class="card">
          <form id="verify-reset-form">
            <input type="hidden" id="reset-username" value="${username}">
            
            <div class="form-group">
              <label class="form-label">OTP CODE</label>
              <input 
                type="text" 
                class="form-input" 
                id="reset-otp" 
                required 
                maxlength="6"
                pattern="[0-9]{6}"
                placeholder="000000"
                style="font-family: var(--font-mono); font-size: 24px; text-align: center; letter-spacing: 8px;"
              >
            </div>
            
            <div class="form-group">
              <label class="form-label">NEW PASSWORD</label>
              <input type="password" class="form-input" id="reset-password" required minlength="6" autocomplete="new-password">
              <p style="font-size: 12px; color: var(--text-muted); margin-top: 4px;">Minimum 6 characters</p>
            </div>
            
            <div class="form-group">
              <label class="form-label">CONFIRM PASSWORD</label>
              <input type="password" class="form-input" id="reset-password-confirm" required minlength="6" autocomplete="new-password">
            </div>
            
            <button type="submit" class="btn btn-primary" style="width: 100%;">
              RESET PASSWORD
            </button>
            
            <button type="button" class="btn btn-secondary" style="width: 100%; margin-top: 12px;" onclick="showLogin()">
              BACK TO LOGIN
            </button>
          </form>
        </div>
      </div>
    </div>
  `);

  document.getElementById('verify-reset-form').addEventListener('submit', handleForgotPasswordReset);
}

async function handleForgotPasswordReset(e) {
  e.preventDefault();

  const username = document.getElementById('reset-username').value;
  const otpCode = document.getElementById('reset-otp').value;
  const newPassword = document.getElementById('reset-password').value;
  const confirmPassword = document.getElementById('reset-password-confirm').value;

  if (newPassword !== confirmPassword) {
    showToast('Passwords do not match', 'error');
    return;
  }

  const submitBtn = e.target.querySelector('button[type="submit"]');
  submitBtn.disabled = true;
  submitBtn.textContent = 'RESETTING...';

  try {
    const response = await fetch('/api/auth/forgot-password/verify', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify({ username, otpCode, newPassword })
    });

    const data = await response.json();

    if (!response.ok) {
      throw new Error(data.error);
    }

    showToast('Password reset successfully! Redirecting to login...', 'success');
    setTimeout(() => showLogin(), 2000);
  } catch (error) {
    showToast(error.message, 'error');
    submitBtn.disabled = false;
    submitBtn.textContent = 'RESET PASSWORD';
  }
}


function showToast(message, type = 'info') {
  const toast = document.createElement('div');
  toast.className = `toast ${type}`;
  toast.innerHTML = `
    <span style="font-size: 20px;">
      ${type === 'success' ? '✓' : type === 'error' ? '✕' : 'ℹ'}
    </span>
    <span>${message}</span>
  `;

  document.getElementById('toast-container').appendChild(toast);

  setTimeout(() => {
    toast.style.animation = 'slideIn 0.3s ease reverse';
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

function closeModal(event) {
  if (event && event.target.className !== 'modal-overlay') {
    return;
  }

  const modal = document.querySelector('.modal-overlay');
  if (modal) {
    modal.remove();
  }
}

// Make functions globally available
window.logout = logout;
window.showLogin = showLogin;
window.showSignup = showSignup;
window.showForgotPassword = showForgotPassword;
window.showCreateUserModal = showCreateUserModal;
window.createUser = createUser;
window.deleteUser = deleteUser;
window.showUploadModal = showUploadModal;
window.uploadPaper = uploadPaper;
window.releasePaper = releasePaper;
window.downloadPaper = downloadPaper;
window.closeModal = closeModal;
window.closeReleaseModal = closeReleaseModal;
window.confirmRelease = confirmRelease;
window.toggleAllFaculty = toggleAllFaculty;
