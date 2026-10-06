/**
 * DOCUMENT GUARDIAN - Main Web Application Controller
 * Complete feature parity with desktop app:
 * - PBKDF2/AES-GCM Envelope Encryption & DEK Lifecycle
 * - Multi-account registration with live password strength meter
 * - Login with 5-attempt brute-force lockout and live countdown
 * - Session manager with inactivity auto-lock and live header countdown
 * - Holographic 3D Smart Cards (Passport, Aadhaar, PAN) with pointer tilt physics
 * - Dual view modes: Holographic Smart Cards <-> Detailed Data Table
 * - Real-time filtering, search, and dynamic legal validation
 * - Reminders engine with urgency radar
 * - Encrypted file vault with magic bytes validation and client-side encryption
 * - Settings with live DEK re-wrapping, CSV export, and encrypted JSON backup/restore
 */

// Global Application State
let currentActiveView = 'dashboard';
let currentFilterType = 'All';
let currentFilterStatus = 'All';
let currentSearchQuery = '';
let currentViewMode = 'cards'; // 'cards' or 'table'
let inactivityInterval = null;
let lockoutInterval = null;

// Initialize upon DOM readiness
document.addEventListener('DOMContentLoaded', async () => {
  initTheme();
  initGlobalActivityMonitors();
  initViewTabs();
  initAuthHandlers();
  initDocumentModals();
  initFileVaultDropzone();
  initSettingsHandlers();

  // Check initial authentication
  updateAppSessionState();

  // Start periodic 1-second timer loop for idle countdown & lockout countdown
  startPeriodicTimerLoop();
});

// ==============================================================================
// 1. Theme Management (Executive Dark / Crisp Light)
// ==============================================================================

function initTheme() {
  const savedTheme = localStorage.getItem('docguardian_theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  updateThemeIcon(savedTheme);

  const themeBtn = document.getElementById('themeToggleBtn');
  if (themeBtn) {
    themeBtn.addEventListener('click', () => {
      const current = document.documentElement.getAttribute('data-theme');
      const next = current === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', next);
      localStorage.setItem('docguardian_theme', next);
      updateThemeIcon(next);
      showToast(`Switched to ${next === 'dark' ? 'Cyber Dark' : 'Crisp Light'} mode`, 'info');
    });
  }
}

function updateThemeIcon(theme) {
  const icon = document.getElementById('themeIcon');
  if (icon) {
    icon.textContent = theme === 'dark' ? '☀️' : '🌙';
  }
}

// ==============================================================================
// 2. Global Activity Monitoring & Inactivity Auto-Lock Loop
// ==============================================================================

function initGlobalActivityMonitors() {
  const resetActivity = () => {
    if (window.storageService) {
      window.storageService.recordActivity();
    }
  };

  window.addEventListener('mousemove', resetActivity, { passive: true });
  window.addEventListener('keydown', resetActivity, { passive: true });
  window.addEventListener('click', resetActivity, { passive: true });
  window.addEventListener('scroll', resetActivity, { passive: true });
}

function startPeriodicTimerLoop() {
  if (inactivityInterval) clearInterval(inactivityInterval);

  inactivityInterval = setInterval(() => {
    // 1. Check Inactivity Timeout
    if (window.storageService && window.storageService.isAuthenticated()) {
      const isNowLocked = window.storageService.checkInactivity();
      if (isNowLocked) {
        showToast("Session locked due to inactivity.", "warning");
        updateAppSessionState();
        return;
      }

      // Update Header Countdown Badge
      const remSec = window.storageService.getRemainingInactivitySeconds();
      const mins = Math.floor(remSec / 60);
      const secs = remSec % 60;
      const timerEl = document.getElementById('navIdleTimer');
      if (timerEl) {
        timerEl.textContent = `⏱️ ${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
        timerEl.classList.toggle('urgent', remSec <= 120);
      }
    }

    // 2. Check Lockout Countdown on Auth Screen if user was locked
    const lockoutAlert = document.getElementById('authLockoutAlert');
    const lockoutMsg = document.getElementById('authLockoutMsg');
    if (lockoutAlert && lockoutAlert.style.display !== 'none') {
      const users = window.storageService ? window.storageService.getUsers() : [];
      const lockedUser = users.find(u => u.lockedUntil && Date.now() < u.lockedUntil);
      if (lockedUser) {
        const waitSec = Math.ceil((lockedUser.lockedUntil - Date.now()) / 1000);
        const lm = Math.floor(waitSec / 60);
        const ls = waitSec % 60;
        lockoutMsg.textContent = `Account temporarily locked due to 5 failed attempts. Retry in ${lm}m ${ls}s.`;
      } else {
        lockoutAlert.style.display = 'none';
      }
    }
  }, 1000);
}

// ==============================================================================
// 3. Navigation & Session UI State Synchronizer
// ==============================================================================

function updateAppSessionState() {
  const isAuth = window.storageService && window.storageService.isAuthenticated();
  const isLocked = window.storageService && window.storageService.session.isLocked;
  const currentUser = window.storageService ? window.storageService.session.user : null;

  const authView = document.getElementById('view-auth');
  const lockOverlay = document.getElementById('lockScreenOverlay');
  const mainNavTabs = document.getElementById('mainNavTabs');
  const navIdleTimer = document.getElementById('navIdleTimer');
  const navUserBadge = document.getElementById('navUserBadge');
  const navUsername = document.getElementById('navUsername');
  const navLockBtn = document.getElementById('navLockBtn');
  const navLogoutBtn = document.getElementById('navLogoutBtn');

  if (isLocked) {
    lockOverlay.style.display = 'flex';
  } else {
    lockOverlay.style.display = 'none';
  }

  if (isAuth) {
    authView.style.display = 'none';
    mainNavTabs.style.display = 'flex';
    navIdleTimer.style.display = 'inline-flex';
    navUserBadge.style.display = 'inline-flex';
    navUsername.textContent = currentUser ? currentUser.username : 'User';
    navLockBtn.style.display = 'inline-flex';
    navLogoutBtn.style.display = 'inline-flex';

    // Refresh active view
    switchAppView(currentActiveView);
  } else if (!isLocked) {
    // Show Auth Screen
    authView.style.display = 'block';
    mainNavTabs.style.display = 'none';
    navIdleTimer.style.display = 'none';
    navUserBadge.style.display = 'none';
    navLockBtn.style.display = 'none';
    navLogoutBtn.style.display = 'none';

    // Hide all internal app views
    document.querySelectorAll('.app-section:not(#view-auth)').forEach(sec => sec.style.display = 'none');
  }
}

function initViewTabs() {
  document.querySelectorAll('#mainNavTabs .tab-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const view = btn.getAttribute('data-view');
      switchAppView(view);
    });
  });

  // Top Nav Brand Click -> Return to Dashboard
  const brandLogo = document.getElementById('navBrandLogo');
  if (brandLogo) {
    brandLogo.addEventListener('click', (e) => {
      e.preventDefault();
      if (window.storageService && window.storageService.isAuthenticated()) {
        switchAppView('dashboard');
      }
    });
  }

  // Quick Lock Button
  const navLockBtn = document.getElementById('navLockBtn');
  if (navLockBtn) {
    navLockBtn.addEventListener('click', () => {
      if (window.storageService) {
        window.storageService.lockSession('User manual lock');
        showToast('Vault locked. Keys wiped from memory.', 'info');
        updateAppSessionState();
      }
    });
  }

  // Logout Button
  const navLogoutBtn = document.getElementById('navLogoutBtn');
  if (navLogoutBtn) {
    navLogoutBtn.addEventListener('click', () => {
      if (window.storageService) {
        window.storageService.logout();
        showToast('Signed out of vault.', 'info');
        updateAppSessionState();
      }
    });
  }
}

function switchAppView(viewName) {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;

  currentActiveView = viewName;

  // Update tab styles
  document.querySelectorAll('#mainNavTabs .tab-btn').forEach(btn => {
    btn.classList.toggle('active', btn.getAttribute('data-view') === viewName);
  });

  // Hide all sections then show target
  document.querySelectorAll('.app-section').forEach(sec => sec.style.display = 'none');
  const targetSection = document.getElementById(`view-${viewName}`);
  if (targetSection) {
    targetSection.style.display = 'block';
  }

  // Trigger view renderers
  if (viewName === 'dashboard') renderDashboard();
  else if (viewName === 'documents') renderDocumentsView();
  else if (viewName === 'reminders') renderRemindersView();
  else if (viewName === 'vault') renderVaultFilesView();
  else if (viewName === 'audit') renderAuditTrailView();
  else if (viewName === 'settings') renderSettingsView();

  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// ==============================================================================
// 4. Authentication Subsystem (Registration, Login, Lockout)
// ==============================================================================

function initAuthHandlers() {
  const tabSignIn = document.getElementById('tabBtnSignIn');
  const tabRegister = document.getElementById('tabBtnRegister');
  const formSignIn = document.getElementById('signInForm');
  const formRegister = document.getElementById('registerForm');

  tabSignIn.addEventListener('click', () => {
    tabSignIn.classList.add('active');
    tabRegister.classList.remove('active');
    formSignIn.style.display = 'block';
    formRegister.style.display = 'none';
  });

  tabRegister.addEventListener('click', () => {
    tabRegister.classList.add('active');
    tabSignIn.classList.remove('active');
    formRegister.style.display = 'block';
    formSignIn.style.display = 'none';
  });

  // Show / Hide Password Toggles
  setupPasswordVisibilityToggle('toggleLoginPwdVisibility', 'loginPassword');
  setupPasswordVisibilityToggle('toggleRegPwdVisibility', 'regPassword');

  // Interactive Password Strength Meter
  const regPwdInput = document.getElementById('regPassword');
  regPwdInput.addEventListener('input', () => {
    updatePasswordStrengthMeter(regPwdInput.value);
  });


  // Sign In Form Submit
  formSignIn.addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = document.getElementById('loginUsername').value;
    const pwd = document.getElementById('loginPassword').value;

    try {
      await window.storageService.loginUser(user, pwd);
      showToast(`Welcome back, ${user}!`, 'success');
      document.getElementById('loginPassword').value = '';
      updateAppSessionState();
    } catch (err) {
      showToast(err.message, 'error');
      // If error mentions lockout, show alert
      if (err.message.includes('locked')) {
        const lockoutAlert = document.getElementById('authLockoutAlert');
        const lockoutMsg = document.getElementById('authLockoutMsg');
        lockoutAlert.style.display = 'flex';
        lockoutMsg.textContent = err.message;
      }
    }
  });

  // Register Form Submit
  formRegister.addEventListener('submit', async (e) => {
    e.preventDefault();
    const user = document.getElementById('regUsername').value;
    const pwd = document.getElementById('regPassword').value;
    const confirm = document.getElementById('regConfirmPassword').value;

    try {
      await window.storageService.registerUser(user, pwd, confirm);
      showToast('Vault account created and encryption key initialized!', 'success');
      formRegister.reset();
      updateAppSessionState();
    } catch (err) {
      showToast(err.message, 'error');
    }
  });

  // Lock Screen Overlay Unlock Form
  const overlayUnlockForm = document.getElementById('overlayUnlockForm');
  overlayUnlockForm.addEventListener('submit', async (e) => {
    e.preventDefault();
    const pwd = document.getElementById('overlayUnlockPassword').value;
    const res = await window.storageService.unlockSession(pwd);
    if (res.success) {
      document.getElementById('overlayUnlockPassword').value = '';
      showToast('Vault unlocked successfully!', 'success');
      updateAppSessionState();
    } else {
      showToast(res.message, 'error');
    }
  });
}

function handleLockSignOut() {
  if (window.storageService) {
    window.storageService.logout();
    document.getElementById('overlayUnlockPassword').value = '';
    showToast('Signed out of vault session.', 'info');
    updateAppSessionState();
  }
}

function setupPasswordVisibilityToggle(btnId, inputId) {
  const btn = document.getElementById(btnId);
  const input = document.getElementById(inputId);
  if (!btn || !input) return;

  btn.addEventListener('click', () => {
    const isShowing = input.type === 'text';
    input.type = isShowing ? 'password' : 'text';
    btn.textContent = isShowing ? 'Show' : 'Hide';
  });
}

function updatePasswordStrengthMeter(pwd) {
  const fill = document.getElementById('strengthBarFill');
  const label = document.getElementById('strengthLabel');
  if (!fill || !label) return;

  if (!pwd) {
    fill.style.width = '0%';
    fill.style.backgroundColor = 'transparent';
    label.textContent = 'Password requirements: Min 10 chars, uppercase, lowercase, number, symbol';
    label.style.color = 'var(--text-muted)';
    return;
  }

  let score = 0;
  if (pwd.length >= 10) score++;
  if (/[A-Z]/.test(pwd)) score++;
  if (/[a-z]/.test(pwd)) score++;
  if (/[0-9]/.test(pwd)) score++;
  if (/[^A-Za-z0-9]/.test(pwd)) score++;

  const pct = (score / 5) * 100;
  fill.style.width = `${pct}%`;

  if (score <= 2) {
    fill.style.backgroundColor = 'var(--brand-crimson)';
    label.textContent = `Strength: Weak (${score}/5 criteria met)`;
    label.style.color = 'var(--brand-crimson)';
  } else if (score <= 4) {
    fill.style.backgroundColor = 'var(--brand-amber)';
    label.textContent = `Strength: Moderate (${score}/5 criteria met)`;
    label.style.color = 'var(--brand-amber)';
  } else {
    fill.style.backgroundColor = 'var(--brand-emerald)';
    label.textContent = 'Strength: Strong! Meets all cybersecurity requirements.';
    label.style.color = 'var(--brand-emerald)';
  }
}

// ==============================================================================
// 5. Dashboard View Subsystem
// ==============================================================================

function renderDashboard() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const docs = window.storageService.getDocuments(userId);

  let total = docs.length;
  let validCount = 0;
  let attentionCount = 0;
  let reviewCount = 0;
  let expiredCount = 0;

  const urgentDocs = [];

  docs.forEach(doc => {
    const analysis = analyzeDocumentStatus(doc);
    if (analysis.status === DocumentStatus.VALID) validCount++;
    else if (analysis.status === DocumentStatus.ATTENTION_REQUIRED) {
      attentionCount++;
      urgentDocs.push({ doc, analysis });
    } else if (analysis.status === DocumentStatus.REVIEW_DUE) {
      reviewCount++;
      urgentDocs.push({ doc, analysis });
    } else if (analysis.status === DocumentStatus.EXPIRED) {
      expiredCount++;
      urgentDocs.push({ doc, analysis });
    }
  });

  // Sort urgent docs: Expired -> Review Due -> Attention Required
  urgentDocs.sort((a, b) => {
    const order = { 'Expired': 1, 'Review Due': 2, 'Attention Required': 3 };
    return (order[a.analysis.status] || 99) - (order[b.analysis.status] || 99);
  });

  // Update KPI Tiles
  document.getElementById('kpiDashTotal').textContent = total;
  document.getElementById('kpiDashValid').textContent = validCount;
  document.getElementById('kpiDashAttention').textContent = attentionCount;
  document.getElementById('kpiDashReview').textContent = reviewCount;
  document.getElementById('kpiDashExpired').textContent = expiredCount;

  // Render Urgent Attention Table
  const tableBody = document.getElementById('urgentAttentionTableBody');
  tableBody.innerHTML = '';

  if (urgentDocs.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="6" style="text-align: center; padding: 28px; color: var(--text-muted);">
          ✨ All personal identity documents are currently up-to-date. Zero actions required!
        </td>
      </tr>
    `;
    return;
  }

  urgentDocs.forEach(({ doc, analysis }) => {
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${getDocumentIcon(doc.document_type)} ${doc.document_type}</strong></td>
      <td><code>${doc.document_number_masked}</code></td>
      <td>${doc.expiry_date || doc.reminder_date || '—'}</td>
      <td><span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.displayText}</span></td>
      <td style="color: var(--text-secondary); font-size: 0.82rem;">${doc.notes || 'No description provided'}</td>
      <td style="text-align: right;">
        <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">View / Decrypt</button>
        <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">Update</button>
      </td>
    `;
    tableBody.appendChild(tr);
  });
}

function navigateToDocumentsFilter(type, status) {
  currentFilterType = type;
  currentFilterStatus = status;
  const typeSelect = document.getElementById('filterDocType');
  const statusSelect = document.getElementById('filterDocStatus');
  if (typeSelect) typeSelect.value = type;
  if (statusSelect) statusSelect.value = status;
  switchAppView('documents');
}

// ==============================================================================
// 6. My Documents View Subsystem (3D Smart Cards & Table View)
// ==============================================================================

function renderDocumentsView() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const allDocs = window.storageService.getDocuments(userId);

  // Apply filters
  const filtered = allDocs.filter(doc => {
    // Type Filter
    if (currentFilterType !== 'All' && doc.document_type !== currentFilterType) return false;

    // Status Filter
    const analysis = analyzeDocumentStatus(doc);
    if (currentFilterStatus !== 'All' && analysis.status !== currentFilterStatus) return false;

    // Search Query Filter
    if (currentSearchQuery) {
      const q = currentSearchQuery.toLowerCase();
      const matchType = doc.document_type.toLowerCase().includes(q);
      const matchMasked = doc.document_number_masked.toLowerCase().includes(q);
      const matchNotes = (doc.notes || '').toLowerCase().includes(q);
      if (!matchType && !matchMasked && !matchNotes) return false;
    }

    return true;
  });

  // Render Mode A: 3D Holographic Smart Cards
  renderSmartCards(filtered);

  // Render Mode B: Detailed Table
  renderDocumentsTable(filtered);
}

function renderSmartCards(docs) {
  const container = document.getElementById('smartCardsGrid');
  container.innerHTML = '';

  if (docs.length === 0) {
    container.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 60px 20px; color: var(--text-muted); background: var(--bg-card); border-radius: 16px; border: 1px dashed var(--border-medium);">
        <div style="font-size: 2.5rem; margin-bottom: 12px;">📁</div>
        <h3>No documents found</h3>
        <p style="font-size: 0.88rem; margin-top: 6px;">Try adjusting your filters or click "+ Add Document" to register a new record.</p>
      </div>
    `;
    return;
  }

  docs.forEach(doc => {
    const analysis = analyzeDocumentStatus(doc);
    const cardEl = document.createElement('div');

    if (doc.document_type === DocumentType.PASSPORT) {
      cardEl.className = 'smart-card smart-card-passport';
      cardEl.innerHTML = `
        <div>
          <div class="card-top">
            <div class="passport-emblem-badge">
              <div class="passport-gold-seal">🏛️</div>
              <div class="passport-header-text">
                <h4>PASSPORT / PASSEPORT</h4>
                <span>REPUBLIC OF INDIA</span>
              </div>
            </div>
            <div class="biometric-chip" title="Biometric RFID Microchip"></div>
          </div>

          <div class="card-number">${doc.document_number_masked}</div>

          <div class="card-meta">
            <div>
              <div style="font-size: 0.68rem; color: #94A3B8;">ISSUE DATE</div>
              <div>${doc.issue_date || '—'}</div>
            </div>
            <div>
              <div style="font-size: 0.68rem; color: #94A3B8;">EXPIRY DATE</div>
              <div>${doc.expiry_date || '—'}</div>
            </div>
            <div>
              <div style="font-size: 0.68rem; color: #94A3B8;">STATUS</div>
              <span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.status}</span>
            </div>
          </div>

          <div class="mrz-strip">
            P&lt;IND<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<br>
            ${doc.document_number_masked}&lt;0IND${doc.expiry_date ? doc.expiry_date.replace(/-/g, '').slice(2) : '310101'}7M<<<<<<<<<<<<&lt;08
          </div>
        </div>

        <div class="card-quick-actions">
          <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">👁️ Decrypt</button>
          <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">✏️ Edit</button>
          <button class="btn-card-action" onclick="deleteDocumentRecord(${doc.document_id})" style="color: #F87171;">🗑️ Delete</button>
        </div>
      `;
    } else if (doc.document_type === DocumentType.AADHAAR) {
      cardEl.className = 'smart-card smart-card-aadhaar';
      cardEl.innerHTML = `
        <div class="aadhaar-ribbon"></div>
        <div>
          <div class="card-top">
            <div class="aadhaar-header-text">
              <h4>AADHAAR IDENTITY CARD</h4>
              <span>Statutory Personal Identity · Lifetime Validity</span>
            </div>
            <span class="lifetime-badge">✓ Lifetime</span>
          </div>

          <div class="card-mid-section">
            <div class="aadhaar-qr-box" title="Simulated 2D Identity QR Barcode">
              <svg viewBox="0 0 24 24" fill="none" stroke="#1E293B" stroke-width="2">
                <rect x="3" y="3" width="7" height="7"></rect>
                <rect x="14" y="3" width="7" height="7"></rect>
                <rect x="3" y="14" width="7" height="7"></rect>
                <rect x="15" y="15" width="5" height="5" fill="#1E293B"></rect>
              </svg>
            </div>
            <div>
              <div class="card-number">${doc.document_number_masked}</div>
              <div style="font-size: 0.76rem; color: var(--text-muted); margin-top: 4px;">
                ${doc.notes || 'Resident of Republic of India'}
              </div>
            </div>
          </div>

          <div class="card-meta">
            <div>
              <div style="font-size: 0.68rem; color: var(--text-muted);">PERIODIC REVIEW</div>
              <div>${doc.reminder_date || 'No review scheduled'}</div>
            </div>
            <div>
              <span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.displayText}</span>
            </div>
          </div>
        </div>

        <div class="card-quick-actions">
          <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">👁️ Decrypt</button>
          <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">✏️ Edit</button>
          <button class="btn-card-action" onclick="deleteDocumentRecord(${doc.document_id})" style="color: #F87171;">🗑️ Delete</button>
        </div>
      `;
    } else {
      // PAN Card
      cardEl.className = 'smart-card smart-card-pan';
      cardEl.innerHTML = `
        <div>
          <div class="card-top">
            <div class="pan-header-text">
              <h4>INCOME TAX DEPARTMENT</h4>
              <span>GOVT. OF INDIA · PERMANENT ACCOUNT CARD</span>
            </div>
            <div class="pan-hologram-square" title="Security Optical Hologram">🔒</div>
          </div>

          <div class="card-number">${doc.document_number_masked}</div>

          <div class="card-meta">
            <div>
              <div style="font-size: 0.68rem; color: #94A3B8;">LEGAL STATUS</div>
              <div style="color: var(--brand-emerald); font-weight: 600;">Permanent Lifetime</div>
            </div>
            <div>
              <div style="font-size: 0.68rem; color: #94A3B8;">REVIEW STATUS</div>
              <span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.displayText}</span>
            </div>
          </div>

          <div style="font-size: 0.74rem; color: #94A3B8; margin-top: 10px; font-style: italic;">
            ${doc.notes || 'Permanent Account Record - Sec 139A IT Act'}
          </div>
        </div>

        <div class="card-quick-actions">
          <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">👁️ Decrypt</button>
          <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">✏️ Edit</button>
          <button class="btn-card-action" onclick="deleteDocumentRecord(${doc.document_id})" style="color: #F87171;">🗑️ Delete</button>
        </div>
      `;
    }

    // Attach 3D interactive tilt physics
    attachCardTiltEffect(cardEl);

    container.appendChild(cardEl);
  });
}

function renderDocumentsTable(docs) {
  const tableBody = document.getElementById('documentsTableBody');
  tableBody.innerHTML = '';

  if (docs.length === 0) {
    tableBody.innerHTML = `
      <tr>
        <td colspan="7" style="text-align: center; padding: 24px; color: var(--text-muted);">
          No matching documents found.
        </td>
      </tr>
    `;
    return;
  }

  docs.forEach(doc => {
    const analysis = analyzeDocumentStatus(doc);
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td><strong>${getDocumentIcon(doc.document_type)} ${doc.document_type}</strong></td>
      <td><code>${doc.document_number_masked}</code></td>
      <td>${doc.issue_date || '—'}</td>
      <td>${doc.expiry_date || doc.reminder_date || 'Lifetime'}</td>
      <td><span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.status}</span></td>
      <td style="color: var(--text-secondary); font-size: 0.82rem;">${doc.notes || '—'}</td>
      <td style="text-align: right;">
        <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">Decrypt</button>
        <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">Edit</button>
        <button class="btn-card-action" onclick="deleteDocumentRecord(${doc.document_id})" style="color: #F87171;">Delete</button>
      </td>
    `;
    tableBody.appendChild(tr);
  });
}

function attachCardTiltEffect(card) {
  card.addEventListener('mousemove', (e) => {
    const rect = card.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    const centerX = rect.width / 2;
    const centerY = rect.height / 2;

    const rotateX = ((y - centerY) / centerY) * -10;
    const rotateY = ((x - centerX) / centerX) * 10;

    card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-6px)`;
  });

  card.addEventListener('mouseleave', () => {
    card.style.transform = 'perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0)';
  });
}

function getDocumentIcon(type) {
  if (type === DocumentType.PASSPORT) return '📘';
  if (type === DocumentType.AADHAAR) return '🪪';
  if (type === DocumentType.PAN) return '💳';
  return '📄';
}

// ==============================================================================
// 7. Reminders Subsystem View
// ==============================================================================

function renderRemindersView() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const docs = window.storageService.getDocuments(userId);

  const container = document.getElementById('remindersListContainer');
  container.innerHTML = '';

  const reminderItems = [];
  docs.forEach(doc => {
    const analysis = analyzeDocumentStatus(doc);
    if (analysis.status !== DocumentStatus.VALID || doc.expiry_date || doc.reminder_date) {
      reminderItems.push({ doc, analysis });
    }
  });

  // Sort by days remaining (lowest first, nulls at bottom)
  reminderItems.sort((a, b) => {
    const aDays = a.analysis.daysRemaining !== null ? a.analysis.daysRemaining : 9999;
    const bDays = b.analysis.daysRemaining !== null ? b.analysis.daysRemaining : 9999;
    return aDays - bDays;
  });

  if (reminderItems.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 60px 20px; color: var(--text-muted); background: var(--bg-card); border-radius: 16px;">
        <div style="font-size: 2.5rem; margin-bottom: 12px;">⏰</div>
        <h3>No Upcoming Reminders</h3>
        <p style="font-size: 0.88rem; margin-top: 6px;">All document milestones are clear. Set reminder thresholds when adding documents.</p>
      </div>
    `;
    return;
  }

  reminderItems.forEach(({ doc, analysis }) => {
    const card = document.createElement('div');
    const urgencyClass = analysis.status === DocumentStatus.EXPIRED ? 'urgent' :
                         analysis.status === DocumentStatus.ATTENTION_REQUIRED ? 'attention' : 'review';

    card.className = `reminder-card ${urgencyClass}`;
    card.innerHTML = `
      <div>
        <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 4px;">
          <h4 style="font-size: 1.05rem; margin: 0; color: var(--text-primary);">
            ${getDocumentIcon(doc.document_type)} ${doc.document_type} (${doc.document_number_masked})
          </h4>
          <span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.status}</span>
        </div>
        <div style="font-size: 0.84rem; color: var(--text-secondary);">
          Milestone Date: <strong>${doc.expiry_date || doc.reminder_date || 'Lifetime'}</strong>
          ${doc.notes ? ` · Note: ${doc.notes}` : ''}
        </div>
        <div style="font-size: 0.78rem; color: var(--brand-blue-light); margin-top: 4px;">
          ${analysis.displayText}
        </div>
      </div>

      <div style="display: flex; gap: 8px;">
        <button class="btn-card-action" onclick="openEditDocModal(${doc.document_id})">✏️ Update Milestone</button>
        <button class="btn-card-action" onclick="viewDocumentDecrypted(${doc.document_id})">👁️ Decrypt</button>
      </div>
    `;
    container.appendChild(card);
  });
}

// ==============================================================================
// 8. Encrypted File Vault View Subsystem
// ==============================================================================

function initFileVaultDropzone() {
  const dropzone = document.getElementById('fileDropzone');
  const fileInput = document.getElementById('vaultFileInput');
  if (!dropzone || !fileInput) return;

  ['dragenter', 'dragover'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.add('dragover');
    });
  });

  ['dragleave', 'drop'].forEach(eventName => {
    dropzone.addEventListener(eventName, (e) => {
      e.preventDefault();
      e.stopPropagation();
      dropzone.classList.remove('dragover');
    });
  });

  dropzone.addEventListener('drop', async (e) => {
    const files = e.dataTransfer.files;
    if (files && files.length > 0) {
      await handleVaultFilesUpload(files);
    }
  });

  fileInput.addEventListener('change', async () => {
    if (fileInput.files && fileInput.files.length > 0) {
      await handleVaultFilesUpload(fileInput.files);
      fileInput.value = '';
    }
  });
}

async function handleVaultFilesUpload(fileList) {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;

  for (let i = 0; i < fileList.length; i++) {
    const file = fileList[i];
    try {
      showToast(`Encrypting ${file.name} with AES-256-GCM...`, 'info');
      await window.storageService.encryptAndStoreVaultFile(userId, file);
      showToast(`Encrypted and saved ${file.name}!`, 'success');
    } catch (err) {
      showToast(`Error saving ${file.name}: ${err.message}`, 'error');
    }
  }

  renderVaultFilesView();
}

function renderVaultFilesView() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const files = window.storageService.getVaultFiles(userId);

  document.getElementById('vaultFileCount').textContent = files.length;
  const grid = document.getElementById('vaultFilesGrid');
  grid.innerHTML = '';

  if (files.length === 0) {
    grid.innerHTML = `
      <div style="grid-column: 1 / -1; text-align: center; padding: 40px; color: var(--text-muted); background: var(--bg-card); border-radius: 14px;">
        <div style="font-size: 2.2rem; margin-bottom: 8px;">🔐</div>
        <h4>No encrypted files in vault yet</h4>
        <p style="font-size: 0.82rem; margin-top: 4px;">Drag and drop PDFs or images above to protect them with zero-knowledge envelope encryption.</p>
      </div>
    `;
    return;
  }

  files.forEach(file => {
    const fileCard = document.createElement('div');
    fileCard.className = 'file-card';
    const isPdf = file.mime_type === 'application/pdf';
    const icon = isPdf ? '📄' : '🖼️';

    fileCard.innerHTML = `
      <div>
        <div class="file-header">
          <div class="file-icon">${icon}</div>
          <div>
            <div class="file-title">${file.file_name}</div>
            <div class="file-meta">
              ${(file.file_size / 1024).toFixed(1)} KB · Encrypted at Rest
            </div>
            <div style="font-size: 0.72rem; color: var(--brand-emerald); margin-top: 2px;">
              ✓ AES-256-GCM Authenticated
            </div>
          </div>
        </div>
      </div>

      <div class="file-actions">
        <button class="btn-card-action" onclick="downloadDecryptedVaultFile(${file.file_id})">📥 Download Decrypted</button>
        <button class="btn-card-action" onclick="deleteVaultFileRecord(${file.file_id})" style="color: #F87171;">🗑️ Delete</button>
      </div>
    `;
    grid.appendChild(fileCard);
  });
}

async function downloadDecryptedVaultFile(fileId) {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;

  try {
    showToast('Decrypting file with active session key...', 'info');
    const { blob, fileRecord } = await window.storageService.decryptVaultFile(fileId, userId);
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = fileRecord.file_name;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
    showToast('File decrypted and downloaded!', 'success');
  } catch (err) {
    showToast(`Decryption error: ${err.message}`, 'error');
  }
}

async function deleteVaultFileRecord(fileId) {
  if (!confirm("Are you sure you want to permanently delete this encrypted file?")) return;
  const userId = window.storageService.session.user.userId;
  await window.storageService.deleteVaultFile(fileId, userId);
  showToast("File deleted from vault.", "info");
  renderVaultFilesView();
}

// ==============================================================================
// 9. Audit Trail Subsystem View
// ==============================================================================

function renderAuditTrailView() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const logs = window.storageService.getAuditLogs(userId);

  const tbody = document.getElementById('auditTableBody');
  tbody.innerHTML = '';

  if (logs.length === 0) {
    tbody.innerHTML = `
      <tr>
        <td colspan="3" style="text-align: center; padding: 24px; color: var(--text-muted);">
          No audit logs recorded yet.
        </td>
      </tr>
    `;
    return;
  }

  logs.forEach(log => {
    const tr = document.createElement('tr');
    const timeFormatted = new Date(log.timestamp).toLocaleString();
    tr.innerHTML = `
      <td style="font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-muted);">${timeFormatted}</td>
      <td><span class="user-account-badge" style="padding: 2px 8px; font-size: 0.72rem;">${log.action}</span></td>
      <td style="color: var(--text-primary); font-size: 0.84rem;">${log.details}</td>
    `;
    tbody.appendChild(tr);
  });
}

function exportAuditLogCSV() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const logs = window.storageService.getAuditLogs(userId);

  const headers = ["Timestamp", "Action", "Details"];
  const rows = logs.map(l => [
    `"${l.timestamp}"`,
    `"${l.action}"`,
    `"${(l.details || '').replace(/"/g, '""')}"`
  ]);

  const csv = "\uFEFF" + [headers.join(","), ...rows.map(r => r.join(","))].join("\r\n");
  downloadBlob(new Blob([csv], { type: "text/csv;charset=utf-8;" }), `DocumentGuardian_Audit_${Date.now()}.csv`);
  showToast("Audit logs exported to CSV.", "success");
}

// ==============================================================================
// 10. Settings & Vault Management Subsystem
// ==============================================================================

function initSettingsHandlers() {
  // Master Password Change Form
  const formChangePwd = document.getElementById('changePasswordForm');
  if (formChangePwd) {
    formChangePwd.addEventListener('submit', async (e) => {
      e.preventDefault();
      const curr = document.getElementById('currMasterPwd').value;
      const next = document.getElementById('newMasterPwd').value;
      const conf = document.getElementById('confirmNewMasterPwd').value;

      try {
        await window.storageService.changeMasterPassword(curr, next, conf);
        showToast("Master password updated! Vault DEK re-wrapped successfully.", "success");
        formChangePwd.reset();
      } catch (err) {
        showToast(err.message, "error");
      }
    });
  }

  // Inactivity Timeout Slider
  const slider = document.getElementById('timeoutSlider');
  const badge = document.getElementById('sliderValBadge');
  if (slider && badge) {
    slider.addEventListener('input', () => {
      badge.textContent = `${slider.value} min`;
    });
    slider.addEventListener('change', () => {
      window.storageService.setTimeoutMinutes(slider.value);
      showToast(`Inactivity timeout set to ${slider.value} minutes.`, "info");
    });
  }
}

function renderSettingsView() {
  if (!window.storageService) return;
  const settings = window.storageService.getSettings();
  const slider = document.getElementById('timeoutSlider');
  const badge = document.getElementById('sliderValBadge');
  if (slider && badge) {
    slider.value = settings.timeoutMinutes || 15;
    badge.textContent = `${slider.value} min`;
  }
}

async function exportRegistryCSV() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;

  try {
    showToast("Decrypting records for CSV export...", "info");
    const csvStr = await window.storageService.exportDecryptedCSV(userId);
    downloadBlob(new Blob([csvStr], { type: "text/csv;charset=utf-8;" }), `DocumentGuardian_Registry_${Date.now()}.csv`);
    showToast("Decrypted Document Registry exported to CSV!", "success");
  } catch (err) {
    showToast(`Export failed: ${err.message}`, "error");
  }
}

function downloadEncryptedBackup() {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;

  try {
    const jsonStr = window.storageService.exportEncryptedJSONBackup(userId);
    downloadBlob(new Blob([jsonStr], { type: "application/json;charset=utf-8;" }), `DocumentGuardian_VaultBackup_${Date.now()}.json`);
    showToast("Encrypted zero-knowledge vault backup exported!", "success");
  } catch (err) {
    showToast(`Backup error: ${err.message}`, "error");
  }
}

async function handleRestoreBackup() {
  const fileInput = document.getElementById('backupFileInput');
  const pwdInput = document.getElementById('backupRestorePwd');

  if (!fileInput.files || fileInput.files.length === 0) {
    showToast("Please choose a valid .json vault backup file.", "error");
    return;
  }
  if (!pwdInput.value) {
    showToast("Please enter the master password associated with the backup.", "error");
    return;
  }

  const file = fileInput.files[0];
  const text = await file.text();

  try {
    showToast("Validating and unwrapping backup vault key...", "info");
    const res = await window.storageService.restoreEncryptedJSONBackup(text, pwdInput.value);
    showToast(`Vault restored successfully with ${res.docCount} records!`, "success");
    pwdInput.value = '';
    fileInput.value = '';
    updateAppSessionState();
    switchAppView('dashboard');
  } catch (err) {
    showToast(`Restore failed: ${err.message}`, "error");
  }
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

// ==============================================================================
// 11. Modal Dialogs (Add, Edit, View Decrypted)
// ==============================================================================

function initDocumentModals() {
  // Document Type change listener in Add Modal
  const typeSelect = document.getElementById('modalDocType');
  if (typeSelect) {
    typeSelect.addEventListener('change', () => {
      configureModalFieldsForType(typeSelect.value);
    });
  }

  // Add / Edit Document Form Submit
  const addForm = document.getElementById('addDocForm');
  if (addForm) {
    addForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      await handleSaveDocument();
    });
  }

  // Filter Event Listeners in My Documents View
  const filterType = document.getElementById('filterDocType');
  const filterStatus = document.getElementById('filterDocStatus');
  const searchInput = document.getElementById('docSearchInput');

  if (filterType) {
    filterType.addEventListener('change', () => {
      currentFilterType = filterType.value;
      renderDocumentsView();
    });
  }

  if (filterStatus) {
    filterStatus.addEventListener('change', () => {
      currentFilterStatus = filterStatus.value;
      renderDocumentsView();
    });
  }

  if (searchInput) {
    searchInput.addEventListener('input', () => {
      currentSearchQuery = searchInput.value.trim();
      renderDocumentsView();
    });
  }

  // View Mode Switcher Buttons (Cards vs Table)
  const toggleCards = document.getElementById('viewToggleCards');
  const toggleTable = document.getElementById('viewToggleTable');
  const cardsContainer = document.getElementById('cardsViewContainer');
  const tableContainer = document.getElementById('tableViewContainer');

  if (toggleCards && toggleTable) {
    toggleCards.addEventListener('click', () => {
      currentViewMode = 'cards';
      toggleCards.classList.add('active');
      toggleTable.classList.remove('active');
      cardsContainer.style.display = 'block';
      tableContainer.style.display = 'none';
    });

    toggleTable.addEventListener('click', () => {
      currentViewMode = 'table';
      toggleTable.classList.add('active');
      toggleCards.classList.remove('active');
      cardsContainer.style.display = 'none';
      tableContainer.style.display = 'block';
    });
  }
}

function configureModalFieldsForType(docType) {
  const passportFields = document.getElementById('passportOnlyFields');
  const lifetimeNotice = document.getElementById('lifetimeNotice');
  const reviewFields = document.getElementById('reviewOnlyFields');
  const numInput = document.getElementById('modalDocNumber');
  const helpText = document.getElementById('docNumberHelpText');

  if (docType === DocumentType.PASSPORT) {
    passportFields.style.display = 'grid';
    lifetimeNotice.style.display = 'none';
    reviewFields.style.display = 'none';
    numInput.placeholder = 'e.g. Z9876543 (1 letter + 7 digits)';
    helpText.textContent = 'Passports require issue date and dynamic expiry date.';
  } else if (docType === DocumentType.AADHAAR) {
    passportFields.style.display = 'none';
    lifetimeNotice.style.display = 'block';
    reviewFields.style.display = 'block';
    numInput.placeholder = 'e.g. 2345 6789 0128 (12 digits, cannot start with 0 or 1)';
    helpText.textContent = 'Aadhaar cards have permanent lifetime validity (no expiry date).';
  } else {
    // PAN
    passportFields.style.display = 'none';
    lifetimeNotice.style.display = 'block';
    reviewFields.style.display = 'block';
    numInput.placeholder = 'e.g. ABCDE1234F (10 chars, 4th char is entity)';
    helpText.textContent = 'PAN cards have permanent lifetime validity (no expiry date).';
  }
}

function openAddDocModal() {
  document.getElementById('editingDocId').value = '';
  document.getElementById('addDocDialogTitle').textContent = '+ Add Document to Encrypted Vault';
  document.getElementById('btnSubmitDocModal').textContent = 'Encrypt & Save Record';

  document.getElementById('modalDocType').value = DocumentType.PASSPORT;
  document.getElementById('modalDocNumber').value = '';
  document.getElementById('modalIssueDate').value = '';
  document.getElementById('modalExpiryDate').value = '';
  document.getElementById('modalReminderDate').value = '';
  document.getElementById('modalNotes').value = '';

  configureModalFieldsForType(DocumentType.PASSPORT);
  openDialog('addDocDialog');
}

function openEditDocModal(documentId) {
  const userId = window.storageService.session.user.userId;
  const docs = window.storageService.getDocuments(userId);
  const doc = docs.find(d => d.document_id === documentId);
  if (!doc) return;

  document.getElementById('editingDocId').value = doc.document_id;
  document.getElementById('addDocDialogTitle').textContent = `✏️ Edit ${doc.document_type} (${doc.document_number_masked})`;
  document.getElementById('btnSubmitDocModal').textContent = 'Save Changes';

  document.getElementById('modalDocType').value = doc.document_type;
  document.getElementById('modalDocNumber').value = doc.document_number_masked; // Keep masked as placeholder
  document.getElementById('modalIssueDate').value = doc.issue_date || '';
  document.getElementById('modalExpiryDate').value = doc.expiry_date || '';
  document.getElementById('modalReminderDate').value = doc.reminder_date || '';
  document.getElementById('modalNotes').value = doc.notes || '';

  configureModalFieldsForType(doc.document_type);
  openDialog('addDocDialog');
}

async function handleSaveDocument() {
  const editingIdStr = document.getElementById('editingDocId').value;
  const isEditing = Boolean(editingIdStr);
  const docType = document.getElementById('modalDocType').value;
  const rawNum = document.getElementById('modalDocNumber').value.trim();
  const issueDate = document.getElementById('modalIssueDate').value || null;
  const expiryDate = document.getElementById('modalExpiryDate').value || null;
  const reminderDate = document.getElementById('modalReminderDate').value || null;
  const notes = document.getElementById('modalNotes').value.trim();

  // If editing and user didn't modify masked number, skip rawNum validation check
  const isMaskedPlaceholder = isEditing && rawNum.includes('X');

  if (!isMaskedPlaceholder) {
    const valResult = validateDocumentInput(docType, rawNum, issueDate, expiryDate, reminderDate);
    if (!valResult.isValid) {
      showToast(valResult.issues[0], 'error');
      return;
    }
  }

  const userId = window.storageService.session.user.userId;

  try {
    if (isEditing) {
      const updatePayload = {
        document_type: docType,
        issue_date: issueDate,
        expiry_date: expiryDate,
        reminder_date: reminderDate,
        notes: notes
      };
      if (!isMaskedPlaceholder) {
        updatePayload.document_number = rawNum;
      }
      await window.storageService.updateDocument(parseInt(editingIdStr), userId, updatePayload);
      showToast('Document record updated!', 'success');
    } else {
      await window.storageService.addDocument(userId, {
        document_type: docType,
        document_number: rawNum,
        issue_date: issueDate,
        expiry_date: expiryDate,
        reminder_date: reminderDate,
        reminder_days: 180,
        notes: notes
      });
      showToast('Document encrypted with AES-256-GCM and saved!', 'success');
    }

    closeDialog('addDocDialog');
    if (currentActiveView === 'dashboard') renderDashboard();
    else if (currentActiveView === 'documents') renderDocumentsView();
    else if (currentActiveView === 'reminders') renderRemindersView();
  } catch (err) {
    showToast(err.message, 'error');
  }
}

async function viewDocumentDecrypted(documentId) {
  if (!window.storageService || !window.storageService.isAuthenticated()) return;
  const userId = window.storageService.session.user.userId;
  const docs = window.storageService.getDocuments(userId);
  const doc = docs.find(d => d.document_id === documentId);
  if (!doc) return;

  const modalBody = document.getElementById('viewModalBody');
  modalBody.innerHTML = '<div style="text-align: center; padding: 20px;">Decrypting with AES-256-GCM...</div>';
  openDialog('viewDocDialog');

  let rawNumber = '';
  try {
    rawNumber = await window.storageService.decryptDocumentNumber(doc);
  } catch (err) {
    rawNumber = 'DECRYPTION_ERROR';
  }

  const analysis = analyzeDocumentStatus(doc);

  modalBody.innerHTML = `
    <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 20px;">
      <div style="font-size: 2.2rem;">${getDocumentIcon(doc.document_type)}</div>
      <div>
        <h4 style="margin: 0; font-size: 1.2rem; color: var(--text-primary);">${doc.document_type}</h4>
        <span class="smart-card-status ${analysis.badgeClass.replace('status-', '')}">${analysis.status}</span>
      </div>
    </div>

    <!-- Decrypted Number Box with Copy -->
    <div style="background: var(--bg-input); border: 1px solid var(--border-medium); border-radius: 12px; padding: 16px; margin-bottom: 20px;">
      <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
        <span style="font-size: 0.76rem; color: var(--text-muted); text-transform: uppercase;">Decrypted Document Number</span>
        <button class="btn-card-action" onclick="copyToClipboard('${rawNumber}')">📋 Copy</button>
      </div>
      <div id="unmaskedNumberDisplay" style="font-family: var(--font-mono); font-size: 1.4rem; font-weight: 800; letter-spacing: 3px; color: var(--brand-blue-light);">
        ${rawNumber}
      </div>
    </div>

    <!-- Detailed Key-Value Grid -->
    <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; font-size: 0.88rem;">
      <div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">MASKED NUMBER</div>
        <div><code>${doc.document_number_masked}</code></div>
      </div>
      <div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">HMAC BLIND HASH</div>
        <div style="font-family: var(--font-mono); font-size: 0.72rem; word-break: break-all; color: var(--text-secondary);">${doc.document_number_hash.slice(0, 16)}...</div>
      </div>
      <div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">ISSUE DATE</div>
        <div>${doc.issue_date || '—'}</div>
      </div>
      <div>
        <div style="color: var(--text-muted); font-size: 0.75rem;">EXPIRY / REVIEW DATE</div>
        <div>${doc.expiry_date || doc.reminder_date || 'Permanent Lifetime'}</div>
      </div>
      <div style="grid-column: 1 / -1;">
        <div style="color: var(--text-muted); font-size: 0.75rem;">STATUS CALCULATION</div>
        <div style="color: var(--brand-blue-light);">${analysis.displayText}</div>
      </div>
      <div style="grid-column: 1 / -1;">
        <div style="color: var(--text-muted); font-size: 0.75rem;">DESCRIPTION & NOTES</div>
        <div style="color: var(--text-primary);">${doc.notes || 'No description notes provided'}</div>
      </div>
      <div style="grid-column: 1 / -1;">
        <div style="color: var(--text-muted); font-size: 0.75rem;">ENCRYPTED RECORD CREATION</div>
        <div style="font-size: 0.78rem; color: var(--text-muted);">${new Date(doc.created_at).toLocaleString()}</div>
      </div>
    </div>
  `;
}

async function deleteDocumentRecord(documentId) {
  if (!confirm("Are you sure you want to permanently delete this document from your encrypted vault?")) return;
  const userId = window.storageService.session.user.userId;
  await window.storageService.deleteDocument(documentId, userId);
  showToast("Document deleted.", "info");
  if (currentActiveView === 'dashboard') renderDashboard();
  else if (currentActiveView === 'documents') renderDocumentsView();
  else if (currentActiveView === 'reminders') renderRemindersView();
}

function copyToClipboard(text) {
  navigator.clipboard.writeText(text).then(() => {
    showToast("Decrypted number copied to clipboard!", "success");
  }).catch(() => {
    showToast("Unable to copy to clipboard", "error");
  });
}

// Native Dialog Helpers
function openDialog(dialogId) {
  const dialog = document.getElementById(dialogId);
  if (dialog && typeof dialog.showModal === 'function') {
    dialog.showModal();
  }
}

function closeDialog(dialogId) {
  const dialog = document.getElementById(dialogId);
  if (dialog && typeof dialog.close === 'function') {
    dialog.close();
  }
}

// Toast System
function showToast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  if (!container) return;

  const toast = document.createElement('div');
  toast.className = `toast toast-${type}`;

  const icons = {
    success: '✓',
    error: '✕',
    warning: '⚠️',
    info: 'ℹ️'
  };

  toast.innerHTML = `
    <span style="font-size: 1.1rem; font-weight: bold;">${icons[type] || 'ℹ️'}</span>
    <span style="flex: 1;">${message}</span>
  `;

  container.appendChild(toast);

  setTimeout(() => {
    toast.style.opacity = '0';
    toast.style.transform = 'translateX(100%)';
    toast.style.transition = 'all 0.3s ease';
    setTimeout(() => toast.remove(), 300);
  }, 4000);
}
