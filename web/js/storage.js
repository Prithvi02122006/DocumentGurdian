/**
 * DOCUMENT GUARDIAN - Client-Side Storage & Session State
 * Controls in-memory DEK lifecycle, activity detection, brute-force lockout,
 * DEK re-wrapping on master password change, encrypted file vault, CSV export,
 * and zero-knowledge backup/restore.
 */

class StorageService {
  constructor() {
    this.session = {
      user: null,
      dek: null,          // In-memory CryptoKey; strictly wiped on lock or logout
      isLocked: false,
      lastActivity: Date.now(),
      timeoutMinutes: 15
    };

    this.STORAGE_KEYS = {
      USERS: 'docguardian_users',
      DOCUMENTS: 'docguardian_documents',
      AUDIT_LOGS: 'docguardian_audit_logs',
      FILES: 'docguardian_vault_files',
      SETTINGS: 'docguardian_settings'
    };

    // Remove any leftover demo citizen account so users always start with their own clean vault
    this._cleanupLegacyDemo();
  }

  _cleanupLegacyDemo() {
    try {
      const rawUsers = localStorage.getItem(this.STORAGE_KEYS.USERS);
      if (rawUsers) {
        const users = JSON.parse(rawUsers);
        const demoUser = users.find(u => u.username === 'citizen_demo');
        if (demoUser) {
          const filteredUsers = users.filter(u => u.username !== 'citizen_demo');
          localStorage.setItem(this.STORAGE_KEYS.USERS, JSON.stringify(filteredUsers));

          const rawDocs = localStorage.getItem(this.STORAGE_KEYS.DOCUMENTS);
          if (rawDocs) {
            const docs = JSON.parse(rawDocs);
            const filteredDocs = docs.filter(d => d.user_id !== demoUser.userId);
            localStorage.setItem(this.STORAGE_KEYS.DOCUMENTS, JSON.stringify(filteredDocs));
          }
        }
      }
    } catch (e) {
      // Safe fallback
    }
  }

  // --- Session Methods ---

  startSession(user, dek) {
    this.session.user = user;
    this.session.dek = dek;
    this.session.isLocked = false;
    this.session.lastActivity = Date.now();
    this.logAudit(AuditAction.LOGIN_SUCCESS, user.userId, `Session initialized for user '${user.username}'`);
  }

  lockSession(reason = "User manual lock") {
    if (!this.session.user) return;
    this.session.dek = null; // Wipe key from memory
    this.session.isLocked = true;
    this.logAudit(AuditAction.SESSION_LOCKED, this.session.user.userId, reason);
  }

  async unlockSession(password) {
    if (!this.session.user) return { success: false, message: "No active session to unlock." };
    const user = this.session.user;

    // Check account lockout
    if (user.lockedUntil && Date.now() < user.lockedUntil) {
      const waitSec = Math.ceil((user.lockedUntil - Date.now()) / 1000);
      const mins = Math.floor(waitSec / 60);
      const secs = waitSec % 60;
      return { success: false, message: `Account locked due to consecutive failed attempts. Try again in ${mins}m ${secs}s.` };
    }

    try {
      const kek = await window.webCrypto.deriveKEK(password, new Uint8Array(window.webCrypto.base64ToArrayBuffer(user.kekSalt)));
      const dek = await window.webCrypto.unwrapDEK(user.encryptedDek, user.dekNonce, kek);
      this.session.dek = dek;
      this.session.isLocked = false;
      this.session.lastActivity = Date.now();

      // Reset failed attempts
      user.failedAttempts = 0;
      user.lockedUntil = null;
      this._updateUser(user);

      this.logAudit(AuditAction.SESSION_UNLOCKED, user.userId, "Unlocked with master password");
      return { success: true };
    } catch (e) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= 5) {
        user.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 mins
        this._updateUser(user);
        this.logAudit(AuditAction.LOGIN_FAILED, user.userId, "Account locked: 5 consecutive failed unlock attempts");
        return { success: false, message: "Too many failed attempts. Account locked for 15 minutes." };
      }
      this._updateUser(user);
      const remaining = 5 - user.failedAttempts;
      this.logAudit(AuditAction.LOGIN_FAILED, user.userId, `Failed unlock attempt (${user.failedAttempts}/5)`);
      return { success: false, message: `Incorrect master password. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining.` };
    }
  }

  logout() {
    if (this.session.user) {
      this.logAudit(AuditAction.LOGOUT, this.session.user.userId, "User logged out");
    }
    this.session.user = null;
    this.session.dek = null;
    this.session.isLocked = false;
  }

  isAuthenticated() {
    return this.session.user !== null && !this.session.isLocked && this.session.dek !== null;
  }

  getDEK() {
    if (this.session.isLocked || !this.session.dek) {
      throw new Error("Session is locked or unauthenticated. Cryptographic key not in memory.");
    }
    return this.session.dek;
  }

  recordActivity() {
    this.session.lastActivity = Date.now();
  }

  checkInactivity() {
    if (!this.isAuthenticated()) return false;
    const elapsedMs = Date.now() - this.session.lastActivity;
    const timeoutMs = (this.session.timeoutMinutes || 15) * 60 * 1000;
    if (elapsedMs >= timeoutMs) {
      this.lockSession("Inactivity timeout exceeded");
      return true;
    }
    return false;
  }

  getRemainingInactivitySeconds() {
    if (!this.isAuthenticated()) return 0;
    const elapsedMs = Date.now() - this.session.lastActivity;
    const timeoutMs = (this.session.timeoutMinutes || 15) * 60 * 1000;
    return Math.max(0, Math.floor((timeoutMs - elapsedMs) / 1000));
  }

  setTimeoutMinutes(minutes) {
    this.session.timeoutMinutes = Math.max(1, Math.min(60, parseInt(minutes) || 15));
    const settings = this.getSettings();
    settings.timeoutMinutes = this.session.timeoutMinutes;
    localStorage.setItem(this.STORAGE_KEYS.SETTINGS, JSON.stringify(settings));
  }

  getSettings() {
    const raw = localStorage.getItem(this.STORAGE_KEYS.SETTINGS);
    return raw ? JSON.parse(raw) : { timeoutMinutes: 15 };
  }

  // --- Authentication: Registration & Login ---

  async registerUser(username, password, confirmPassword) {
    const cleanUser = (username || '').trim();
    if (!cleanUser || cleanUser.length < 3) {
      throw new Error("Username must be at least 3 characters long.");
    }
    if (password !== confirmPassword) {
      throw new Error("Master passwords do not match.");
    }

    // Password requirements check: min 10 chars, uppercase, lowercase, digit, symbol
    if (password.length < 10) {
      throw new Error("Master password must be at least 10 characters long.");
    }
    if (!/[A-Z]/.test(password)) {
      throw new Error("Master password must contain at least one uppercase letter (A-Z).");
    }
    if (!/[a-z]/.test(password)) {
      throw new Error("Master password must contain at least one lowercase letter (a-z).");
    }
    if (!/[0-9]/.test(password)) {
      throw new Error("Master password must contain at least one numeric digit (0-9).");
    }
    if (!/[^A-Za-z0-9]/.test(password)) {
      throw new Error("Master password must contain at least one special symbol (!@#$%^&*...).");
    }

    const users = this.getUsers();
    if (users.some(u => u.username.toLowerCase() === cleanUser.toLowerCase())) {
      throw new Error(`Username '${cleanUser}' is already registered. Please choose another or sign in.`);
    }

    // Key Derivation and Envelope Encryption
    const saltBytes = window.webCrypto.generateRandomBytes(16);
    const saltB64 = window.webCrypto.arrayBufferToBase64(saltBytes);

    const kek = await window.webCrypto.deriveKEK(password, saltBytes);
    const dek = await window.webCrypto.generateDEK();
    const wrapped = await window.webCrypto.wrapDEK(dek, kek);

    const newUser = {
      userId: Date.now(),
      username: cleanUser,
      kekSalt: saltB64,
      encryptedDek: wrapped.encryptedDek,
      dekNonce: wrapped.nonce,
      failedAttempts: 0,
      lockedUntil: null,
      created_at: new Date().toISOString()
    };

    users.push(newUser);
    this.saveUsers(users);

    this.logAudit(AuditAction.LOGIN_SUCCESS, newUser.userId, `New account registered: ${cleanUser}`);
    this.startSession(newUser, dek);
    return { user: newUser, dek: dek };
  }

  async loginUser(username, password) {
    const cleanUser = (username || '').trim();
    if (!cleanUser || !password) {
      throw new Error("Please enter both username and master password.");
    }

    const users = this.getUsers();
    const user = users.find(u => u.username.toLowerCase() === cleanUser.toLowerCase());
    if (!user) {
      throw new Error("Invalid username or password.");
    }

    // Check temporary lockout
    if (user.lockedUntil && Date.now() < user.lockedUntil) {
      const waitSec = Math.ceil((user.lockedUntil - Date.now()) / 1000);
      const mins = Math.floor(waitSec / 60);
      const secs = waitSec % 60;
      throw new Error(`Account locked due to 5 consecutive failed attempts. Try again in ${mins}m ${secs}s.`);
    }

    try {
      const saltBytes = new Uint8Array(window.webCrypto.base64ToArrayBuffer(user.kekSalt));
      const kek = await window.webCrypto.deriveKEK(password, saltBytes);
      const dek = await window.webCrypto.unwrapDEK(user.encryptedDek, user.dekNonce, kek);

      // Successful unlock: reset counters
      user.failedAttempts = 0;
      user.lockedUntil = null;
      this._updateUser(user);

      this.startSession(user, dek);
      return { user: user, dek: dek };
    } catch (e) {
      user.failedAttempts = (user.failedAttempts || 0) + 1;
      if (user.failedAttempts >= 5) {
        user.lockedUntil = Date.now() + 15 * 60 * 1000; // 15 mins
        this._updateUser(user);
        this.logAudit(AuditAction.LOGIN_FAILED, user.userId, "Account locked: 5 consecutive failed login attempts");
        throw new Error("Too many failed attempts. Account temporarily locked for 15 minutes.");
      }
      this._updateUser(user);
      const remaining = 5 - user.failedAttempts;
      this.logAudit(AuditAction.LOGIN_FAILED, user.userId, `Failed login attempt (${user.failedAttempts}/5)`);
      throw new Error(`Invalid master password. ${remaining} attempt${remaining !== 1 ? 's' : ''} remaining before lockout.`);
    }
  }

  async changeMasterPassword(currentPassword, newPassword, confirmPassword) {
    if (!this.isAuthenticated()) {
      throw new Error("Session expired. Please sign in again.");
    }
    const user = this.session.user;

    if (newPassword !== confirmPassword) {
      throw new Error("New master passwords do not match.");
    }

    // Password requirements check
    if (newPassword.length < 10 || !/[A-Z]/.test(newPassword) || !/[a-z]/.test(newPassword) || !/[0-9]/.test(newPassword) || !/[^A-Za-z0-9]/.test(newPassword)) {
      throw new Error("New password must have >= 10 chars, uppercase, lowercase, digit, and symbol.");
    }

    // 1. Verify current password by deriving old KEK and unwrapping current DEK
    let currentDek;
    try {
      const oldSaltBytes = new Uint8Array(window.webCrypto.base64ToArrayBuffer(user.kekSalt));
      const oldKek = await window.webCrypto.deriveKEK(currentPassword, oldSaltBytes);
      currentDek = await window.webCrypto.unwrapDEK(user.encryptedDek, user.dekNonce, oldKek);
    } catch (e) {
      throw new Error("Current master password is incorrect.");
    }

    // 2. Generate new fresh salt & derive new KEK
    const newSaltBytes = window.webCrypto.generateRandomBytes(16);
    const newSaltB64 = window.webCrypto.arrayBufferToBase64(newSaltBytes);
    const newKek = await window.webCrypto.deriveKEK(newPassword, newSaltBytes);

    // 3. Re-wrap the SAME DEK with the new KEK!
    const rewrapped = await window.webCrypto.wrapDEK(currentDek, newKek);

    // 4. Update user record
    user.kekSalt = newSaltB64;
    user.encryptedDek = rewrapped.encryptedDek;
    user.dekNonce = rewrapped.nonce;
    this._updateUser(user);

    // Keep active session key
    this.session.dek = currentDek;
    this.logAudit(AuditAction.PASSWORD_CHANGED, user.userId, "Master password changed and DEK re-wrapped successfully");
    return true;
  }

  _updateUser(user) {
    const users = this.getUsers();
    const idx = users.findIndex(u => u.userId === user.userId);
    if (idx !== -1) {
      users[idx] = user;
      this.saveUsers(users);
    }
  }

  // --- Storage CRUD Methods ---

  getUsers() {
    const raw = localStorage.getItem(this.STORAGE_KEYS.USERS);
    return raw ? JSON.parse(raw) : [];
  }

  saveUsers(users) {
    localStorage.setItem(this.STORAGE_KEYS.USERS, JSON.stringify(users));
  }

  getDocuments(userId) {
    const raw = localStorage.getItem(this.STORAGE_KEYS.DOCUMENTS);
    const all = raw ? JSON.parse(raw) : [];
    return all.filter(d => d.user_id === userId);
  }

  getAllDocuments() {
    const raw = localStorage.getItem(this.STORAGE_KEYS.DOCUMENTS);
    return raw ? JSON.parse(raw) : [];
  }

  saveAllDocuments(docs) {
    localStorage.setItem(this.STORAGE_KEYS.DOCUMENTS, JSON.stringify(docs));
  }

  async addDocument(userId, docData) {
    const dek = this.getDEK();
    const user = this.session.user;

    // 1. Calculate HMAC duplicate hash
    const numberHash = await window.webCrypto.generateDocumentHash(docData.document_number, user.kekSalt);
    const userDocs = this.getDocuments(userId);

    const exists = userDocs.some(d => d.document_type === docData.document_type && d.document_number_hash === numberHash);
    if (exists) {
      throw new Error(`A ${docData.document_type} with this number is already registered in your vault.`);
    }

    // 2. Encrypt document number with AES-256-GCM
    const encResult = await window.webCrypto.encryptString(docData.document_number, dek);

    // 3. Mask number for safe display
    const masked = maskDocumentNumber(docData.document_type, docData.document_number);

    const newDoc = {
      document_id: Date.now() + Math.floor(Math.random() * 1000),
      user_id: userId,
      document_type: docData.document_type,
      document_number_cipher: encResult.ciphertext,
      document_number_nonce: encResult.nonce,
      document_number_masked: masked,
      document_number_hash: numberHash,
      issue_date: docData.issue_date || null,
      expiry_date: docData.expiry_date || null,
      reminder_date: docData.reminder_date || null,
      reminder_days: docData.reminder_days || 180,
      notes: docData.notes || '',
      file_id: docData.file_id || null,
      file_name: docData.file_name || null,
      file_size: docData.file_size || null,
      created_at: new Date().toISOString()
    };

    const all = this.getAllDocuments();
    all.unshift(newDoc);
    this.saveAllDocuments(all);

    this.logAudit(AuditAction.DOCUMENT_ADDED, userId, `Added ${newDoc.document_type} (${newDoc.document_number_masked})`);
    return newDoc;
  }

  async updateDocument(documentId, userId, updateData) {
    const dek = this.getDEK();
    const all = this.getAllDocuments();
    const idx = all.findIndex(d => d.document_id === documentId && d.user_id === userId);
    if (idx === -1) throw new Error("Document not found.");

    const existing = all[idx];

    // If document number changed, re-encrypt & compute new HMAC
    if (updateData.document_number) {
      const user = this.session.user;
      const numberHash = await window.webCrypto.generateDocumentHash(updateData.document_number, user.kekSalt);
      const otherDocs = all.filter(d => d.user_id === userId && d.document_id !== documentId);
      if (otherDocs.some(d => d.document_type === (updateData.document_type || existing.document_type) && d.document_number_hash === numberHash)) {
        throw new Error(`Another ${updateData.document_type || existing.document_type} with this number already exists.`);
      }

      const encResult = await window.webCrypto.encryptString(updateData.document_number, dek);
      existing.document_number_cipher = encResult.ciphertext;
      existing.document_number_nonce = encResult.nonce;
      existing.document_number_masked = maskDocumentNumber(updateData.document_type || existing.document_type, updateData.document_number);
      existing.document_number_hash = numberHash;
    }

    if (updateData.document_type) existing.document_type = updateData.document_type;
    if (updateData.issue_date !== undefined) existing.issue_date = updateData.issue_date;
    if (updateData.expiry_date !== undefined) existing.expiry_date = updateData.expiry_date;
    if (updateData.reminder_date !== undefined) existing.reminder_date = updateData.reminder_date;
    if (updateData.reminder_days !== undefined) existing.reminder_days = updateData.reminder_days;
    if (updateData.notes !== undefined) existing.notes = updateData.notes;
    if (updateData.file_id !== undefined) existing.file_id = updateData.file_id;
    if (updateData.file_name !== undefined) existing.file_name = updateData.file_name;
    if (updateData.file_size !== undefined) existing.file_size = updateData.file_size;

    all[idx] = existing;
    this.saveAllDocuments(all);

    this.logAudit(AuditAction.DOCUMENT_UPDATED, userId, `Updated ${existing.document_type} (${existing.document_number_masked})`);
    return existing;
  }

  async deleteDocument(documentId, userId) {
    const all = this.getAllDocuments();
    const target = all.find(d => d.document_id === documentId && d.user_id === userId);
    if (!target) return false;

    const filtered = all.filter(d => !(d.document_id === documentId && d.user_id === userId));
    this.saveAllDocuments(filtered);

    this.logAudit(AuditAction.DOCUMENT_DELETED, userId, `Deleted ${target.document_type} (${target.document_number_masked})`);
    return true;
  }

  async decryptDocumentNumber(doc) {
    const dek = this.getDEK();
    return await window.webCrypto.decryptString(doc.document_number_cipher, doc.document_number_nonce, dek);
  }

  // --- Encrypted File Vault ---

  getVaultFiles(userId) {
    const raw = localStorage.getItem(this.STORAGE_KEYS.FILES);
    const all = raw ? JSON.parse(raw) : [];
    return all.filter(f => f.user_id === userId);
  }

  saveAllVaultFiles(files) {
    localStorage.setItem(this.STORAGE_KEYS.FILES, JSON.stringify(files));
  }

  async encryptAndStoreVaultFile(userId, file) {
    const dek = this.getDEK();

    // 1. Read file as ArrayBuffer
    const arrayBuffer = await file.arrayBuffer();

    // 2. Validate magic bytes
    const bytes = new Uint8Array(arrayBuffer.slice(0, 8));
    let detectedMime = null;
    if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
      detectedMime = 'application/pdf';
    } else if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
      detectedMime = 'image/png';
    } else if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
      detectedMime = 'image/jpeg';
    } else {
      throw new Error("Unsupported file type. Only authentic PDF, PNG, and JPEG documents are permitted.");
    }

    // 3. Encrypt file bytes with AES-256-GCM
    const encResult = await window.webCrypto.encryptBuffer(arrayBuffer, dek);

    const fileRecord = {
      file_id: Date.now() + Math.floor(Math.random() * 1000),
      user_id: userId,
      file_name: file.name,
      file_size: file.size,
      mime_type: detectedMime,
      cipher_b64: encResult.ciphertext,
      nonce_b64: encResult.nonce,
      uploaded_at: new Date().toISOString()
    };

    const files = this.getVaultFiles(userId);
    const allFiles = localStorage.getItem(this.STORAGE_KEYS.FILES) ? JSON.parse(localStorage.getItem(this.STORAGE_KEYS.FILES)) : [];
    allFiles.unshift(fileRecord);
    this.saveAllVaultFiles(allFiles);

    this.logAudit(AuditAction.FILE_UPLOADED, userId, `Encrypted and stored file: ${file.name} (${(file.size / 1024).toFixed(1)} KB)`);
    return fileRecord;
  }

  async decryptVaultFile(fileId, userId) {
    const dek = this.getDEK();
    const files = this.getVaultFiles(userId);
    const fileRecord = files.find(f => f.file_id === fileId);
    if (!fileRecord) throw new Error("Vault file not found.");

    const decryptedBuffer = await window.webCrypto.decryptBuffer(fileRecord.cipher_b64, fileRecord.nonce_b64, dek);
    const blob = new Blob([decryptedBuffer], { type: fileRecord.mime_type });
    this.logAudit(AuditAction.FILE_VIEWED, userId, `Decrypted vault file: ${fileRecord.file_name}`);
    return { blob, fileRecord };
  }

  async deleteVaultFile(fileId, userId) {
    const allFiles = localStorage.getItem(this.STORAGE_KEYS.FILES) ? JSON.parse(localStorage.getItem(this.STORAGE_KEYS.FILES)) : [];
    const target = allFiles.find(f => f.file_id === fileId && f.user_id === userId);
    if (!target) return false;

    const filtered = allFiles.filter(f => !(f.file_id === fileId && f.user_id === userId));
    this.saveAllVaultFiles(filtered);
    this.logAudit(AuditAction.DOCUMENT_DELETED, userId, `Removed vault file: ${target.file_name}`);
    return true;
  }

  // --- Export & Backup / Restore ---

  async exportDecryptedCSV(userId) {
    if (!this.isAuthenticated()) throw new Error("Authentication required.");
    const docs = this.getDocuments(userId);

    const headers = ["Document ID", "Document Type", "Document Number", "Masked Number", "Issue Date", "Expiry Date", "Reminder Date", "Status", "Notes", "Created At"];
    const rows = [];

    for (const doc of docs) {
      let rawNumber = "DECRYPTION_ERROR";
      try {
        rawNumber = await this.decryptDocumentNumber(doc);
      } catch (e) {
        rawNumber = doc.document_number_masked;
      }
      const analysis = analyzeDocumentStatus(doc);
      rows.push([
        doc.document_id,
        doc.document_type,
        `"${rawNumber.replace(/"/g, '""')}"`,
        `"${doc.document_number_masked}"`,
        doc.issue_date || "",
        doc.expiry_date || "",
        doc.reminder_date || "",
        analysis.status,
        `"${(doc.notes || "").replace(/"/g, '""')}"`,
        doc.created_at
      ]);
    }

    const csvContent = "\uFEFF" + [headers.join(","), ...rows.map(r => r.join(","))].join("\r\n");
    this.logAudit(AuditAction.RECORDS_EXPORTED, userId, `Exported ${docs.length} document records to CSV`);
    return csvContent;
  }

  exportEncryptedJSONBackup(userId) {
    if (!this.isAuthenticated()) throw new Error("Authentication required.");
    const user = this.session.user;
    const docs = this.getDocuments(userId);
    const files = this.getVaultFiles(userId);
    const logs = this.getAuditLogs(userId);

    const backupBundle = {
      app: "DOCUMENT_GUARDIAN",
      version: "1.0.0",
      exported_at: new Date().toISOString(),
      user: {
        username: user.username,
        kekSalt: user.kekSalt,
        encryptedDek: user.encryptedDek,
        dekNonce: user.dekNonce
      },
      documents: docs,
      vault_files: files,
      audit_logs: logs
    };

    this.logAudit(AuditAction.RECORDS_EXPORTED, userId, "Generated full encrypted JSON vault backup bundle");
    return JSON.stringify(backupBundle, null, 2);
  }

  async restoreEncryptedJSONBackup(jsonString, masterPassword) {
    let bundle;
    try {
      bundle = JSON.parse(jsonString);
    } catch (e) {
      throw new Error("Invalid backup file format. Must be valid JSON.");
    }

    if (bundle.app !== "DOCUMENT_GUARDIAN" || !bundle.user || !bundle.documents) {
      throw new Error("Incompatible backup file format.");
    }

    // Verify master password against the backup's wrapped DEK
    let dek;
    try {
      const saltBytes = new Uint8Array(window.webCrypto.base64ToArrayBuffer(bundle.user.kekSalt));
      const kek = await window.webCrypto.deriveKEK(masterPassword, saltBytes);
      dek = await window.webCrypto.unwrapDEK(bundle.user.encryptedDek, bundle.user.dekNonce, kek);
    } catch (e) {
      throw new Error("Master password does not match this backup file.");
    }

    // Restore user
    const users = this.getUsers().filter(u => u.username.toLowerCase() !== bundle.user.username.toLowerCase());
    const restoredUser = {
      userId: Date.now(),
      username: bundle.user.username,
      kekSalt: bundle.user.kekSalt,
      encryptedDek: bundle.user.encryptedDek,
      dekNonce: bundle.user.dekNonce,
      failedAttempts: 0,
      lockedUntil: null,
      created_at: bundle.exported_at || new Date().toISOString()
    };
    users.push(restoredUser);
    this.saveUsers(users);

    // Restore documents
    const allDocs = this.getAllDocuments().filter(d => d.user_id !== restoredUser.userId);
    const restoredDocs = bundle.documents.map(d => ({ ...d, user_id: restoredUser.userId }));
    this.saveAllDocuments([...restoredDocs, ...allDocs]);

    // Restore files
    if (bundle.vault_files && Array.isArray(bundle.vault_files)) {
      const allFiles = (localStorage.getItem(this.STORAGE_KEYS.FILES) ? JSON.parse(localStorage.getItem(this.STORAGE_KEYS.FILES)) : []).filter(f => f.user_id !== restoredUser.userId);
      const restoredFiles = bundle.vault_files.map(f => ({ ...f, user_id: restoredUser.userId }));
      this.saveAllVaultFiles([...restoredFiles, ...allFiles]);
    }

    this.startSession(restoredUser, dek);
    this.logAudit(AuditAction.RECORDS_EXPORTED, restoredUser.userId, `Restored vault backup containing ${restoredDocs.length} records`);
    return { user: restoredUser, docCount: restoredDocs.length };
  }

  // --- Audit Trail ---

  logAudit(action, userId, details) {
    const logs = this.getAuditLogs();
    const entry = {
      log_id: Date.now() + Math.floor(Math.random() * 1000),
      user_id: userId,
      action: action,
      details: details,
      timestamp: new Date().toISOString()
    };
    logs.unshift(entry);
    if (logs.length > 250) logs.pop();
    localStorage.setItem(this.STORAGE_KEYS.AUDIT_LOGS, JSON.stringify(logs));
  }

  getAuditLogs(userId = null) {
    const raw = localStorage.getItem(this.STORAGE_KEYS.AUDIT_LOGS);
    const logs = raw ? JSON.parse(raw) : [];
    if (userId) return logs.filter(l => l.user_id === userId);
    return logs;
  }

}

window.storageService = new StorageService();
