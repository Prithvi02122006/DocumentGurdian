# DOCUMENT GUARDIAN
### Secure Personal Document Management System

> [!NOTE]
> **Academic Project Notice**: Document Guardian is an independent, student-developed software project created for secure personal records management. This application is **NOT an official Government of India application** and has no affiliation with, sponsorship from, or endorsement by the Government of India or any government agency. It does not employ official government seals, emblems, or logos.

---

## 1. Overview
Document Guardian is a secure desktop application designed to help individuals maintain confidential records of primary identity documents (Passport, Aadhaar, and PAN), track renewal and review milestones, securely store encrypted digital copies (PDF, JPG, JPEG, PNG), and receive proactive desktop reminders before documents expire or require periodic review.

---

## 2. Security Architecture & Threat Model

### Cryptographic Standards
- **Symmetric Encryption**: **AES-256-GCM** (Galois/Counter Mode). Provides both confidentiality and cryptographic authenticity (tamper detection). Used for sensitive document numbers and uploaded vault files.
- **Key Derivation & Password Hashing**: **Argon2id** (memory-hard, resistant to GPU/ASIC cracking) with fallback to **PBKDF2-HMAC-SHA256** (600,000 iterations).
- **Integrity & Duplicate Detection**: **HMAC-SHA256** using a per-user salt to detect duplicate document numbers without storing plaintext.

### Key Management Approach (Envelope Encryption)
To avoid hardcoding secrets or storing raw encryption keys beside sensitive data, Document Guardian implements a two-tier envelope encryption architecture:

```
[ Master Password ] + [ Random KEK Salt ]
               │
               ▼ (Argon2id / PBKDF2)
       [ KEK: Key Encrypting Key ]
               │
       Decrypts / Encrypts
               ▼
   [ DEK: Data Encryption Key (256-bit random) ]
               │
       In-Memory Active Session Only
               │
       AES-256-GCM Encrypts & Decrypts
               ▼
   [ Sensitive Document Numbers & Vault Files ]
```

1. **Registration**: A cryptographically random 256-bit Data Encryption Key (`DEK`) is generated via `os.urandom(32)`. A Key Encrypting Key (`KEK`) is derived from the master password and a unique 32-byte salt (`kek_salt`). The `DEK` is encrypted with the `KEK` using AES-256-GCM and stored in the database (`encrypted_dek` and `dek_nonce`).
2. **Authentication**: The user's password derives the `KEK`, which decrypts the stored `encrypted_dek` into volatile memory for the active session.
3. **Session Lock / Logout**: The `DEK` is immediately dereferenced and wiped from process memory.
4. **Password Change**: When updating the password, the `DEK` is decrypted using the old `KEK` and re-encrypted with a new `KEK` derived from the new password. **Zero re-encryption of files or records is required.**

### Security Trade-offs for a Local Desktop Application
- **At-Rest Protection**: Strong. If the local device is powered down, stolen, or the SQLite file copied, the attacker cannot read any document numbers or vault files without the master password.
- **In-Memory Exposure**: While unlocked, the application must hold the `DEK` in volatile RAM to perform operations. An adversary with administrative debugger access to the running process could theoretically dump memory. Document Guardian mitigates this through **configurable session inactivity timeouts** that automatically clear keys from RAM when idle.

---

## 3. Database Schema (SQLite)

Document Guardian utilizes SQLite with `PRAGMA foreign_keys = ON;` and structured tables:
- `users`: Account credentials, cryptographic salts, encrypted DEK, lockout tracking, and session timestamps.
- `documents`: Encrypted document numbers, masked numbers, hash for duplicate prevention, issue/expiry/reminder dates, and encrypted file references.
- `audit_logs`: Append-only security audit trail recording authentication, document actions, and vault access. **Strictly no sensitive numbers, keys, or passwords in logs.**

---

## 4. Document Rules
- **Passport**:
  - Requires Issue Date and Expiry Date.
  - Expiry is calculated dynamically against current date.
  - Generates `Expired` or `Attention Required` alerts within the configured reminder window.
- **Aadhaar & PAN**:
  - **No invented expiry dates**: Neither Aadhaar nor PAN expire by law.
  - Optional review/update reminder dates for periodic record verification.
  - Status is `Valid` or `Review Due`.

---

## 5. Development Roadmap & Status
All 12 development stages have been successfully built, verified, and packaged:

| Stage | Description | Status |
| :--- | :--- | :--- |
| **Stage 1** | Project structure + SQLite schema | **COMPLETE** |
| **Stage 2** | Authentication + password hashing + lockout policy | **COMPLETE** |
| **Stage 3** | Session management + DEK lifecycle + inactivity lock | **COMPLETE** |
| **Stage 4** | Document CRUD operations + HMAC duplicate detection | **COMPLETE** |
| **Stage 5** | Expiry / review date dynamic calculation engine | **COMPLETE** |
| **Stage 6** | Reminder engine & desktop notifications (Plyer) | **COMPLETE** |
| **Stage 7** | Encrypted document vault storage (AES-256-GCM) | **COMPLETE** |
| **Stage 8** | Professional public-service CustomTkinter UI | **COMPLETE** |
| **Stage 9** | Settings, CSV export (masked/decrypted) & audit viewer | **COMPLETE** |
| **Stage 10** | Validation & error handling hardening | **COMPLETE** |
| **Stage 11** | End-to-end testing suite (66 automated tests) | **COMPLETE** |
| **Stage 12** | Standalone PyInstaller packaging (`DocumentGuardian.exe`) | **COMPLETE** |

---

## 6. Running the Application

### Option A: Standalone Executable (Windows)
No Python runtime or third-party dependencies required:
```powershell
# Run GUI application
.\dist\DocumentGuardian.exe

# Or run non-GUI integrity smoke test
.\dist\DocumentGuardian.exe --smoke-test
```

### Option B: Running from Source
```powershell
# Navigate to project directory
cd C:\Users\DELL\.gemini\antigravity\scratch\DocumentGuardian

# Run GUI application with virtual environment Python
.\.venv\Scripts\python.exe main.py

# Or run integrity smoke test
.\.venv\Scripts\python.exe main.py --smoke-test
```

---

## 7. Running the Test Suite
The automated test suite contains 66 tests verifying all subsystems, cryptography, and end-to-end user flows:
```powershell
.\.venv\Scripts\pytest -v
```

