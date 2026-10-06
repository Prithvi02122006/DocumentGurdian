/**
 * DOCUMENT GUARDIAN - Client-Side Cryptography Subsystem
 * Implements two-tier envelope encryption using the native Web Cryptography API (crypto.subtle).
 * Zero third-party dependencies. Authenticated AES-256-GCM encryption with tamper detection.
 */

class WebCryptoService {
  constructor() {
    this.crypto = window.crypto || window.msCrypto;
    if (!this.crypto || !this.crypto.subtle) {
      console.warn("Web Cryptography API is unavailable in this environment. Falling back to local demo mode.");
    }
  }

  // Base64 Helpers
  arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return window.btoa(binary);
  }

  base64ToArrayBuffer(base64) {
    const binary = window.atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes.buffer;
  }

  generateRandomBytes(length = 32) {
    const bytes = new Uint8Array(length);
    this.crypto.getRandomValues(bytes);
    return bytes;
  }

  generateRandomHex(length = 16) {
    const bytes = this.generateRandomBytes(length);
    return Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  /**
   * Derives a 256-bit Key Encrypting Key (KEK) from the master password and salt.
   * Utilizes PBKDF2 with SHA-256 and 100,000 rounds.
   */
  async deriveKEK(password, saltBytes) {
    const enc = new TextEncoder();
    const keyMaterial = await this.crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );

    return await this.crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        salt: saltBytes,
        iterations: 100000,
        hash: "SHA-256"
      },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt", "wrapKey", "unwrapKey"]
    );
  }

  /**
   * Generates a 256-bit random Data Encryption Key (DEK).
   */
  async generateDEK() {
    return await this.crypto.subtle.generateKey(
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Wraps (encrypts) the user's DEK with their KEK.
   */
  async wrapDEK(dekKey, kekKey) {
    const iv = this.generateRandomBytes(12);
    const wrappedBuffer = await this.crypto.subtle.wrapKey(
      "raw",
      dekKey,
      kekKey,
      { name: "AES-GCM", iv: iv }
    );

    return {
      encryptedDek: this.arrayBufferToBase64(wrappedBuffer),
      nonce: this.arrayBufferToBase64(iv)
    };
  }

  /**
   * Unwraps (decrypts) the stored DEK using the user's derived KEK.
   */
  async unwrapDEK(encryptedDekB64, nonceB64, kekKey) {
    const wrappedBuffer = this.base64ToArrayBuffer(encryptedDekB64);
    const iv = new Uint8Array(this.base64ToArrayBuffer(nonceB64));

    return await this.crypto.subtle.unwrapKey(
      "raw",
      wrappedBuffer,
      kekKey,
      { name: "AES-GCM", iv: iv },
      { name: "AES-GCM", length: 256 },
      true,
      ["encrypt", "decrypt"]
    );
  }

  /**
   * Encrypts plaintext string with the active DEK via AES-256-GCM.
   */
  async encryptString(plaintext, dekKey) {
    const enc = new TextEncoder();
    const iv = this.generateRandomBytes(12);
    const cipherBuffer = await this.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      dekKey,
      enc.encode(plaintext)
    );

    return {
      ciphertext: this.arrayBufferToBase64(cipherBuffer),
      nonce: this.arrayBufferToBase64(iv)
    };
  }

  /**
   * Decrypts AES-256-GCM ciphertext using the active DEK.
   */
  async decryptString(ciphertextB64, nonceB64, dekKey) {
    const cipherBuffer = this.base64ToArrayBuffer(ciphertextB64);
    const iv = new Uint8Array(this.base64ToArrayBuffer(nonceB64));

    const decryptedBuffer = await this.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      dekKey,
      cipherBuffer
    );

    const dec = new TextDecoder();
    return dec.decode(decryptedBuffer);
  }

  /**
   * Encrypts an ArrayBuffer of file bytes with AES-256-GCM.
   */
  async encryptBuffer(arrayBuffer, dekKey) {
    const iv = this.generateRandomBytes(12);
    const cipherBuffer = await this.crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      dekKey,
      arrayBuffer
    );
    return {
      ciphertext: this.arrayBufferToBase64(cipherBuffer),
      nonce: this.arrayBufferToBase64(iv)
    };
  }

  /**
   * Decrypts an AES-256-GCM encrypted file buffer.
   */
  async decryptBuffer(ciphertextB64, nonceB64, dekKey) {
    const cipherBuffer = this.base64ToArrayBuffer(ciphertextB64);
    const iv = new Uint8Array(this.base64ToArrayBuffer(nonceB64));
    return await this.crypto.subtle.decrypt(
      { name: "AES-GCM", iv: iv },
      dekKey,
      cipherBuffer
    );
  }

  /**
   * Generates a per-user HMAC-SHA256 hash of a document number for duplicate detection
   * without storing plaintext.
   */
  async generateDocumentHash(rawNumber, userSalt) {
    const cleaned = rawNumber.trim().replace(/\s+/g, '').replace(/-/g, '').toUpperCase();
    const enc = new TextEncoder();

    let saltBytes;
    try {
      saltBytes = new Uint8Array(this.base64ToArrayBuffer(userSalt));
    } catch (e) {
      saltBytes = new Uint8Array(userSalt.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
    }

    const hmacKey = await this.crypto.subtle.importKey(
      "raw",
      saltBytes,
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["sign"]
    );

    const signature = await this.crypto.subtle.sign(
      "HMAC",
      hmacKey,
      enc.encode(cleaned)
    );

    return Array.from(new Uint8Array(signature)).map(b => b.toString(16).padStart(2, '0')).join('');
  }
}

// Export singleton instance
window.webCrypto = new WebCryptoService();
