/**
 * DOCUMENT GUARDIAN - Document Business Rules & Legal Validation
 * Enforces dynamic status rules:
 * - Passport: Issue date and expiry date required. Expiry dynamically calculated.
 * - Aadhaar / PAN: Strictly lifetime validity (no invented expiry dates). Optional review dates.
 */

const DocumentType = {
  PASSPORT: 'Passport',
  AADHAAR: 'Aadhaar',
  PAN: 'PAN'
};

const DocumentStatus = {
  VALID: 'Valid',
  ATTENTION_REQUIRED: 'Attention Required',
  EXPIRED: 'Expired',
  REVIEW_DUE: 'Review Due'
};

const AuditAction = {
  LOGIN_SUCCESS: 'LOGIN_SUCCESS',
  LOGIN_FAILED: 'LOGIN_FAILED',
  LOGOUT: 'LOGOUT',
  PASSWORD_CHANGED: 'PASSWORD_CHANGED',
  DOCUMENT_ADDED: 'DOCUMENT_ADDED',
  DOCUMENT_UPDATED: 'DOCUMENT_UPDATED',
  DOCUMENT_DELETED: 'DOCUMENT_DELETED',
  FILE_UPLOADED: 'FILE_UPLOADED',
  FILE_VIEWED: 'FILE_VIEWED',
  RECORDS_EXPORTED: 'RECORDS_EXPORTED',
  SESSION_LOCKED: 'SESSION_LOCKED',
  SESSION_UNLOCKED: 'SESSION_UNLOCKED'
};

/**
 * Masks sensitive document numbers for safe user interface rendering.
 */
function maskDocumentNumber(docType, rawNumber) {
  if (!rawNumber) return '—';
  const clean = rawNumber.trim().replace(/\s+/g, '').replace(/-/g, '').toUpperCase();

  switch (docType) {
    case DocumentType.AADHAAR:
      if (clean.length === 12) {
        return `XXXX XXXX ${clean.slice(8)}`;
      }
      return clean.length >= 4 ? `XXXX XXXX ${clean.slice(-4)}` : 'XXXX XXXX ****';

    case DocumentType.PAN:
      if (clean.length === 10) {
        return `XXXXX${clean.slice(5, 9)}${clean.slice(9)}`;
      }
      return 'XXXXX****X';

    case DocumentType.PASSPORT:
      if (clean.length >= 8) {
        return `${clean[0]}*****${clean.slice(-2)}`;
      }
      return 'X*****XX';

    default:
      return clean.length > 4 ? `****${clean.slice(-4)}` : '****';
  }
}

/**
 * Validates document input according to national standards and legal rules.
 */
function validateDocumentInput(docType, docNumber, issueDate, expiryDate, reminderDate, reminderDays = 180) {
  const issues = [];
  const cleanNum = (docNumber || '').trim().replace(/\s+/g, '').replace(/-/g, '').toUpperCase();

  if (!cleanNum) {
    issues.push("Document number cannot be empty.");
  }

  // Type specific rules
  if (docType === DocumentType.AADHAAR) {
    if (!/^[2-9][0-9]{11}$/.test(cleanNum)) {
      issues.push("Aadhaar number must be exactly 12 numerical digits (cannot start with 0 or 1).");
    }
    if (expiryDate) {
      issues.push("Aadhaar cards have lifetime validity and do not expire. Expiry dates are legally prohibited.");
    }
  } else if (docType === DocumentType.PAN) {
    if (!/^[A-Z]{5}[0-9]{4}[A-Z]$/.test(cleanNum)) {
      issues.push("PAN must be exactly 10 alphanumeric characters (format: ABCDE1234F).");
    }
    if (expiryDate) {
      issues.push("PAN cards have lifetime validity and do not expire. Expiry dates are legally prohibited.");
    }
  } else if (docType === DocumentType.PASSPORT) {
    if (!/^[A-Z][0-9]{7}$/.test(cleanNum)) {
      issues.push("Passport number must be 1 letter followed by 7 digits (e.g., Z1234567).");
    }
    if (!issueDate) {
      issues.push("Issue date is required for Passport.");
    }
    if (!expiryDate) {
      issues.push("Expiry date is required for Passport.");
    }
  }

  // Calendar validations
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  if (issueDate) {
    const issDt = new Date(issueDate);
    if (isNaN(issDt.getTime())) {
      issues.push("Issue date must be a valid calendar date (YYYY-MM-DD).");
    } else if (issDt > today) {
      issues.push("Issue date cannot be in the future.");
    }
  }

  if (expiryDate) {
    const expDt = new Date(expiryDate);
    if (isNaN(expDt.getTime())) {
      issues.push("Expiry date must be a valid calendar date (YYYY-MM-DD).");
    }
  }

  if (issueDate && expiryDate) {
    const issDt = new Date(issueDate);
    const expDt = new Date(expiryDate);
    if (expDt <= issDt) {
      issues.push("Passport expiry date must be strictly after the issue date.");
    }
  }

  if (reminderDate) {
    const remDt = new Date(reminderDate);
    if (isNaN(remDt.getTime())) {
      issues.push("Review date must be a valid calendar date (YYYY-MM-DD).");
    }
  }

  return {
    isValid: issues.length === 0,
    issues: issues
  };
}

/**
 * Evaluates dynamic status and days remaining for a document without storing computed state.
 */
function analyzeDocumentStatus(doc, referenceDate = new Date()) {
  const refDate = new Date(referenceDate);
  refDate.setHours(0, 0, 0, 0);

  if (doc.document_type === DocumentType.PASSPORT) {
    if (!doc.expiry_date) {
      return {
        status: DocumentStatus.VALID,
        daysRemaining: null,
        displayText: "Valid (No expiry specified)",
        badgeClass: "status-valid"
      };
    }

    const expDate = new Date(doc.expiry_date);
    expDate.setHours(0, 0, 0, 0);

    const diffTime = expDate - refDate;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));
    const windowDays = doc.reminder_days || 180;

    if (diffDays < 0) {
      const overdue = Math.abs(diffDays);
      return {
        status: DocumentStatus.EXPIRED,
        daysRemaining: diffDays,
        displayText: `Expired ${overdue} day${overdue !== 1 ? 's' : ''} ago`,
        badgeClass: "status-expired"
      };
    } else if (diffDays === 0) {
      return {
        status: DocumentStatus.ATTENTION_REQUIRED,
        daysRemaining: 0,
        displayText: "Expires today",
        badgeClass: "status-attention"
      };
    } else if (diffDays <= windowDays) {
      return {
        status: DocumentStatus.ATTENTION_REQUIRED,
        daysRemaining: diffDays,
        displayText: `Expires in ${diffDays} days`,
        badgeClass: "status-attention"
      };
    } else {
      return {
        status: DocumentStatus.VALID,
        daysRemaining: diffDays,
        displayText: `Valid (${diffDays} days remaining)`,
        badgeClass: "status-valid"
      };
    }
  } else {
    // Aadhaar / PAN: Lifetime Validity
    if (!doc.reminder_date) {
      return {
        status: DocumentStatus.VALID,
        daysRemaining: null,
        displayText: "Lifetime Validity",
        badgeClass: "status-valid"
      };
    }

    const remDate = new Date(doc.reminder_date);
    remDate.setHours(0, 0, 0, 0);

    const diffTime = remDate - refDate;
    const diffDays = Math.ceil(diffTime / (1000 * 60 * 60 * 24));

    if (diffDays < 0) {
      const overdue = Math.abs(diffDays);
      return {
        status: DocumentStatus.REVIEW_DUE,
        daysRemaining: diffDays,
        displayText: `Review overdue by ${overdue} day${overdue !== 1 ? 's' : ''}`,
        badgeClass: "status-review"
      };
    } else if (diffDays === 0) {
      return {
        status: DocumentStatus.REVIEW_DUE,
        daysRemaining: 0,
        displayText: "Review due today",
        badgeClass: "status-review"
      };
    } else {
      return {
        status: DocumentStatus.VALID,
        daysRemaining: diffDays,
        displayText: `Valid (Review in ${diffDays} days)`,
        badgeClass: "status-valid"
      };
    }
  }
}
