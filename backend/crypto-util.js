// crypto-util.js
// Encrypts and decrypts sensitive text (like bank account numbers and
// IBAN numbers) before they are stored in the database, so that even
// if someone opens the database file directly, they cannot read the
// raw account numbers.
//
// Uses Node's built-in "crypto" module (AES-256-GCM) - no extra
// package needs to be installed for this.

const crypto = require("crypto");

const ALGORITHM = "aes-256-gcm";
const RAW_KEY = process.env.ENCRYPTION_KEY || "fallback_dev_key_change_me";
// Always turn the key into exactly 32 bytes (required by AES-256)
const KEY = crypto.createHash("sha256").update(String(RAW_KEY)).digest();

function encrypt(text) {
  if (text === undefined || text === null || text === "") return "";
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, KEY, iv);
  let encrypted = cipher.update(String(text), "utf8", "hex");
  encrypted += cipher.final("hex");
  const authTag = cipher.getAuthTag().toString("hex");
  // Store iv + authTag + encrypted text together, separated by ":"
  return iv.toString("hex") + ":" + authTag + ":" + encrypted;
}

function decrypt(data) {
  if (!data) return "";
  try {
    const [ivHex, authTagHex, encrypted] = data.split(":");
    if (!ivHex || !authTagHex || !encrypted) return "";
    const iv = Buffer.from(ivHex, "hex");
    const authTag = Buffer.from(authTagHex, "hex");
    const decipher = crypto.createDecipheriv(ALGORITHM, KEY, iv);
    decipher.setAuthTag(authTag);
    let decrypted = decipher.update(encrypted, "hex", "utf8");
    decrypted += decipher.final("utf8");
    return decrypted;
  } catch (err) {
    return ""; // If it can't be decrypted (corrupted/old data), fail safely
  }
}

// Shows only the last 4 characters, for safely displaying references
// e.g. maskAccountNumber("PK36SCBL0000001123456702") -> "•••• •••• 6702"
function maskLast4(text) {
  if (!text) return "";
  const clean = String(text).replace(/\s/g, "");
  if (clean.length <= 4) return clean;
  return "•••• •••• " + clean.slice(-4);
}

module.exports = { encrypt, decrypt, maskLast4 };
