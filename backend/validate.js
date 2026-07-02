// validate.js
// Small helper functions to check and clean up user input before it
// touches the database. This protects against bad data, extremely
// long spam text, and basic script-injection attempts.

function isValidEmail(email) {
  if (!email || typeof email !== "string") return false;
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim());
}

// Accepts Pakistani-style numbers like 03001234567, +923001234567, 0300-1234567
function isValidPhone(phone) {
  if (!phone || typeof phone !== "string") return false;
  const digits = phone.replace(/[\s\-]/g, "");
  return /^(\+92|0)[0-9]{10}$/.test(digits);
}

// Removes < and > (blocks basic HTML/script injection) and trims
// extra whitespace, then cuts the text down to a maximum length.
function sanitizeText(text, maxLen = 500) {
  if (text === undefined || text === null) return "";
  let clean = String(text).replace(/[<>]/g, "").trim();
  if (clean.length > maxLen) clean = clean.slice(0, maxLen);
  return clean;
}

function isValidPassword(password) {
  return typeof password === "string" && password.length >= 6;
}

function isPositiveNumber(value) {
  const n = Number(value);
  return !isNaN(n) && n > 0;
}

const ALLOWED_PAYMENT_METHODS = ["Bank", "JazzCash", "Easypaisa", "COD"];

module.exports = {
  isValidEmail,
  isValidPhone,
  sanitizeText,
  isValidPassword,
  isPositiveNumber,
  ALLOWED_PAYMENT_METHODS
};
