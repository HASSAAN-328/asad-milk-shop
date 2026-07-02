// server.js
// Main backend server for Asad Milk Shop
// Handles: Signup, Login, Orders (registered customers only), Contact messages
// Serves the frontend (HTML/CSS/JS) as static files.
//
// SECURITY FEATURES:
//  - Passwords hashed with bcrypt
//  - Login sessions use signed JWT tokens
//  - Placing an order REQUIRES a logged-in account (requireAuth)
//  - Rate limiting on login/signup/order/contact to block spam & brute force
//  - Server-side input validation & sanitization on every field
//  - Sensitive payment details (account numbers, IBAN) encrypted before saving
//  - Security HTTP headers via helmet, including HSTS (forces HTTPS)
//  - Automatic redirect from HTTP -> HTTPS when running in production
//  - Generic login error messages (does not reveal whether an email exists)
//
// SCALE:
//  - Database access goes through database.js, which automatically
//    uses PostgreSQL when deployed (DATABASE_URL is set) instead of
//    the local SQLite file. This is what allows more than one copy
//    of this server to run at once behind a load balancer - every
//    copy shares the same central database. Login sessions are
//    stateless JWT tokens (not stored on the server), so any server
//    instance can handle any request - nothing "sticky" to one server.

require("dotenv").config();
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const bcrypt = require("bcryptjs");
const path = require("path");

const db = require("./database");
const { generateToken, requireAuth } = require("./auth");
const { encrypt } = require("./crypto-util");
const {
  isValidEmail, isValidPhone, sanitizeText,
  isValidPassword, isPositiveNumber, ALLOWED_PAYMENT_METHODS
} = require("./validate");

const app = express();
const PORT = process.env.PORT || 3000;
const isProduction = process.env.NODE_ENV === "production";

// When deployed behind a hosting provider's proxy/load balancer
// (Render, Railway, Nginx, etc.), this tells Express to trust the
// "X-Forwarded-*" headers so it can correctly detect the visitor's
// real IP address and whether their original request was HTTPS.
// Needed for the HTTPS redirect below and for rate limiting to work
// correctly once this app runs behind a proxy.
app.set("trust proxy", 1);

// ---------------------------------------------------------
// FORCE HTTPS (production only)
// Hosting providers like Render/Railway already give you a free
// HTTPS certificate and handle the encryption for you - but traffic
// reaches your app internally as plain HTTP. This middleware makes
// sure that if a visitor ever reaches the site over plain HTTP
// (e.g. typed "http://" by hand, or an old bookmark), they are
// immediately redirected to the secure "https://" version.
// ---------------------------------------------------------
if (isProduction) {
  app.use((req, res, next) => {
    if (req.secure || req.headers["x-forwarded-proto"] === "https") {
      return next();
    }
    return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
  });
}

// Security headers. CSP is disabled because this project intentionally
// uses simple inline <script> tags in the HTML pages for easy learning -
// for a real production launch, scripts should be moved to external
// files and a strict CSP re-enabled.
// HSTS tells browsers "always use HTTPS for this website from now on,
// for the next year, even if someone types http:// by mistake."
app.use(helmet({
  contentSecurityPolicy: false,
  hsts: isProduction
    ? { maxAge: 31536000, includeSubDomains: true, preload: true }
    : false
}));
app.use(cors());
app.use(express.json({ limit: "50kb" })); // reject unusually large payloads

// ---------------------------------------------------------
// RATE LIMITERS - block scripted abuse / brute force attempts
// ---------------------------------------------------------
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10,
  message: { success: false, message: "Too many attempts. Please try again in 15 minutes." },
  standardHeaders: true,
  legacyHeaders: false
});

const orderLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  message: { success: false, message: "Too many orders submitted. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false
});

const contactLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  message: { success: false, message: "Too many messages sent. Please try again later." },
  standardHeaders: true,
  legacyHeaders: false
});

// Serve the frontend folder (index.html, css, js, images, other pages)
const frontendPath = path.join(__dirname, "..", "frontend");
app.use(express.static(frontendPath));

// -------------------------------------------------------
// SIGNUP
// -------------------------------------------------------
app.post("/api/signup", authLimiter, async (req, res) => {
  try {
    let { full_name, email, phone, password } = req.body;

    full_name = sanitizeText(full_name, 100);
    email = sanitizeText(email, 150).toLowerCase();
    phone = sanitizeText(phone, 20);

    if (!full_name || full_name.length < 2) {
      return res.status(400).json({ success: false, message: "Please enter your full name." });
    }
    if (!isValidEmail(email)) {
      return res.status(400).json({ success: false, message: "Please enter a valid email address." });
    }
    if (phone && !isValidPhone(phone)) {
      return res.status(400).json({ success: false, message: "Please enter a valid Pakistani phone number." });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ success: false, message: "Password must be at least 6 characters long." });
    }

    const existing = await db.get("SELECT id FROM users WHERE email = ?", [email]);
    if (existing) {
      return res.status(400).json({ success: false, message: "An account with this email already exists." });
    }

    const password_hash = bcrypt.hashSync(password, 12);

    const info = await db.run(
      "INSERT INTO users (full_name, email, phone, password_hash) VALUES (?, ?, ?, ?)",
      [full_name, email, phone || "", password_hash]
    );

    const user = { id: info.lastInsertRowid, full_name, email };
    const token = generateToken(user);

    return res.json({
      success: true,
      message: "Account created successfully!",
      token,
      user
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error during signup." });
  }
});

// -------------------------------------------------------
// LOGIN
// -------------------------------------------------------
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    let { email, password } = req.body;
    email = sanitizeText(email, 150).toLowerCase();

    // Same generic error message whether the email doesn't exist or the
    // password is wrong - this stops attackers from "guessing" which
    // emails are registered on the site (user enumeration).
    const genericError = { success: false, message: "Incorrect email or password." };

    if (!isValidEmail(email) || !password) {
      return res.status(400).json(genericError);
    }

    const user = await db.get("SELECT * FROM users WHERE email = ?", [email]);
    if (!user) {
      return res.status(400).json(genericError);
    }

    const valid = bcrypt.compareSync(password, user.password_hash);
    if (!valid) {
      return res.status(400).json(genericError);
    }

    const safeUser = { id: user.id, full_name: user.full_name, email: user.email };
    const token = generateToken(safeUser);

    return res.json({
      success: true,
      message: "Login successful!",
      token,
      user: safeUser
    });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error during login." });
  }
});

// -------------------------------------------------------
// PLACE ORDER  (registered & logged-in customers ONLY)
// -------------------------------------------------------
app.post("/api/orders", orderLimiter, requireAuth, async (req, res) => {
  try {
    let {
      customer_name, phone, address,
      product_name, unit, unit_price, quantity, total_price,
      payment_method, payment_account_title, payment_account_number,
      payment_bank_name, payment_iban
    } = req.body;

    customer_name = sanitizeText(customer_name, 100);
    phone = sanitizeText(phone, 20);
    address = sanitizeText(address, 300);
    product_name = sanitizeText(product_name, 100);
    unit = sanitizeText(unit, 30);
    payment_method = sanitizeText(payment_method, 20);
    payment_account_title = sanitizeText(payment_account_title, 100);
    payment_bank_name = sanitizeText(payment_bank_name, 100);

    if (!customer_name || !phone || !address) {
      return res.status(400).json({ success: false, message: "Please fill in your name, phone and address." });
    }
    if (!isValidPhone(phone)) {
      return res.status(400).json({ success: false, message: "Please enter a valid Pakistani phone number." });
    }
    if (!product_name || !unit) {
      return res.status(400).json({ success: false, message: "Invalid product." });
    }
    if (!isPositiveNumber(unit_price) || !isPositiveNumber(quantity) || !isPositiveNumber(total_price)) {
      return res.status(400).json({ success: false, message: "Invalid quantity or price." });
    }
    if (quantity > 1000) {
      return res.status(400).json({ success: false, message: "Quantity is too large. Please contact us directly for bulk/event orders." });
    }
    // Recalculate the total on the server - never trust a price sent from the browser
    const expectedTotal = Math.round(unit_price * quantity * 100) / 100;
    if (Math.abs(expectedTotal - Number(total_price)) > 1) {
      return res.status(400).json({ success: false, message: "Price mismatch detected. Please refresh and try again." });
    }
    if (!ALLOWED_PAYMENT_METHODS.includes(payment_method)) {
      return res.status(400).json({ success: false, message: "Please select a valid payment method." });
    }

    // Encrypt sensitive payment details before saving to the database
    const encryptedAccountNumber = encrypt(sanitizeText(payment_account_number, 60));
    const encryptedIban = encrypt(sanitizeText(payment_iban, 60));

    const info = await db.run(
      `INSERT INTO orders
      (user_id, customer_name, phone, address, product_name, unit, unit_price, quantity, total_price,
       payment_method, payment_account_title, payment_account_number, payment_bank_name, payment_iban)
      VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
      [
        req.user.id,
        customer_name, phone, address,
        product_name, unit, unit_price, quantity, expectedTotal,
        payment_method,
        payment_account_title || "",
        encryptedAccountNumber,
        payment_bank_name || "",
        encryptedIban
      ]
    );

    return res.json({ success: true, message: "Order placed successfully!", orderId: info.lastInsertRowid });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error while placing order." });
  }
});

// -------------------------------------------------------
// CONTACT US / COMPLAINT MESSAGE
// -------------------------------------------------------
app.post("/api/contact", contactLimiter, async (req, res) => {
  try {
    let { name, email, phone, message } = req.body;

    name = sanitizeText(name, 100);
    email = sanitizeText(email, 150);
    phone = sanitizeText(phone, 20);
    message = sanitizeText(message, 1000);

    if (!name || !message) {
      return res.status(400).json({ success: false, message: "Please enter your name and message." });
    }
    if (email && !isValidEmail(email)) {
      return res.status(400).json({ success: false, message: "Please enter a valid email address." });
    }

    await db.run(
      "INSERT INTO messages (name, email, phone, message) VALUES (?, ?, ?, ?)",
      [name, email || "", phone || "", message]
    );

    return res.json({ success: true, message: "Thank you! Your message has been received." });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ success: false, message: "Server error while sending message." });
  }
});

// Fallback: send index.html for any unknown route (nice for direct links)
app.get("*", (req, res, next) => {
  if (req.path.startsWith("/api")) return next();
  res.sendFile(path.join(frontendPath, "index.html"));
});

// ---------------------------------------------------------
// START THE SERVER
// The database (SQLite or PostgreSQL, whichever applies) must be
// ready BEFORE we start accepting requests, so we wait for
// initSchema() to finish first.
//
// On Vercel, the platform itself calls this file as a "serverless
// function" for every request instead of us calling app.listen() -
// Vercel runs and manages the web server for us. So we only call
// app.listen() when running locally on your own computer (or on a
// normal host like Render). Either way, initSchema() still runs to
// make sure the database tables exist.
// ---------------------------------------------------------
let schemaReady = null;
function ensureSchema() {
  if (!schemaReady) schemaReady = db.initSchema();
  return schemaReady;
}

if (process.env.VERCEL) {
  // Running on Vercel: just make sure the schema is ready, then let
  // Vercel handle incoming requests by using "app" directly below.
  ensureSchema().catch((err) => console.error("Failed to set up the database:", err));
} else {
  // Running locally, or on Render/any normal Node host: start a
  // real, always-on web server the traditional way.
  ensureSchema()
    .then(() => {
      app.listen(PORT, () => {
        console.log(`\n===========================================`);
        console.log(` Asad Milk Shop server is running!`);
        console.log(` Open this in your browser: http://localhost:${PORT}`);
        console.log(` Database: ${db.usingPostgres ? "PostgreSQL (production)" : "SQLite (local testing)"}`);
        console.log(` HTTPS redirect: ${isProduction ? "ON" : "OFF (only enabled when NODE_ENV=production)"}`);
        console.log(`===========================================\n`);
      });
    })
    .catch((err) => {
      console.error("Failed to set up the database:", err);
      process.exit(1);
    });
}

module.exports = app;
