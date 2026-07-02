// auth.js
// Handles creating and checking login tokens (JWT) so that we can
// require customers to be logged in before placing an order.

const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET || "fallback_dev_secret_change_me";
const TOKEN_EXPIRY = "7d"; // customer stays logged in for 7 days

function generateToken(user) {
  return jwt.sign(
    { id: user.id, email: user.email, full_name: user.full_name },
    JWT_SECRET,
    { expiresIn: TOKEN_EXPIRY }
  );
}

// Middleware: blocks the request unless a valid login token is sent.
// Used to protect the "place order" endpoint so only registered,
// logged-in customers can order.
function requireAuth(req, res, next) {
  const authHeader = req.headers["authorization"] || "";
  const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : null;

  if (!token) {
    return res.status(401).json({
      success: false,
      code: "NO_TOKEN",
      message: "Please login to your account before placing an order."
    });
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({
      success: false,
      code: "INVALID_TOKEN",
      message: "Your session has expired. Please login again."
    });
  }
}

module.exports = { generateToken, requireAuth };
