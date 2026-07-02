// database.js
// Handles ALL database work for Asad Milk Shop.
//
// Automatically picks the right database:
//   - If a DATABASE_URL environment variable is present (hosting
//     providers like Render/Railway set this automatically when you
//     add a PostgreSQL database) -> uses PostgreSQL.
//   - Otherwise (running on your own computer for testing) -> uses
//     the simple built-in SQLite file, exactly like before. No setup
//     needed for local testing.
//
// WHY THIS MATTERS FOR SCALE:
// SQLite stores everything in ONE file on ONE computer, so only a
// single server can use it. PostgreSQL is a real database SERVER
// that many app servers can connect to at the same time - this is
// required if you ever run more than one copy of this website behind
// a load balancer to handle heavy traffic.

const path = require("path");
const usingPostgres = !!process.env.DATABASE_URL;

let pool = null;       // used only in PostgreSQL mode
let sqliteDb = null;   // used only in SQLite mode

// Turns "SELECT * FROM users WHERE email = ?" into
// "SELECT * FROM users WHERE email = $1"
// (SQLite uses "?" placeholders, PostgreSQL uses "$1, $2, ...")
function toPgPlaceholders(sql) {
  let i = 0;
  return sql.replace(/\?/g, () => `$${++i}`);
}

if (usingPostgres) {
  const { Pool } = require("pg");
  pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    // Most hosted Postgres providers (Render, Railway, Supabase, etc.)
    // require SSL but use a certificate Node doesn't automatically
    // trust, so we relax that one check. The connection is still
    // fully encrypted either way.
    ssl: { rejectUnauthorized: false },
    max: 20 // max simultaneous connections in the pool - raise this later if you scale up
  });
} else {
  const { DatabaseSync } = require("node:sqlite");
  sqliteDb = new DatabaseSync(path.join(__dirname, "asadmilkshop.db"));
}

// ---------------------------------------------------------
// LOW-LEVEL HELPERS - same shape no matter which database is active,
// so the rest of the app (server.js) never needs to know or care
// which one is running underneath.
// ---------------------------------------------------------

// Run a query that returns ONE row (or undefined if none found)
async function get(sql, params = []) {
  if (usingPostgres) {
    const result = await pool.query(toPgPlaceholders(sql), params);
    return result.rows[0];
  }
  return sqliteDb.prepare(sql).get(...params);
}

// Run a query that returns MANY rows
async function all(sql, params = []) {
  if (usingPostgres) {
    const result = await pool.query(toPgPlaceholders(sql), params);
    return result.rows;
  }
  return sqliteDb.prepare(sql).all(...params);
}

// Run an INSERT / UPDATE / DELETE. Returns the new row's id when inserting.
async function run(sql, params = []) {
  if (usingPostgres) {
    let pgSql = toPgPlaceholders(sql);
    // Postgres doesn't automatically hand back the new row's id like
    // SQLite does - we ask for it explicitly with RETURNING id.
    if (/^\s*insert/i.test(pgSql) && !/returning/i.test(pgSql)) {
      pgSql += " RETURNING id";
    }
    const result = await pool.query(pgSql, params);
    return {
      lastInsertRowid: result.rows[0] ? result.rows[0].id : undefined,
      changes: result.rowCount
    };
  }
  const info = sqliteDb.prepare(sql).run(...params);
  return { lastInsertRowid: info.lastInsertRowid, changes: info.changes };
}

// ---------------------------------------------------------
// CREATE TABLES (runs once when the server starts, safe to re-run)
// ---------------------------------------------------------
async function initSchema() {
  if (usingPostgres) {
    await pool.query(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER NOT NULL REFERENCES users(id),
        customer_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        address TEXT NOT NULL,
        product_name TEXT NOT NULL,
        unit TEXT NOT NULL,
        unit_price REAL NOT NULL,
        quantity REAL NOT NULL,
        total_price REAL NOT NULL,
        payment_method TEXT NOT NULL,
        payment_account_title TEXT,
        payment_account_number TEXT,
        payment_bank_name TEXT,
        payment_iban TEXT,
        order_status TEXT DEFAULT 'Pending',
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    await pool.query(`
      CREATE TABLE IF NOT EXISTS messages (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        message TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);
    console.log(" Connected to PostgreSQL database (production mode).");
  } else {
    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        full_name TEXT NOT NULL,
        email TEXT NOT NULL UNIQUE,
        phone TEXT,
        password_hash TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );
    `);
    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        customer_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        address TEXT NOT NULL,
        product_name TEXT NOT NULL,
        unit TEXT NOT NULL,
        unit_price REAL NOT NULL,
        quantity REAL NOT NULL,
        total_price REAL NOT NULL,
        payment_method TEXT NOT NULL,
        payment_account_title TEXT,
        payment_account_number TEXT,
        payment_bank_name TEXT,
        payment_iban TEXT,
        order_status TEXT DEFAULT 'Pending',
        created_at TEXT DEFAULT (datetime('now')),
        FOREIGN KEY (user_id) REFERENCES users(id)
      );
    `);
    sqliteDb.exec(`
      CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT,
        phone TEXT,
        message TEXT NOT NULL,
        created_at TEXT DEFAULT (datetime('now'))
      );
    `);
    console.log(" Using local SQLite database file (asadmilkshop.db) - testing mode.");
  }
}

module.exports = { get, all, run, initSchema, usingPostgres };
