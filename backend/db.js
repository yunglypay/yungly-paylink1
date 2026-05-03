const { Pool } = require('pg');

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL
    ? { rejectUnauthorized: false }
    : false
});

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    // ── USERS ────────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        id            TEXT PRIMARY KEY,
        name          TEXT NOT NULL,
        display_name  TEXT,
        handle        TEXT UNIQUE,
        phone         TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role          TEXT DEFAULT 'teen',
        parent_id     TEXT,
        wallet_balance    INTEGER DEFAULT 0,
        monthly_received  INTEGER DEFAULT 0,
        monthly_limit     INTEGER DEFAULT 5000,
        kyc_verified      BOOLEAN DEFAULT false,
        guardian_approved BOOLEAN DEFAULT false,
        created_at    TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── PARENTS ──────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS parents (
        id                  TEXT PRIMARY KEY,
        name                TEXT NOT NULL,
        phone               TEXT UNIQUE NOT NULL,
        password_hash       TEXT NOT NULL,
        teen_id             TEXT,
        teen_phone          TEXT,
        per_link_limit      INTEGER DEFAULT 1000,
        daily_limit         INTEGER DEFAULT 2000,
        monthly_limit       INTEGER DEFAULT 5000,
        blocked_categories  TEXT[] DEFAULT ARRAY['adult','gambling','crypto','alcohol','weapons'],
        created_at          TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── SESSIONS (JWT alternative — simple token store) ───────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS sessions (
        token       TEXT PRIMARY KEY,
        user_id     TEXT NOT NULL,
        role        TEXT NOT NULL,
        expires_at  TIMESTAMPTZ NOT NULL,
        created_at  TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── PAYLINKS ─────────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS paylinks (
        id           TEXT PRIMARY KEY,
        creator_id   TEXT NOT NULL,
        display_name TEXT,
        handle       TEXT,
        amount       INTEGER NOT NULL,
        purpose      TEXT NOT NULL,
        note         TEXT,
        status       TEXT DEFAULT 'active',
        txn_id       TEXT,
        expires_at   TIMESTAMPTZ,
        created_at   TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── TRANSACTIONS ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS transactions (
        id                  TEXT PRIMARY KEY,
        link_id             TEXT,
        amount              INTEGER NOT NULL,
        purpose             TEXT,
        from_name           TEXT,
        to_user             TEXT,
        payment_method      TEXT DEFAULT 'UPI',
        razorpay_payment_id TEXT,
        status              TEXT DEFAULT 'success',
        created_at          TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── NOTIFICATIONS ─────────────────────────────────────────────────────────
    await client.query(`
      CREATE TABLE IF NOT EXISTS notifications (
        id         TEXT PRIMARY KEY,
        parent_id  TEXT NOT NULL,
        type       TEXT,
        message    TEXT,
        txn_id     TEXT,
        amount     INTEGER,
        read       BOOLEAN DEFAULT false,
        created_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    // ── SEED ADMIN (only once) ────────────────────────────────────────────────
    const { rows: existing } = await client.query(`SELECT id FROM users WHERE id = 'admin_1'`);
    if (existing.length === 0) {
      // Admin password: "yungly@admin" — hashed manually below
      // bcrypt hash of "yungly@admin" with 10 rounds
      await client.query(`
        INSERT INTO users (id, name, display_name, handle, phone, password_hash, role)
        VALUES ('admin_1','Yungly Admin','Admin','@admin','0000000000',
        '$2b$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', 'admin')
      `);
      console.log('✅ Admin seeded (phone: 0000000000, password: password)');
    }

    await client.query('COMMIT');
    console.log('✅ Database ready');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ DB init error:', err.message);
    throw err;
  } finally {
    client.release();
  }
}

module.exports = { pool, initDB };
