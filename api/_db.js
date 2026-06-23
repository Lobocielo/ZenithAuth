// Database connection module for Neon Postgres (serverless)
const { neon } = require("@neondatabase/serverless");

let sql;

function getDb() {
  if (!sql) {
    if (!process.env.DATABASE_URL) {
      throw new Error("DATABASE_URL environment variable is not set. Add it in Vercel Dashboard > Settings > Environment Variables.");
    }
    sql = neon(process.env.DATABASE_URL);
  }
  return sql;
}

// Initialize database tables on first call
async function initDb() {
  const sql = getDb();

  await sql`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      username VARCHAR(50) UNIQUE NOT NULL,
      password VARCHAR(255) NOT NULL,
      role VARCHAR(10) DEFAULT 'client' CHECK (role IN ('owner', 'admin', 'client')),
      hwid VARCHAR(255) DEFAULT NULL,
      license_key VARCHAR(100) DEFAULT NULL,
      is_banned BOOLEAN DEFAULT FALSE,
      expiry_date TIMESTAMPTZ DEFAULT NULL,
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  await sql`
    CREATE TABLE IF NOT EXISTS licenses (
      id SERIAL PRIMARY KEY,
      license_key VARCHAR(100) UNIQUE NOT NULL,
      duration_days INT DEFAULT 0,
      is_used BOOLEAN DEFAULT FALSE,
      created_by VARCHAR(50) DEFAULT 'owner',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  return sql;
}

module.exports = { getDb, initDb };
