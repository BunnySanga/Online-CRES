const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const path = require('path');
// Always load env from backend/.env when running from repo root
require('dotenv').config({ path: path.resolve(__dirname, '../.env') });

/*
 * Database Connection Pool
 * 
 * This module creates and exports a MySQL connection pool for the application. It uses the
 * mysql2 library to provide promise-based connections. The pool is configured using environment
 * variables and includes a startup test to verify connectivity.
 * 
 * Exports:
 * - pool: A promise-based MySQL connection pool.
 * 
 * Notes:
 * - Ensure the .env file contains the necessary DB_* variables.
 * - The startup test logs a success or error message based on the connection status.
 */

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT || 3306,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  // SSL configuration for cloud databases like Railway
  ssl: process.env.NODE_ENV === 'production' ? {
    rejectUnauthorized: false
  } : false
});

async function bootstrapDefaultAdmin() {
  try {
    const [rows] = await pool.query('SELECT COUNT(*) AS count FROM Admin');
    if (rows[0] && rows[0].count === 0) {
      const hashedPassword = await bcrypt.hash('Admin@123', 10);
      await pool.query(
        'INSERT INTO Admin (admin_id, name, email, password_hash) VALUES (?, ?, ?, ?)',
        ['admin001', 'Default Admin', 'admin@example.com', hashedPassword]
      );
      console.log('Default admin created successfully');
    }
  } catch (err) {
    console.warn('Skipping default admin bootstrap:', err.message);
  }
}

(async () => {
  try {
    const conn = await pool.getConnection();
    console.log('MySQL connected successfully');
    conn.release();
    // Attempt to ensure a default admin exists
    await bootstrapDefaultAdmin();
  } catch (err) {
    console.error('MySQL connection error:', err.message);
  }
})();

module.exports = pool;
