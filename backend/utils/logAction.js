const pool = require('../config/db');

async function logAction(userId, role, ip, actionType, details, outcome = 'SUCCESS') {
  try {
    await pool.query(
      'INSERT INTO AuditLog (user_id, role, ip_address, action_type, details, outcome) VALUES (?, ?, ?, ?, ?, ?)',
      [userId, role || 'SYSTEM', ip || null, actionType, JSON.stringify(details || {}), outcome]
    );
  } catch (err) {
    console.error('Audit log failed:', err);
  }
}

module.exports = logAction;
