const pool = require('../config/db');

exports.listAudit = async (req, res) => {
  try {
    const { user_id, role, action_type, from, to, limit = 100 } = req.query;
    let sql = 'SELECT * FROM AuditLog WHERE 1=1';
    const params = [];

    if (user_id) { sql += ' AND user_id = ?'; params.push(user_id); }
    if (role) { sql += ' AND role = ?'; params.push(role); }
    if (action_type) { sql += ' AND action_type = ?'; params.push(action_type); }
    if (from) { sql += ' AND timestamp >= ?'; params.push(from); }
    if (to) { sql += ' AND timestamp <= ?'; params.push(to); }

    sql += ' ORDER BY timestamp DESC LIMIT ?';
    params.push(parseInt(limit));

    const [rows] = await pool.query(sql, params);
    res.json(rows);
  } catch (err) {
    console.error('listAudit error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
