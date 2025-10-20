// controllers/policyController.js
const pool = require('../config/db');
const logAction = require('../utils/logAction');

exports.getLatestPolicy = async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM Policy ORDER BY version DESC LIMIT 1');
    if (!rows.length) return res.status(404).json({ error: 'No policy found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getLatestPolicy error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.listPolicies = async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM Policy ORDER BY version DESC');
    res.json(rows);
  } catch (err) {
    console.error('listPolicies error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.acceptPolicy = async (req, res) => {
  try {
    let { policy_id } = req.body || {};
    if (!policy_id) {
      const [rows] = await pool.query('SELECT policy_id FROM Policy ORDER BY version DESC LIMIT 1');
      if (!rows.length) return res.status(404).json({ error: 'No policy available to accept' });
      policy_id = rows[0].policy_id;
    }

    await pool.query('INSERT INTO PolicyAcceptance (user_id, policy_id, timestamp) VALUES (?, ?, NOW())', [
      req.user.id,
      policy_id
    ]);
    await logAction(req.user.id, req.user.role, req.ip, 'POLICY_ACCEPT', { policy_id });
    res.json({ message: 'Policy accepted successfully' });
  } catch (err) {
    console.error('acceptPolicy error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.createPolicy = async (req, res) => {
  try {
    const { policy_text } = req.body;
    const [r] = await pool.query('SELECT COALESCE(MAX(version), 0) AS v FROM Policy');
    const version = (r[0].v || 0) + 1;
    const [ins] = await pool.query(
      'INSERT INTO Policy (policy_text, version, created_by_admin_id) VALUES (?, ?, ?)',
      [policy_text, version, req.user.id]
    );
    await logAction(req.user.id, req.user.role, req.ip, 'POLICY_CREATE', { policy_id: ins.insertId });
    res.json({ message: 'Policy created successfully', policy_id: ins.insertId });
  } catch (err) {
    console.error('createPolicy error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.deletePolicy = async (req, res) => {
  const policyId = req.params.id;
  try {
    await pool.query('DELETE FROM Policy WHERE policy_id = ?', [policyId]);
    await logAction(req.user.id, req.user.role, req.ip, 'POLICY_DELETE', { policy_id: policyId });
    res.json({ message: 'Policy deleted successfully' });
  } catch (err) {
    console.error('deletePolicy error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
