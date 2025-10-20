// controllers/nominationsController.js
const pool = require('../config/db');
const logAction = require('../utils/logAction');
exports.submitNomination = async (req, res) => {
  try {
    const { election_id, manifesto, photo_url} = req.body;
    const studentId = req.user.id;
    // check nomination window
    console.log(election_id);
    const [eRows] = await pool.query('SELECT * FROM election WHERE election_id = ?', [election_id]);
    if (!eRows.length) return res.status(404).json({ error: 'Election not found' });
    const e = eRows[0];
    const now = new Date();
    if (now < new Date(e.nomination_start) || now > new Date(e.nomination_end)) {
      return res.status(400).json({ error: 'Nomination window closed' });
    }

    // ensure policy accepted (fetch latest policy id)
    const [policyRows] = await pool.query('SELECT * FROM Policy ORDER BY version DESC LIMIT 1');
    if (policyRows.length) {
      const policyId = policyRows[0].policy_id;
      const [accepted] = await pool.query('SELECT * FROM PolicyAcceptance WHERE user_id = ? AND policy_id = ?', [studentId, policyId]);
      if (!accepted.length) return res.status(403).json({ error: 'Policy must be accepted before nomination' });
    }

    await pool.query('INSERT INTO Nomination (election_id, student_id, manifesto, photo_url) VALUES (?, ?, ?, ?)', [election_id, studentId, manifesto, photo_url]);
    await logAction(studentId, req.user.role, req.ip, 'NOMINATION_SUBMITTED', { election_id });
    res.json({ message: 'Nomination submitted' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.listByElection = async (req, res) => {
  const electionId = req.params.electionId;
  try {
    const [rows] = await pool.query('SELECT * FROM Nomination WHERE election_id = ?', [electionId]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.approveNomination = async (req, res) => {
  const id = req.params.id;
  try {
    await pool.query('UPDATE Nomination SET status = ?, reviewed_by_admin_id = ?, reviewed_at = NOW() WHERE nomination_id = ?', ['APPROVED', req.user.id, id]);
    await logAction(req.user.id, req.user.role, req.ip, 'NOMINATION_APPROVE', { nomination_id: id });
    res.json({ message: 'Nomination approved' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.rejectNomination = async (req, res) => {
  const id = req.params.id;
  const { reason } = req.body;
  try {
    await pool.query('UPDATE Nomination SET status = ?, reviewed_by_admin_id = ?, reviewed_at = NOW(), rejection_reason = ? WHERE nomination_id = ?', ['REJECTED', req.user.id, reason, id]);
    await logAction(req.user.id, req.user.role, req.ip, 'NOMINATION_REJECT', { nomination_id: id, reason });
    res.json({ message: 'Nomination rejected' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};
