// controllers/electionsController.js
const pool = require('../config/db');
const logAction = require('../utils/logAction');
const { genToken, hashToken } = require('../utils/tokenUtils');
const { v4: uuidv4 } = require('uuid');

// create election
exports.createElection = async (req, res) => {
  try {
    const { class_id, nomination_start, nomination_end, voting_start, voting_end } = req.body;
    if (!class_id || !nomination_start || !nomination_end || !voting_start || !voting_end) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    const [result] = await pool.query(
      `INSERT INTO Election (class_id, nomination_start, nomination_end, voting_start, voting_end, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [class_id, nomination_start, nomination_end, voting_start, voting_end, req.user.id]
    );
    await logAction(req.user.id, req.user.role, req.ip, 'CREATE_ELECTION', { election_id: result.insertId });
    res.json({ message: 'Election created', election_id: result.insertId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};


// Update election details
exports.updateElection = async (req, res) => {
  const electionId = req.params.id;
  try {
    const { nomination_start, nomination_end, voting_start, voting_end, is_active } = req.body;
    const [result] = await pool.query(
      `UPDATE Election SET nomination_start=?, nomination_end=?, voting_start=?, voting_end=?, is_active=? WHERE election_id=?`,
      [nomination_start, nomination_end, voting_start, voting_end, is_active, electionId]
    );

    if (result.affectedRows === 0) return res.status(404).json({ error: 'Election not found' });

    await logAction(req.user.id, req.user.role, req.ip, 'UPDATE_ELECTION', { election_id: electionId });
    res.json({ message: 'Election updated successfully' });
  } catch (err) {
    console.error('updateElection error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Get a specific election
exports.getElection = async (req, res) => {
  const electionId = req.params.id;
  try {
    const [rows] = await pool.query('SELECT * FROM Election WHERE election_id = ?', [electionId]);
    if (!rows.length) return res.status(404).json({ error: 'Election not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getElection error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// List all elections (admin or student)
exports.listElections = async (req, res) => {
  try {
    let query = 'SELECT * FROM Election ORDER BY created_at DESC';
    const [rows] = await pool.query(query);
    res.json(rows);
  } catch (err) {
    console.error('listElections error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};



// Activate election: generate VotingToken rows + VoterStatus for students in that class
exports.activateElection = async (req, res) => {
  const electionId = req.params.id;
  try {
    // fetch election and class
    const [eRows] = await pool.query('SELECT * FROM Election WHERE election_id = ?', [electionId]);
    if (!eRows.length) return res.status(404).json({ error: 'Election not found' });
    const election = eRows[0];

    // get students for this class
    const [students] = await pool.query('SELECT student_id, email FROM Student WHERE class_id = ?', [election.class_id]);

    // generate tokens in batch
    const insertVt = [];
    const insertVs = [];
    for (const s of students) {
      const token = genToken();
      const tokenHash = hashToken(token);
      const tokenId = uuidv4();
      insertVt.push([tokenId, s.student_id, electionId, tokenHash]);

      // create voter status
      insertVs.push([s.student_id, electionId, false]);
      // Optionally: email a notification that voting is open (not token)
      // Do not email tokens (we will issue in-session), but you can send notification
    }

    // batch insert
    if (insertVt.length) {
      await pool.query('INSERT INTO VotingToken (token_id, student_id, election_id, token_hash) VALUES ?', [insertVt]);
      await pool.query('INSERT INTO VoterStatus (student_id, election_id, has_voted) VALUES ?', [insertVs]);
    }

    await pool.query('UPDATE Election SET is_active = TRUE WHERE election_id = ?', [electionId]);
    await logAction(req.user.id, req.user.role, req.ip, 'ELECTION_ACTIVATED', { election_id: electionId });
    res.json({ message: 'Election activated' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

// publish results
exports.publishResults = async (req, res) => {
  try {
    const electionId = req.params.id;
    await pool.query('UPDATE Election SET is_published = TRUE, is_active = FALSE WHERE election_id = ?', [electionId]);
    await logAction(req.user.id, req.user.role, req.ip, 'RESULTS_PUBLISHED', { election_id: electionId });
    res.json({ message: 'Results published' });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

// getActiveElectionForClass
exports.getActiveElectionForClass = async (req, res) => {
  try {
    const classId = req.params.classId;
    const [rows] = await pool.query(
      `SELECT * FROM Election WHERE class_id = ? AND is_active = TRUE ORDER BY created_at DESC LIMIT 1`,
      [classId]
    );
    if (!rows.length) return res.status(404).json({ error: 'No active election' });
    res.json(rows[0]);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

// listElections, updateElection, getElection etc - implement similarly
