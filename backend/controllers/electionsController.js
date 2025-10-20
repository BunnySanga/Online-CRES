// controllers/electionsController.js
const pool = require('../config/db');
const logAction = require('../utils/logAction');
const { genToken, hashToken } = require('../utils/tokenUtils');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');

exports.createElection = async (req, res) => {
  try {
    const { class_id, nomination_start, nomination_end, voting_start, voting_end } = req.body;
    if (!class_id || !nomination_start || !nomination_end || !voting_start || !voting_end) {
      return res.status(400).json({ error: 'Missing fields' });
    }
    // validate time order (strict)
    const ns = new Date(nomination_start), ne = new Date(nomination_end), vs = new Date(voting_start), ve = new Date(voting_end);
    if (!(ns < ne && ne < vs && vs < ve)) {
      return res.status(400).json({ error: 'Invalid timeline: ensure nomination_start < nomination_end < voting_start < voting_end' });
    }
    // validate class exists
    const [cRows] = await pool.query('SELECT 1 FROM Class WHERE class_id = ? LIMIT 1', [class_id]);
    if (!cRows.length) return res.status(400).json({ error: 'Class not found' });

    // enforce: no overlapping elections for the same class between nomination_start and voting_end
    const [overlaps] = await pool.query(
      `SELECT election_id FROM Election
       WHERE class_id = ?
         AND NOT (voting_end < ? OR nomination_start > ?)`,
      [class_id, nomination_start, voting_end]
    );
    if (overlaps.length) {
      return res.status(400).json({ error: 'Another election overlaps this timeline for this class. Complete current election before creating a new one.' });
    }
    const [result] = await pool.query(
      `INSERT INTO Election (class_id, nomination_start, nomination_end, voting_start, voting_end, created_by_admin_id) VALUES (?, ?, ?, ?, ?, ?)`,
      [class_id, nomination_start, nomination_end, voting_start, voting_end, req.user.id]
    );
    // ensure not active by default regardless of DB defaults
    await pool.query('UPDATE Election SET is_active = FALSE, is_published = FALSE WHERE election_id = ?', [result.insertId]);
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
    if (nomination_start && nomination_end && voting_start && voting_end) {
      const ns = new Date(nomination_start), ne = new Date(nomination_end), vs = new Date(voting_start), ve = new Date(voting_end);
      if (!(ns < ne && ne < vs && vs < ve)) {
        return res.status(400).json({ error: 'Invalid timeline: ensure nomination_start < nomination_end < voting_start < voting_end' });
      }
      // Enforce updated timeline does not overlap another election for the same class
      const [[curr]] = await pool.query('SELECT class_id FROM Election WHERE election_id = ?', [electionId]);
      if (!curr) return res.status(404).json({ error: 'Election not found' });
      const [overlaps] = await pool.query(
        `SELECT election_id FROM Election
         WHERE class_id = ? AND election_id <> ?
           AND NOT (voting_end < ? OR nomination_start > ?)`,
        [curr.class_id, electionId, nomination_start, voting_end]
      );
      if (overlaps.length) {
        return res.status(400).json({ error: 'Updated timeline overlaps another election for this class.' });
      }
    }
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

    // prevent double activation
    if (election.is_active) {
      return res.status(400).json({ error: 'Election already active' });
    }

    // ensure no other active election exists for this class
    const [existsActive] = await pool.query('SELECT 1 FROM Election WHERE class_id = ? AND is_active = TRUE AND election_id <> ? LIMIT 1', [election.class_id, electionId]);
    if (existsActive.length) return res.status(400).json({ error: 'Another election is already active for this class' });

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

exports.publishResults = async (req, res) => {
  try {
    const electionId = req.params.id;
    // ensure voting has ended before publishing
    const [[eInfo]] = await pool.query('SELECT class_id, voting_end FROM Election WHERE election_id = ?', [electionId]);
    if (!eInfo) return res.status(404).json({ error: 'Election not found' });
    if (new Date() <= new Date(eInfo.voting_end)) {
      return res.status(400).json({ error: 'Cannot publish results before voting ends' });
    }
    // compute winner to notify
    const [countRows] = await pool.query(
      `SELECT v.candidate_id, COUNT(*) AS votes
       FROM VoteAnonymous v
       WHERE v.election_id = ?
       GROUP BY v.candidate_id
       ORDER BY votes DESC`, [electionId]
    );

    let outcome = 'NO_VOTES';
    let winnerId = null;
    if (countRows.length > 0) {
      const topVotes = countRows[0].votes;
      const tie = countRows.filter(r => r.votes === topVotes).length > 1;
      if (topVotes === 0) outcome = 'NO_VOTES';
      else if (tie) outcome = 'TIE';
      else { outcome = 'WINNER'; winnerId = countRows[0].candidate_id; }
    }

    await pool.query('UPDATE Election SET is_published = TRUE, is_active = FALSE WHERE election_id = ?', [electionId]);
    await logAction(req.user.id, req.user.role, req.ip, 'RESULTS_PUBLISHED', { election_id: electionId, outcome, winnerId });

    // notify winner by email (if clear winner)
    if (outcome === 'WINNER' && winnerId) {
      const [[student]] = await pool.query('SELECT email, name FROM Student WHERE student_id = ?', [winnerId]);
      if (student && student.email) {
        const host = process.env.SMTP_HOST;
        const port = parseInt(process.env.SMTP_PORT || '587');
        const user = process.env.SMTP_USER; const pass = process.env.SMTP_PASS;
        if (host && user && pass) {
          const transporter = nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });
          await transporter.sendMail({
            from: process.env.OTP_EMAIL_FROM,
            to: student.email,
            subject: 'Congratulations: You have been elected Class Representative',
            text: `Dear ${student.name || winnerId},\n\nCongratulations! You have been elected as the Class Representative. Please await further instructions from the faculty advisor.\n\nRegards,\nElection Committee`
          });
        }
      }
    }

    // notify all students of the class that results are published
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587');
    const user = process.env.SMTP_USER; const pass = process.env.SMTP_PASS;
    if (host && user && pass) {
      const transporter = nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });
      const [students] = await pool.query('SELECT email, name FROM Student WHERE class_id = ?', [eInfo.class_id]);
      for (const s of students) {
        if (!s.email) continue;
        await transporter.sendMail({
          from: process.env.OTP_EMAIL_FROM,
          to: s.email,
          subject: 'Election Results Published',
          text: `Dear ${s.name || 'Student'},\n\nResults for your class election (ID: ${electionId}) have been published. Please log into the system to view the results.\n\nRegards,\nElection Committee`
        });
      }
    }

    res.json({ message: 'Results published', outcome, winnerId });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Bulk publish results for multiple elections
exports.publishResultsBulk = async (req, res) => {
  try {
    const { election_ids } = req.body || {};
    if (!Array.isArray(election_ids) || !election_ids.length) {
      return res.status(400).json({ error: 'election_ids array required' });
    }
    // ensure all have voting ended
    const [notEnded] = await pool.query(
      `SELECT election_id FROM Election WHERE election_id IN (${election_ids.map(()=>'?').join(',')}) AND voting_end > NOW()`,
      election_ids
    );
    if (notEnded.length) {
      return res.status(400).json({ error: `Cannot publish before voting ends for elections: ${notEnded.map(r=>r.election_id).join(', ')}` });
    }
    await pool.query(
      `UPDATE Election SET is_published = TRUE, is_active = FALSE WHERE election_id IN (${election_ids.map(()=>'?').join(',')})`,
      election_ids
    );
    await logAction(req.user.id, req.user.role, req.ip, 'RESULTS_PUBLISHED_BULK', { election_ids });
    res.json({ message: 'Results published for selected elections' });
  } catch (err) {
    console.error('publishResultsBulk error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Notify students when voting opens (announcement only, no tokens)
exports.notifyVotingOpen = async (req, res) => {
  try {
    const electionId = req.params.id;
    const [eRows] = await pool.query('SELECT * FROM Election WHERE election_id = ?', [electionId]);
    if (!eRows.length) return res.status(404).json({ error: 'Election not found' });
    const election = eRows[0];

    // fetch students emails in class
    const [students] = await pool.query('SELECT email, name FROM Student WHERE class_id = ?', [election.class_id]);
    const host = process.env.SMTP_HOST;
    const port = parseInt(process.env.SMTP_PORT || '587');
    const user = process.env.SMTP_USER;
    const pass = process.env.SMTP_PASS;
    if (!host || !user || !pass) {
      return res.status(400).json({ error: 'SMTP not configured' });
    }
    const transporter = nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });

    const start = new Date(election.voting_start).toLocaleString();
    const end = new Date(election.voting_end).toLocaleString();

    // naive batching
    for (const s of students) {
      if (!s.email) continue;
      await transporter.sendMail({
        from: process.env.OTP_EMAIL_FROM,
        to: s.email,
  subject: 'Voting for Class Representative Now Open',
  text: `Dear ${s.name || 'Student'},\n\nThe election for Class Representative is scheduled between ${start} and ${end}. Please log into the Class Representative Election System during this window to cast your vote.\n\nRegards,\nElection Committee`
      });
    }
    await logAction(req.user.id, req.user.role, req.ip, 'EMAIL_NOTIFICATION_SENT', { election_id: electionId, recipients: students.length });
    res.json({ message: 'Notifications sent (if SMTP configured)' });
  } catch (err) {
    console.error('notifyVotingOpen error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// Notify students when nomination opens (announcement)
exports.notifyNominationOpen = async (req, res) => {
  try {
    const electionId = req.params.id;
    const [eRows] = await pool.query('SELECT * FROM Election WHERE election_id = ?', [electionId]);
    if (!eRows.length) return res.status(404).json({ error: 'Election not found' });
    const election = eRows[0];
    const [students] = await pool.query('SELECT email, name FROM Student WHERE class_id = ?', [election.class_id]);
    const host = process.env.SMTP_HOST; const port = parseInt(process.env.SMTP_PORT || '587'); const user = process.env.SMTP_USER; const pass = process.env.SMTP_PASS;
    if (!host || !user || !pass) return res.status(400).json({ error: 'SMTP not configured' });
    const transporter = nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });
    const start = new Date(election.nomination_start).toLocaleString();
    const end = new Date(election.nomination_end).toLocaleString();
    for (const s of students) {
      if (!s.email) continue;
      await transporter.sendMail({
        from: process.env.OTP_EMAIL_FROM,
        to: s.email,
        subject: 'Nomination Window Now Open',
        text: `Dear ${s.name || 'Student'},\n\nThe nomination window is open from ${start} to ${end}. Please submit your nomination via the Class Representative Election System.\n\nRegards,\nElection Committee`
      });
    }
    await logAction(req.user.id, req.user.role, req.ip, 'EMAIL_NOTIFICATION_SENT', { election_id: electionId, type: 'NOMINATION', recipients: students.length });
    res.json({ message: 'Nomination notifications sent (if SMTP configured)' });
  } catch (err) {
    console.error('notifyNominationOpen error:', err);
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

// Convenience: active election for the logged-in student based on their class
exports.getMyActiveElection = async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.user.id;
    const [sRows] = await pool.query('SELECT class_id FROM Student WHERE student_id = ?', [studentId]);
    if (!sRows.length || !sRows[0].class_id) return res.status(404).json({ error: 'Student class not found' });
    const classId = sRows[0].class_id;
    const [rows] = await pool.query(
      `SELECT * FROM Election WHERE class_id = ? AND is_active = TRUE ORDER BY created_at DESC LIMIT 1`,
      [classId]
    );
    if (!rows.length) return res.status(404).json({ error: 'No active election' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getMyActiveElection error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// List all elections for the logged-in student's class with computed status flags
exports.getMyElections = async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.user.id;
    const [[s]] = await pool.query('SELECT class_id FROM Student WHERE student_id = ?', [studentId]);
    if (!s || !s.class_id) return res.status(404).json({ error: 'Student class not found' });
    const classId = s.class_id;
    const [rows] = await pool.query('SELECT * FROM Election WHERE class_id = ? ORDER BY created_at DESC', [classId]);
    const now = Date.now();
    const data = rows.map(e => {
      const ns = new Date(e.nomination_start).getTime();
      const ne = new Date(e.nomination_end).getTime();
      const vs = new Date(e.voting_start).getTime();
      const ve = new Date(e.voting_end).getTime();
      return {
        ...e,
        nomination_open: now >= ns && now <= ne,
        voting_open: now >= vs && now <= ve,
        ended: now > ve
      };
    });
    res.json(data);
  } catch (err) {
    console.error('getMyElections error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// listElections, updateElection, getElection etc - implement similarly
