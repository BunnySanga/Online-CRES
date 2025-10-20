// controllers/votesController.js
const pool = require('../config/db');
const logAction = require('../utils/logAction');
const { genToken, hashToken, genBallotId } = require('../utils/tokenUtils');
const { v4: uuidv4 } = require('uuid');

/**
 * GET /api/votes/election/:electionId/token
 * Returns or creates a token for the logged-in student for the given election.
 * (We issue token server-side and return it to the session only.)
 */
exports.getOrCreateTokenForStudent = async (req, res) =>{
  const studentId = req.user.id;
  const electionId = req.params.electionId;
  const ip = req.ip;
  try {
    // ensure election exists and within voting window
    const [eRows] = await pool.query('SELECT * FROM Election WHERE election_id = ?', [electionId]);
    if (!eRows.length) return res.status(404).json({ error: 'Election not found' });
    const election = eRows[0];
    const now = new Date();
    if (now < new Date(election.voting_start) || now > new Date(election.voting_end)) {
      return res.status(400).json({ error: 'Voting not open' });
    }

    // check voter status
    const [vsRows] = await pool.query('SELECT * FROM VoterStatus WHERE student_id = ? AND election_id = ?', [studentId, electionId]);
    if (!vsRows.length) {
      return res.status(403).json({ error: 'Student not eligible to vote in this election' });
    }
    if (vsRows[0].has_voted) return res.status(400).json({ error: 'Already voted' });

    // check if token exists and unused for this student -> otherwise create new one
    const [tokenRows] = await pool.query('SELECT token_id FROM VotingToken WHERE student_id = ? AND election_id = ? AND used = FALSE LIMIT 1', [studentId, electionId]);
    let plaintextToken = null;
    if (tokenRows.length) {
      // we don't store plaintext; to re-issue we would need to regenerate and replace hash.
      // For simplicity: regenerate token and replace hash (safe)
      plaintextToken = genToken();
      const tokenHash = hashToken(plaintextToken);
      await pool.query('UPDATE VotingToken SET token_hash = ? WHERE token_id = ?', [tokenHash, tokenRows[0].token_id]);
    } else {
      // generate a new token row
      plaintextToken = genToken();
      const tokenHash = hashToken(plaintextToken);
      const tokenId = uuidv4();
      await pool.query('INSERT INTO VotingToken (token_id, student_id, election_id, token_hash, used) VALUES (?, ?, ?, ?, ?)', [tokenId, studentId, electionId, tokenHash, false]);
    }

    await logAction(studentId, req.user.role, ip, 'TOKEN_ISSUED', { election_id: electionId });
    // Send the plaintext token back to frontend (over HTTPS) for use in vote request.
    // You may choose to not reveal token and instead keep it server-side; this implementation returns token.
    res.json({ token: plaintextToken });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};

/**
 * POST /api/votes
 * Body: { token, candidate_id, election_id }
 * Transactional: lock token and voter status, insert anonymous vote, anonymize token.
 */
exports.castVote = async (req, res) => {
  const ip = req.ip;
  const userId = req.user.id; // logged-in student (but we won't store as voter->candidate)
  const { token, candidate_id, election_id } = req.body;
  if (!token || !candidate_id || !election_id) return res.status(400).json({ error: 'Missing fields' });

  const conn = await pool.getConnection();
  try {
    await conn.beginTransaction();

    // hash token and find token row FOR UPDATE
    const tokenHash = hashToken(token);
    const [tokenRows] = await conn.query('SELECT token_id, student_id, used FROM VotingToken WHERE token_hash = ? AND election_id = ? FOR UPDATE', [tokenHash, election_id]);
    if (!tokenRows.length) {
      await conn.rollback();
      await logAction(userId, req.user.role, ip, 'VOTE_FAILURE', { reason: 'invalid_token', election_id }, 'FAILURE');
      return res.status(400).json({ error: 'Invalid or used token' });
    }
    const tokenRow = tokenRows[0];
    if (tokenRow.used) {
      await conn.rollback();
      await logAction(userId, req.user.role, ip, 'VOTE_FAILURE', { reason: 'token_used', election_id }, 'FAILURE');
      return res.status(400).json({ error: 'Token already used' });
    }

    // confirm voter status: FOR UPDATE to prevent races
    const [vsRows] = await conn.query('SELECT id, has_voted FROM VoterStatus WHERE student_id = ? AND election_id = ? FOR UPDATE', [tokenRow.student_id, election_id]);
    if (!vsRows.length) {
      await conn.rollback();
      await logAction(userId, req.user.role, ip, 'VOTE_FAILURE', { reason: 'not_eligible', election_id }, 'FAILURE');
      return res.status(403).json({ error: 'Not eligible to vote' });
    }
    if (vsRows[0].has_voted) {
      await conn.rollback();
      await logAction(userId, req.user.role, ip, 'VOTE_FAILURE', { reason: 'already_voted', election_id }, 'FAILURE');
      return res.status(400).json({ error: 'Already voted' });
    }

    // double-check election active and candidate approved
    const [eRows] = await conn.query('SELECT * FROM Election WHERE election_id = ? FOR UPDATE', [election_id]);
    if (!eRows.length) {
      await conn.rollback();
      return res.status(404).json({ error: 'Election not found' });
    }
    const election = eRows[0];
    const now = new Date();
    if (now < new Date(election.voting_start) || now > new Date(election.voting_end) || !election.is_active) {
      await conn.rollback();
      return res.status(400).json({ error: 'Voting not open' });
    }

    // confirm candidate approval
    const [candRows] = await conn.query('SELECT * FROM Nomination WHERE student_id = ? AND election_id = ? AND status = ?', [candidate_id, election_id, 'APPROVED']);
    if (!candRows.length) {
      await conn.rollback();
      return res.status(400).json({ error: 'Invalid candidate' });
    }

    // insert anonymous vote
    const ballotId = genBallotId();
    await conn.query('INSERT INTO VoteAnonymous (election_id, ballot_id, candidate_id) VALUES (?, ?, ?)', [election_id, ballotId, candidate_id]);

    // mark token used and anonymize mapping
    await conn.query('UPDATE VotingToken SET used = TRUE, used_at = NOW(), student_id = NULL, token_hash = NULL WHERE token_id = ?', [tokenRow.token_id]);

    // update voter status (has_voted)
    await conn.query('UPDATE VoterStatus SET has_voted = TRUE, voted_at = NOW() WHERE id = ?', [vsRows[0].id]);

    await conn.commit();

    // audit logs: VOTE_CAST (anonymous) and TOKEN_USED
    await logAction('ANON', 'SYSTEM', ip, 'VOTE_CAST', { election_id, ballot_id: ballotId }, 'SUCCESS');
    await logAction('ANON', 'SYSTEM', ip, 'TOKEN_USED', { election_id }, 'SUCCESS');

    res.json({ message: 'Vote recorded successfully', ballot_id: ballotId });
  } catch (err) {
    await conn.rollback();
    console.error('castVote error', err);
    await logAction(req.user.id || 'UNKNOWN', req.user.role || 'STUDENT', ip, 'VOTE_ERROR', { error: err.message }, 'FAILURE');
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
};

exports.getResults = async (req, res) => {
  try {
    const electionId = req.params.electionId;
    // returns aggregated vote counts
    const [rows] = await pool.query('SELECT candidate_id, COUNT(*) AS votes FROM VoteAnonymous WHERE election_id = ? GROUP BY candidate_id ORDER BY votes DESC', [electionId]);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
};
