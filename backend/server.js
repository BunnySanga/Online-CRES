require('dotenv').config();
const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const app = express();
const PORT = process.env.PORT || 5500;

app.use(helmet());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());
app.use(cors({
  origin: '*',
  credentials: true
}));

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 200
});
app.use(limiter);

const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP attempts, try again later' }
});

// routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/elections', require('./routes/elections'));
app.use('/api/nominations', require('./routes/nominations'));
app.use('/api/votes', require('./routes/votes'));
app.use('/api/policy', require('./routes/policy'));
app.use('/api/audit', require('./routes/audit'));
app.use('/api/admin', require('./routes/admin'));
app.use('/api/students', require('./routes/students'));
app.use('/api/notifications', require('./routes/notifications'));

app.get('/', (req, res) => res.json({ message: 'Class Representative Election System backend up' }));

const pool = require('./config/db');
const { genToken, hashToken } = require('./utils/tokenUtils');
const { v4: uuidv4 } = require('uuid');
setInterval(async () => {
  try {
    // Expire/cleanup OTPs
    await pool.query("UPDATE OTP SET used = TRUE WHERE expiry_time < NOW() AND used = FALSE");
    await pool.query("DELETE FROM OTP WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");

    // Auto-close elections whose voting_end passed and still active
    const [toClose] = await pool.query(
      'SELECT election_id FROM Election WHERE is_active = TRUE AND voting_end < NOW()'
    );
    for (const row of toClose) {
      try {
        await pool.query('UPDATE Election SET is_active = FALSE WHERE election_id = ?', [row.election_id]);
        // Mark any unused tokens as used and anonymize
        await pool.query(
          'UPDATE VotingToken SET used = TRUE, used_at = NOW(), student_id = NULL, token_hash = NULL WHERE election_id = ? AND used = FALSE',
          [row.election_id]
        );
        // Audit log
        const logAction = require('./utils/logAction');
        await logAction('SYSTEM', 'SYSTEM', null, 'ELECTION_CLOSED', { election_id: row.election_id });
      } catch (innerErr) {
        console.error('Election auto-close error:', innerErr && innerErr.message ? innerErr.message : innerErr);
      }
    }

    // Auto-activate elections at nomination start if not already active/published
    const [toActivate] = await pool.query(
      'SELECT election_id, class_id FROM Election WHERE is_active = FALSE AND is_published = FALSE AND nomination_start <= NOW()'
    );
    for (const row of toActivate) {
      try {
        // ensure no other active election exists for this class
        const [activeOther] = await pool.query('SELECT 1 FROM Election WHERE class_id = ? AND is_active = TRUE LIMIT 1', [row.class_id]);
        if (activeOther.length) continue;

        // create tokens and voter status for students of this class
        const [students] = await pool.query('SELECT student_id FROM Student WHERE class_id = ?', [row.class_id]);
        const insertVt = [];
        const insertVs = [];
        for (const s of students) {
          const token = genToken();
          const tokenHash = hashToken(token);
          const tokenId = uuidv4();
          insertVt.push([tokenId, s.student_id, row.election_id, tokenHash]);
          insertVs.push([s.student_id, row.election_id, false]);
        }
        if (insertVt.length) {
          await pool.query('INSERT INTO VotingToken (token_id, student_id, election_id, token_hash) VALUES ?', [insertVt]);
          await pool.query('INSERT INTO VoterStatus (student_id, election_id, has_voted) VALUES ?', [insertVs]);
        }

        await pool.query('UPDATE Election SET is_active = TRUE WHERE election_id = ?', [row.election_id]);
        const logAction = require('./utils/logAction');
        await logAction('SYSTEM', 'SYSTEM', null, 'ELECTION_ACTIVATED_AUTO', { election_id: row.election_id });
      } catch (innerErr) {
        console.error('Election auto-activate error:', innerErr && innerErr.message ? innerErr.message : innerErr);
      }
    }
  } catch (err) {
    console.error('Maintenance job error:', err && err.message ? err.message : err);
  }
}, 1000 * 60);

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
