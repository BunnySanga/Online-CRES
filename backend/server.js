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

// stricter rate limiter for OTP verification / reset endpoints
const otpLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Too many OTP attempts, try again later' }
});
// apply otpLimiter only to the relevant routes (mounted below when routes are used)

// routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/elections', require('./routes/elections'));
app.use('/api/nominations', require('./routes/nominations'));
app.use('/api/votes', require('./routes/votes'));
app.use('/api/policy', require('./routes/policy'));
app.use('/api/audit', require('./routes/audit'));

app.get('/', (req, res) => res.json({ message: 'CRES backend up' }));

// Periodic cleanup job: remove expired OTP rows every hour
const pool = require('./config/db');
setInterval(async () => {
  try {
    // mark expired OTPs used=true to prevent reuse and optionally delete older ones
    await pool.query("UPDATE OTP SET used = TRUE WHERE expiry_time < NOW() AND used = FALSE");
    // delete very old OTP records (older than 7 days)
    await pool.query("DELETE FROM OTP WHERE created_at < DATE_SUB(NOW(), INTERVAL 7 DAY)");
    // console.log('OTP cleanup completed');
  } catch (err) {
    console.error('OTP cleanup error:', err && err.message ? err.message : err);
  }
}, 1000 * 60 * 60); // every hour

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Internal Server Error' });
});

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
