const pool = require('../config/db');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const nodemailer = require('nodemailer');
const logAction = require('../utils/logAction');
const { genToken, hashToken } = require('../utils/tokenUtils');

const transporter = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT || '587'),
  secure: false,
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS
  }
});

exports.adminLogin = async (req, res) => {
  const ip = req.ip;
  try {
    const { adminId, password } = req.body;
    if (!adminId || !password) return res.status(400).json({ error: 'Missing adminId or password' });

    const [rows] = await pool.query('SELECT * FROM Admin WHERE admin_id = ?', [adminId]);
    if (!rows.length) {
      await logAction(adminId, 'ADMIN', ip, 'LOGIN_FAILURE', { reason: 'no_admin' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid admin ID or password' });
    }

    const admin = rows[0];
    const valid = await bcrypt.compare(password, admin.password_hash);
    if (!valid) {
      await logAction(adminId, 'ADMIN', ip, 'LOGIN_FAILURE', { reason: 'invalid_password' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid admin ID or password' });
    }

    // delete old sessions
    await pool.query('DELETE FROM Session WHERE user_id = ?', [adminId]);

    const sessionId = uuidv4();
    const token = jwt.sign({ userId: adminId, role: 'ADMIN', sessionId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
    const expiry = new Date(Date.now() + (60 * 60 * 1000));
    await pool.query('INSERT INTO Session (session_id, user_id, role, creation_time, expiry_time) VALUES (?, ?, ?, NOW(), ?)', [sessionId, adminId, 'ADMIN', expiry]);

    await logAction(adminId, 'ADMIN', ip, 'LOGIN_SUCCESS', {});

    res.json({ message: 'Admin login successful', token, admin: { id: admin.admin_id, name: admin.name, email: admin.email } });
  } catch (err) {
    console.error('Admin login error:', err);
    await logAction('UNKNOWN', 'ADMIN', req.ip, 'LOGIN_FAILURE', { error: err.message }, 'FAILURE');
    res.status(500).json({ error: 'Server error' });
  }
};

// STUDENT login -> send OTP
exports.login = async (req, res)=>{
  const ip = req.ip;
  try {
    const { studentId, password } = req.body;
    if (!studentId || !password) return res.status(400).json({ error: 'Missing studentId or password' });

    const [rows] = await pool.query('SELECT * FROM Student WHERE student_id = ?', [studentId]);
    if (!rows.length) {
      await logAction(studentId, 'STUDENT', ip, 'LOGIN_FAILURE', { reason: 'no_user' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid credentials' });
    }
const user = rows[0];
const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
if (!gmailRegex.test(String(user.email || ''))){
  return res.status(400).json({ error: 'Only Gmail addresses are supported (example@gmail.com)' });
}
const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
     console.log(user.password_hash);
      //console.log(hashedPassword);
      await logAction(studentId, 'STUDENT', ip, 'LOGIN_FAILURE', { reason: 'invalid_password' }, 'FAILURE');
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // generate OTP
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 5 * 60 * 1000);
    await pool.query('INSERT INTO OTP (student_id, otp_code, expiry_time, purpose, used) VALUES (?, ?, ?, ?, ?)', [studentId, otp, expiry, 'LOGIN', false]);

    // send email
    await transporter.sendMail({
      from: process.env.OTP_EMAIL_FROM,
      to: user.email,
  subject: 'Your Class Representative Election System login OTP',
  text: `Your OTP is ${otp}. It expires in 5 minutes.`
    });

    await logAction(studentId, 'STUDENT', ip, 'OTP_SENT', { email: user.email });
    res.json({ message: 'OTP sent to registered email' });
  } catch (err) {
    console.error('login error', err);
    await logAction(req.body.studentId || 'UNKNOWN', 'STUDENT', req.ip, 'OTP_SEND_FAILED', { error: err.message }, 'FAILURE');
    res.status(500).json({ error: 'Server error' });
  }
};

exports.verifyOtp = async (req, res) => {
  const ip = req.ip;
  try {
    const { studentId, otp } = req.body;
    if (!studentId || !otp) return res.status(400).json({ error: 'Missing fields' });

    const [rows] = await pool.query('SELECT * FROM OTP WHERE student_id = ? AND otp_code = ? AND used = FALSE ORDER BY created_at DESC LIMIT 1', [studentId, otp]);
    if (!rows.length) {
      await logAction(studentId, 'STUDENT', ip, 'OTP_VERIFY', { reason: 'not_found' }, 'FAILURE');
      return res.status(400).json({ error: 'Invalid or expired OTP' });
    }
    const record = rows[0];
    if (new Date(record.expiry_time) < new Date()) {
      await pool.query('UPDATE OTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);
      await logAction(studentId, 'STUDENT', ip, 'OTP_EXPIRED', {}, 'FAILURE');
      return res.status(400).json({ error: 'Expired OTP' });
    }

    // mark used
    await pool.query('UPDATE OTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);

    // delete old sessions for student
    await pool.query('DELETE FROM Session WHERE user_id = ?', [studentId]);

    const sessionId = uuidv4();
    const token = jwt.sign({ userId: studentId, role: 'STUDENT', sessionId }, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || '1h' });
    const expiry = new Date(Date.now() + (60 * 60 * 1000));
    await pool.query('INSERT INTO Session (session_id, user_id, role, creation_time, expiry_time) VALUES (?, ?, ?, NOW(), ?)', [sessionId, studentId, 'STUDENT', expiry]);

  // return must_change_password so frontend can prompt change before dashboard
  const [sRows] = await pool.query('SELECT must_change_password FROM Student WHERE student_id = ?', [studentId]);
  const mustChange = sRows.length ? !!sRows[0].must_change_password : false;

  await logAction(studentId, 'STUDENT', ip, 'LOGIN_SUCCESS', {});
  res.json({ token, userId: studentId, role: 'STUDENT', must_change_password: mustChange });
  } catch (err) {
    console.error('verifyOtp error', err);
    await logAction(req.body.studentId || 'UNKNOWN', 'STUDENT', req.ip, 'OTP_VERIFY_ERROR', { error: err.message }, 'FAILURE');
    res.status(500).json({ error: 'Server error' });
  }
};

exports.requestPasswordReset = async (req, res) => {
  const ip = req.ip;
  try {
    const { userId } = req.body;
    if (!userId) return res.status(400).json({ error: 'User ID required' });

    // detect role and user
    const [studentRows] = await pool.query('SELECT student_id AS id, email FROM Student WHERE student_id = ?', [userId]);
    const [adminRows] = await pool.query('SELECT admin_id AS id, email FROM Admin WHERE admin_id = ?', [userId]);
    const isStudent = studentRows.length > 0;
    const isAdmin = adminRows.length > 0;
    const user = isStudent ? studentRows[0] : isAdmin ? adminRows[0] : null;
    const role = isStudent ? 'STUDENT' : isAdmin ? 'ADMIN' : null;
    if (!user) return res.status(404).json({ error: 'User not found' });

    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
    if (!gmailRegex.test(String(user.email || ''))) {
      return res.status(400).json({ error: 'Only Gmail addresses are supported (example@gmail.com)' });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expiry = new Date(Date.now() + 10 * 60 * 1000);

    if (isStudent) {
      await pool.query('INSERT INTO OTP (student_id, otp_code, expiry_time, purpose, used) VALUES (?, ?, ?, ?, ?)', [
        userId, otp, expiry, 'RESET', false
      ]);
    } else {
      await pool.query('INSERT INTO AdminOTP (admin_id, otp_code, expiry_time, purpose, used) VALUES (?, ?, ?, ?, ?)', [
        userId, otp, expiry, 'RESET', false
      ]);
    }

    await transporter.sendMail({
      from: process.env.OTP_EMAIL_FROM || process.env.SMTP_USER,
      to: user.email,
      subject: 'Class Representative Election System Password Reset OTP',
      text: `Your OTP to reset your password is ${otp}. It expires in 10 minutes.`
    });

    await logAction(userId, role, ip, 'PASSWORD_RESET_OTP_SENT', {});
    res.json({ message: 'Reset OTP sent to registered email' });
  } catch (err) {
    console.error('requestPasswordReset error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// RESET PASSWORD (verify OTP and set new password)
exports.resetPassword = async (req, res) => {
  const ip = req.ip;
  try {
    const { userId, otp, newPassword } = req.body;
    if (!userId || !otp || !newPassword) return res.status(400).json({ error: 'Missing fields' });

    // detect role
    const [studentRows] = await pool.query('SELECT student_id FROM Student WHERE student_id = ?', [userId]);
    const [adminRows] = await pool.query('SELECT admin_id FROM Admin WHERE admin_id = ?', [userId]);
    const isStudent = studentRows.length > 0;
    const isAdmin = adminRows.length > 0;
    if (!isStudent && !isAdmin) return res.status(404).json({ error: 'User not found' });

    let recordRows;
    if (isStudent) {
      [recordRows] = await pool.query(
        'SELECT * FROM OTP WHERE student_id = ? AND otp_code = ? AND purpose = ? AND used = FALSE ORDER BY created_at DESC LIMIT 1',
        [userId, otp, 'RESET']
      );
    } else {
      [recordRows] = await pool.query(
        'SELECT * FROM AdminOTP WHERE admin_id = ? AND otp_code = ? AND purpose = ? AND used = FALSE ORDER BY created_at DESC LIMIT 1',
        [userId, otp, 'RESET']
      );
    }

    if (!recordRows.length) return res.status(400).json({ error: 'Invalid or expired OTP' });
    const record = recordRows[0];
    if (new Date(record.expiry_time) < new Date()) {
      if (isStudent) await pool.query('UPDATE OTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);
      else await pool.query('UPDATE AdminOTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);
      return res.status(400).json({ error: 'OTP expired' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    if (isStudent) {
      await pool.query('UPDATE Student SET password_hash = ? WHERE student_id = ?', [newHash, userId]);
      await pool.query('UPDATE OTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);
    } else {
      await pool.query('UPDATE Admin SET password_hash = ? WHERE admin_id = ?', [newHash, userId]);
      await pool.query('UPDATE AdminOTP SET used = TRUE WHERE otp_id = ?', [record.otp_id]);
    }

    await logAction(userId, isStudent ? 'STUDENT' : 'ADMIN', ip, 'PASSWORD_RESET_SUCCESS', {});
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('resetPassword error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};


exports.changePassword = async (req, res) => {
  const ip = req.ip;
  const { newPassword } = req.body;

  try {
    // Ensure user is authenticated and a STUDENT
    if (!req.user || req.user.role !== 'STUDENT') return res.status(401).json({ error: 'Not authorized' });

    const studentId = req.user.id;
    if (!newPassword) return res.status(400).json({ error: 'Missing newPassword' });

    // Check student exists and must change password
    const [rows] = await pool.query('SELECT must_change_password FROM Student WHERE student_id = ?', [studentId]);
    if (!rows.length) {
      await logAction(studentId, 'STUDENT', ip, 'PASSWORD_CHANGE_FAILED', { reason: 'student_not_found' }, 'FAILURE');
      return res.status(404).json({ error: 'Student not found' });
    }

    const mustChange = rows[0].must_change_password;
    if (!mustChange) {
      await logAction(studentId, 'STUDENT', ip, 'PASSWORD_CHANGE_SKIPPED', { reason: 'already_set' });
      return res.status(400).json({ error: 'Password already set' });
    }

    // Hash new password securely
    const hash = await bcrypt.hash(newPassword, 10);

    // Update student record
    await pool.query(
      'UPDATE Student SET password_hash = ?, must_change_password = FALSE, last_login = NOW() WHERE student_id = ?',
      [hash, studentId]
    );

    await logAction(studentId, 'STUDENT', ip, 'PASSWORD_CHANGE', { action: 'initial_password_set' }, 'SUCCESS');

    res.json({ message: 'Password changed successfully. You can now log in normally.' });
  } catch (err) {
    console.error('changePassword error:', err);
    await logAction(req.user ? req.user.id : 'UNKNOWN', 'STUDENT', ip, 'PASSWORD_CHANGE_ERROR', { error: err.message }, 'FAILURE');
    res.status(500).json({ error: 'Server error' });
  }
};


// LOGOUT (invalidate session)
exports.logout = async (req, res) => {
  const ip = req.ip;
  try {
    if (!req.user || !req.user.sessionId) return res.status(401).json({ error: 'Not logged in' });

    await pool.query('DELETE FROM Session WHERE session_id = ?', [req.user.sessionId]);
    await logAction(req.user.id, req.user.role, ip, 'LOGOUT', {});
    res.json({ message: 'Logged out successfully' });
  } catch (err) {
    console.error('logout error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.adminRequestPasswordReset = async (req, res) => {
  const ip = req.ip;
  try {
    const { admin_id } = req.body;
    if (!admin_id) return res.status(400).json({ error: 'admin_id required' });

    // lookup admin in Admin table
    const [rows] = await pool.query('SELECT admin_id, email FROM Admin WHERE admin_id = ?', [admin_id]);
    if (!rows.length) return res.status(404).json({ error: 'Admin not found' });

    // Gmail-only support (to mirror student flow constraints)
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
    if (!gmailRegex.test(String(rows[0].email || ''))) {
      return res.status(400).json({ error: 'Only Gmail addresses are supported (example@gmail.com)' });
    }

    // generate OTP and store its hash in Session table as a short-lived reset token
    // This avoids schema changes and the Student FK on OTP table
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const otpHash = hashToken(otp); // 64-hex chars
    // Remove any existing active reset tokens for this admin stored in Session
    await pool.query(
      "DELETE FROM Session WHERE user_id = ? AND role = 'ADMIN' AND LENGTH(session_id) = 64 AND expiry_time > NOW()",
      [admin_id]
    );
    // Create a new short-lived session row to hold the reset OTP hash
    await pool.query(
      'INSERT INTO Session (session_id, user_id, role, creation_time, expiry_time) VALUES (?, ?, ?, NOW(), DATE_ADD(NOW(), INTERVAL 10 MINUTE))',
      [otpHash, admin_id, 'ADMIN']
    );

    // send email
    await transporter.sendMail({
      from: process.env.OTP_EMAIL_FROM || process.env.SMTP_USER,
      to: rows[0].email,
      subject: 'Admin Password Reset OTP',
      text: `Your OTP is ${otp}. It expires in 10 minutes.`
    });

    await logAction(admin_id, 'ADMIN', ip, 'PASSWORD_RESET_OTP_SENT', {});
    res.json({ message: 'Reset OTP sent to registered email' });
  } catch (err) {
    console.error('adminRequestPasswordReset error', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.adminResetPassword = async (req, res) => {
  const ip = req.ip;
  try {
    const { admin_id, otp, new_password } = req.body;
    if (!admin_id || !otp || !new_password) return res.status(400).json({ error: 'admin_id, otp and new_password required' });

    // verify OTP using Session table hashed token (no schema change required)
    const otpHash = hashToken(otp);
    const [rows] = await pool.query(
      "SELECT * FROM Session WHERE user_id = ? AND role = 'ADMIN' AND session_id = ? AND expiry_time > NOW() LIMIT 1",
      [admin_id, otpHash]
    );
    if (!rows.length) return res.status(400).json({ error: 'Invalid or expired OTP' });

    const hash = await bcrypt.hash(new_password, 10);
    await pool.query('UPDATE Admin SET password_hash = ? WHERE admin_id = ?', [hash, admin_id]);
    // Invalidate the used reset token session
    await pool.query("DELETE FROM Session WHERE user_id = ? AND role = 'ADMIN' AND session_id = ?", [admin_id, otpHash]);

    await logAction(admin_id, 'ADMIN', ip, 'PASSWORD_RESET_SUCCESS', {});
    res.json({ message: 'Password reset successful' });
  } catch (err) {
    console.error('adminResetPassword error', err);
    res.status(500).json({ error: 'Server error' });
  }
};