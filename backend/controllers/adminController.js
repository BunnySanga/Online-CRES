// controllers/adminController.js
const pool = require('../config/db');
const bcrypt = require('bcrypt');
const logAction = require('../utils/logAction');
const nodemailer = require('nodemailer');

// =============== ADMIN PROFILE ===============
exports.getProfile = async (req, res) => {
  try {
    const adminId = req.user.id;
    const [rows] = await pool.query(
      'SELECT admin_id, name, email, created_at FROM Admin WHERE admin_id = ?',
      [adminId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Admin not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getProfile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const adminId = req.user.id;
    const { name, email } = req.body;
    if (!name && !email)
      return res.status(400).json({ error: 'No fields provided' });

    await pool.query(
      'UPDATE Admin SET name = COALESCE(?, name), email = COALESCE(?, email) WHERE admin_id = ?',
      [name, email, adminId]
    );
    await logAction(adminId, req.user.role, req.ip, 'ADMIN_PROFILE_UPDATE', { name, email });
    res.json({ message: 'Profile updated successfully' });
  } catch (err) {
    console.error('updateProfile error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// =============== CLASS MANAGEMENT ===============
exports.listClasses = async (req, res) => {
  try {
    const [rows] = await pool.query('SELECT * FROM Class ORDER BY class_id');
    res.json(rows);
  } catch (err) {
    console.error('listClasses error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.createClass = async (req, res) => {
  try {
    const { class_name } = req.body;
    if (!class_name) return res.status(400).json({ error: 'class_name required' });

    const [result] = await pool.query('INSERT INTO Class (class_name) VALUES (?)', [class_name]);
    await logAction(req.user.id, req.user.role, req.ip, 'CLASS_CREATED', { class_id: result.insertId });
    res.json({ message: 'Class created', class_id: result.insertId });
  } catch (err) {
    console.error('createClass error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.deleteClass = async (req, res) => {
  try {
    const id = req.params.id;

    // Fetch class info and students to notify
    const [[classRow]] = await pool.query('SELECT class_id, class_name FROM Class WHERE class_id = ?', [id]);
    if (!classRow) return res.status(404).json({ error: 'Class not found' });

    const [studentRows] = await pool.query('SELECT student_id, name, email FROM Student WHERE class_id = ?', [id]);
    const totalStudents = studentRows.length;

    // Attempt to send notification emails before deletion (best-effort)
    let mailed = 0;
    let mailErrors = 0;
    try {
      const host = process.env.SMTP_HOST;
      const port = parseInt(process.env.SMTP_PORT || '587');
      const user = process.env.SMTP_USER; const pass = process.env.SMTP_PASS;
      if (host && user && pass && totalStudents > 0) {
        const secure = String(port) === '465';
        const transporter = nodemailer.createTransport({ host, port, secure, auth: { user, pass } });

        const subject = `Class ${classRow.class_name} is being deleted`;
        const tasks = studentRows
          .filter(s => !!s.email)
          .map(s => {
            const text = [
              `Dear ${s.name || s.student_id},`,
              '',
              `This is to inform you that your class "${classRow.class_name}" (ID: ${classRow.class_id}) is being deleted by the administration.`,
              'As a result, your student record for this class will be removed from the system in accordance with our data policy.',
              '',
              'If you believe this is a mistake, please contact the administration immediately.',
              '',
              'Regards,',
              'Election Committee'
            ].join('\n');
            return transporter.sendMail({ from: process.env.OTP_EMAIL_FROM || user, to: s.email, subject, text })
              .then(() => { mailed++; })
              .catch(() => { mailErrors++; });
          });
        await Promise.allSettled(tasks);
      }
    } catch (mailErr) {
      // Log but do not block deletion
      console.error('deleteClass mail notify error:', mailErr && mailErr.message ? mailErr.message : mailErr);
    }

    // Proceed to delete class (will cascade delete students due to FK)
    await pool.query('DELETE FROM Class WHERE class_id = ?', [id]);
    await logAction(req.user.id, req.user.role, req.ip, 'CLASS_DELETED', { class_id: id, notified: mailed, notify_errors: mailErrors, total_students: totalStudents });
    res.json({ message: 'Class deleted successfully', notified: mailed, notify_errors: mailErrors, total_students: totalStudents });
  } catch (err) {
    console.error('deleteClass error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

// =============== STUDENT MANAGEMENT ===============
exports.listStudents = async (req, res) => {
  try {
    const [rows] = await pool.query(
      'SELECT student_id, name, email, class_id, must_change_password, created_at FROM Student'
    );
    res.json(rows);
  } catch (err) {
    console.error('listStudents error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.getStudent = async (req, res) => {
  try {
    const id = req.params.id;
    const [rows] = await pool.query('SELECT * FROM Student WHERE student_id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getStudent error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.createStudent = async (req, res) => {
  try {
    const { student_id, name, email, date_of_birth, class_id } = req.body;
    if (!student_id || !name || !email || !date_of_birth || !class_id)
      return res.status(400).json({ error: 'Missing fields' });

    // Gmail-only email enforcement
    const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
    if (!gmailRegex.test(String(email))) {
      return res.status(400).json({ error: 'Only Gmail addresses are supported (example@gmail.com)' });
    }

    // Default password rule: ddmmyyyynnnn (nnnn = first 4 digits of student_id), all lowercase
    // date_of_birth expected format: YYYY-MM-DD
    const [yyyy, mm, dd] = (date_of_birth || '').split('-');
    if (!yyyy || !mm || !dd) return res.status(400).json({ error: 'Invalid date_of_birth format (YYYY-MM-DD)' });
    const idFirst4 = String(student_id).slice(0,4);
    const defaultPassword = `${dd}${mm}${yyyy}${idFirst4}`.toLowerCase();
    const hash = await bcrypt.hash(defaultPassword, 10);
    await pool.query(
      'INSERT INTO Student (student_id, name, email, date_of_birth, class_id, password_hash, must_change_password) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [student_id, name, email, date_of_birth, class_id, hash, true]
    );
    await logAction(req.user.id, req.user.role, req.ip, 'STUDENT_CREATED', { student_id });
    // Attempt to send welcome email with credentials
    try {
      const host = process.env.SMTP_HOST;
      const port = parseInt(process.env.SMTP_PORT || '587');
      const user = process.env.SMTP_USER; const pass = process.env.SMTP_PASS;
      if (host && user && pass) {
        const transporter = nodemailer.createTransport({ host, port, secure: false, auth: { user, pass } });
        const subject = 'Welcome to Class Representative Election System';
        const lines = [
          `Dear ${name},`,
          '',
          'Your student account has been created. Please use the following credentials to log in and complete your first-time password change:',
          '',
          `Student ID: ${student_id}`,
          `Default Password: ${defaultPassword}`,
          '',
          'Your profile:',
          `- Name: ${name}`,
          `- Email: ${email}`,
          `- Class ID: ${class_id}`,
          `- Date of Birth: ${date_of_birth}`,
          '',
          'For security, you will be required to set a new password on first login.',
          '',
          'Regards,',
          'Election Committee'
        ];
        await transporter.sendMail({ from: process.env.OTP_EMAIL_FROM, to: email, subject, text: lines.join('\n') });
      }
    } catch (mailErr) {
      console.error('createStudent welcome email error:', mailErr && mailErr.message ? mailErr.message : mailErr);
    }
    res.json({ message: 'Student created successfully', defaultPassword });
  } catch (err) {
    console.error('createStudent error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.updateStudent = async (req, res) => {
  try {
    const id = req.params.id;
    const { name, email, class_id } = req.body;
    if (email) {
      const gmailRegex = /^[a-zA-Z0-9._%+-]+@gmail\.com$/i;
      if (!gmailRegex.test(String(email))) {
        return res.status(400).json({ error: 'Only Gmail addresses are supported (example@gmail.com)' });
      }
    }
    await pool.query(
      'UPDATE Student SET name = COALESCE(?, name), email = COALESCE(?, email), class_id = COALESCE(?, class_id) WHERE student_id = ?',
      [name, email, class_id, id]
    );
    await logAction(req.user.id, req.user.role, req.ip, 'STUDENT_UPDATED', { student_id: id });
    res.json({ message: 'Student updated successfully' });
  } catch (err) {
    console.error('updateStudent error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.deleteStudent = async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query('DELETE FROM Student WHERE student_id = ?', [id]);
    await logAction(req.user.id, req.user.role, req.ip, 'STUDENT_DELETED', { student_id: id });
    res.json({ message: 'Student deleted successfully' });
  } catch (err) {
    console.error('deleteStudent error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};

exports.resetStudentPassword = async (req, res) => {
  try {
    const id = req.params.id;
    // Reset rule: same as default creation rule if DOB exists; otherwise generate a strong temp and require reset via OTP
    const [rows] = await pool.query('SELECT date_of_birth FROM Student WHERE student_id = ?', [id]);
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    const dob = rows[0].date_of_birth;
    let tempPassword;
    if (dob) {
      const yyyy = String(dob).slice(0,4);
      const mm = String(dob).slice(5,7);
      const dd = String(dob).slice(8,10);
      const idFirst4 = String(id).slice(0,4);
      tempPassword = `${dd}${mm}${yyyy}${idFirst4}`.toLowerCase();
    } else {
      // fallback temp
      tempPassword = 'reset' + Math.floor(1000 + Math.random()*9000);
    }
    const hash = await bcrypt.hash(tempPassword, 10);
    await pool.query('UPDATE Student SET password_hash=?, must_change_password=TRUE WHERE student_id=?', [hash, id]);
    await logAction(req.user.id, req.user.role, req.ip, 'STUDENT_PASSWORD_RESET', { student_id: id });
    res.json({ message: `Password reset for ${id}`, tempPassword });
  } catch (err) {
    console.error('resetStudentPassword error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
