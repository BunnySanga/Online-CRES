// controllers/studentController.js
const pool = require('../config/db');

exports.getMe = async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.user.id;
    const [rows] = await pool.query(
      `SELECT s.student_id, s.name, s.email, s.class_id, c.class_name, s.date_of_birth, s.created_at, s.must_change_password
       FROM Student s
       LEFT JOIN Class c ON c.class_id = s.class_id
       WHERE s.student_id = ?`,
      [studentId]
    );
    if (!rows.length) return res.status(404).json({ error: 'Student not found' });
    res.json(rows[0]);
  } catch (err) {
    console.error('getMe error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
