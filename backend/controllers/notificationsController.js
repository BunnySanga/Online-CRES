const pool = require('../config/db');

exports.getMyNotifications = async (req, res) => {
  try {
    if (!req.user || req.user.role !== 'STUDENT') return res.status(403).json({ error: 'Forbidden' });
    const studentId = req.user.id;
    const [[s]] = await pool.query('SELECT class_id FROM Student WHERE student_id = ?', [studentId]);
    if (!s || !s.class_id) return res.status(404).json({ error: 'Student class not found' });
    const classId = s.class_id;
    const [rows] = await pool.query('SELECT * FROM Election WHERE class_id = ? ORDER BY created_at DESC LIMIT 20', [classId]);
    const now = Date.now();
    const notices = [];
    for (const e of rows) {
      const ns = new Date(e.nomination_start).getTime();
      const ne = new Date(e.nomination_end).getTime();
      const vs = new Date(e.voting_start).getTime();
      const ve = new Date(e.voting_end).getTime();
      if (now >= ns && now <= ne) {
        notices.push({ type: 'NOMINATION_OPEN', election_id: e.election_id, message: `Nominations open until ${new Date(ne).toLocaleString()}`, ts: e.nomination_start });
      }
      if (now >= vs && now <= ve) {
        notices.push({ type: 'VOTING_OPEN', election_id: e.election_id, message: `Voting open until ${new Date(ve).toLocaleString()}`, ts: e.voting_start });
      }
      if (e.is_published && now > ve) {
        notices.push({ type: 'RESULTS_PUBLISHED', election_id: e.election_id, message: `Results published for Election #${e.election_id}`, ts: e.updated_at || e.created_at });
      }
    }
    // sort newest first and cap size
    notices.sort((a,b)=> new Date(b.ts) - new Date(a.ts));
    res.json(notices.slice(0, 15));
  } catch (err) {
    console.error('getMyNotifications error:', err);
    res.status(500).json({ error: 'Server error' });
  }
};
