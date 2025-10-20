const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/nominationsController');

router.post('/', verifyToken, ctrl.submitNomination); // STUDENT
router.get('/election/:electionId', verifyToken, ctrl.listByElection);
router.put('/:id/approve', verifyToken, requireRole('ADMIN'), ctrl.approveNomination);
router.put('/:id/reject', verifyToken, requireRole('ADMIN'), ctrl.rejectNomination);

module.exports = router;
