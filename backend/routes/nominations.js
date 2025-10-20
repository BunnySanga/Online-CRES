const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/nominationsController');

router.post('/', verifyToken, requireRole('STUDENT'), ctrl.submitNomination);
router.get('/election/:electionId', verifyToken, ctrl.listByElection);
router.get('/election/:electionId/approved', verifyToken, ctrl.listApprovedByElection);
router.get('/election/:electionId/mine', verifyToken, requireRole('STUDENT'), ctrl.getMyNomination);
router.put('/:id/approve', verifyToken, requireRole('ADMIN'), ctrl.approveNomination);
router.put('/:id/reject', verifyToken, requireRole('ADMIN'), ctrl.rejectNomination);

module.exports = router;
