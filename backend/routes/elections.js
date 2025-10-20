const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/electionsController');

router.post('/', verifyToken, requireRole('ADMIN'), ctrl.createElection);
router.put('/:id', verifyToken, requireRole('ADMIN'), ctrl.updateElection);
router.get('/:id', verifyToken, ctrl.getElection);
router.get('/', verifyToken, ctrl.listElections);
router.get('/class/:classId/active', verifyToken, ctrl.getActiveElectionForClass);
router.post('/:id/activate', verifyToken, requireRole('ADMIN'), ctrl.activateElection); // generate tokens
router.post('/:id/publish', verifyToken, requireRole('ADMIN'), ctrl.publishResults);

module.exports = router;
