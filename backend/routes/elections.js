const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/electionsController');

// Creation and listing
router.post('/', verifyToken, requireRole('ADMIN'), ctrl.createElection);
router.get('/', verifyToken, ctrl.listElections);

// Student convenience routes MUST be before generic :id routes
router.get('/my/active', verifyToken, requireRole('STUDENT'), ctrl.getMyActiveElection);
router.get('/my', verifyToken, requireRole('STUDENT'), ctrl.getMyElections);

// Class scoped route should also precede generic :id
router.get('/class/:classId/active', verifyToken, ctrl.getActiveElectionForClass);

// Generic id-based routes and admin actions
router.put('/:id', verifyToken, requireRole('ADMIN'), ctrl.updateElection);
router.get('/:id', verifyToken, ctrl.getElection);
router.post('/:id/activate', verifyToken, requireRole('ADMIN'), ctrl.activateElection); // generate tokens
router.post('/:id/publish', verifyToken, requireRole('ADMIN'), ctrl.publishResults);
router.post('/:id/notify', verifyToken, requireRole('ADMIN'), ctrl.notifyVotingOpen);
router.post('/:id/notify/nomination-open', verifyToken, requireRole('ADMIN'), ctrl.notifyNominationOpen);

// Bulk operations
router.post('/publish/bulk', verifyToken, requireRole('ADMIN'), ctrl.publishResultsBulk);

module.exports = router;
