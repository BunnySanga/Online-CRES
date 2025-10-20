const express = require('express');
const router = express.Router();
const { verifyToken } = require('../middleware/auth');
const ctrl = require('../controllers/votesController');

router.get('/election/:electionId/token', verifyToken, ctrl.getOrCreateTokenForStudent); // student requests token in-session
router.post('/', verifyToken, ctrl.castVote); // student casts vote (uses token in server session)
router.get('/election/:electionId/results', verifyToken, ctrl.getResults); // admin/public after publish

module.exports = router;
