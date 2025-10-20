const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/studentController');

router.get('/me', verifyToken, requireRole('STUDENT'), ctrl.getMe);

module.exports = router;
