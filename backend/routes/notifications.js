const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/notificationsController');

router.get('/mine', verifyToken, requireRole('STUDENT'), ctrl.getMyNotifications);

module.exports = router;
