const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/auditController');

router.get('/', verifyToken, requireRole('ADMIN'), ctrl.listAudit);

module.exports = router;
