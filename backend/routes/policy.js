const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/policyController');

router.get('/', verifyToken, ctrl.getLatestPolicy);
router.post('/accept', verifyToken, ctrl.acceptPolicy);
router.post('/', verifyToken, requireRole('ADMIN'), ctrl.createPolicy);
router.get('/all', verifyToken, requireRole('ADMIN'), ctrl.listPolicies);
router.delete('/:id', verifyToken, requireRole('ADMIN'), ctrl.deletePolicy);

module.exports = router;
