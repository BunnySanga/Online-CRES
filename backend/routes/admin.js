// routes/admin.js
const express = require('express');
const router = express.Router();
const { verifyToken, requireRole } = require('../middleware/auth');
const ctrl = require('../controllers/adminController');

// All admin-only routes
router.use(verifyToken, requireRole('ADMIN'));

// ----- Admin Profile -----
router.get('/profile', ctrl.getProfile);
router.put('/profile', ctrl.updateProfile);

// ----- Class Management -----
router.get('/classes', ctrl.listClasses);
router.post('/classes', ctrl.createClass);
router.delete('/classes/:id', ctrl.deleteClass);

// ----- Student Management -----
router.get('/students', ctrl.listStudents);
router.get('/students/:id', ctrl.getStudent);
router.post('/students', ctrl.createStudent);
router.put('/students/:id', ctrl.updateStudent);
router.delete('/students/:id', ctrl.deleteStudent);
router.post('/students/:id/reset-password', ctrl.resetStudentPassword);

module.exports = router;
