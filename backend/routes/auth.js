const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { body, validationResult } = require('express-validator');
const { verifyToken } = require('../middleware/auth');
const rateLimit = require('express-rate-limit');
const otpLimiter = rateLimit({
	windowMs: 15 * 60 * 1000,
	max: 5,
	message: { error: 'Too many OTP attempts, try again later' }
});
// validators
const loginValidator = [
	body('studentId').isString().isLength({ min: 1 }).withMessage('studentId is required'),
	body('password').isString().isLength({ min: 6 }).withMessage('password must be at least 6 chars'),
	(req, res, next) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
		next();
	}
];

const verifyOtpValidator = [
	body('studentId').isString().isLength({ min: 1 }).withMessage('studentId required'),
	body('otp').isString().isLength({ min: 4 }).withMessage('otp required'),
	(req, res, next) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
		next();
	}
];

const resetValidator = [
	body('userId').isString().isLength({ min: 1 }).withMessage('userId required'),
	body('otp').isString().isLength({ min: 4 }).withMessage('otp required'),
	body('newPassword').isString().isLength({ min: 6 }).withMessage('newPassword at least 6 chars'),
	(req, res, next) => {
		const errors = validationResult(req);
		if (!errors.isEmpty()) return res.status(400).json({ errors: errors.array() });
		next();
	}
];

// routes
router.post('/admin/login', authController.adminLogin);
router.post('/login', loginValidator, authController.login);             
router.post('/verify-otp', verifyOtpValidator, otpLimiter, authController.verifyOtp); 
router.post('/change-password', verifyToken, authController.changePassword);
router.post('/request-reset', authController.requestPasswordReset);
router.post('/reset-password', resetValidator, otpLimiter, authController.resetPassword);
router.post('/logout', verifyToken, authController.logout);
// admin routes (new)
router.post('/admin/request-reset', authController.adminRequestPasswordReset);
router.post('/admin/reset-password', authController.adminResetPassword);

module.exports = router;
