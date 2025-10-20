const express = require('express');
const router = express.Router();
const AuthController = require('../controllers/authController');
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
router.post('/admin/login', AuthController.adminLogin);
router.post('/login', loginValidator, AuthController.login);             
router.post('/verify-otp', verifyOtpValidator, otpLimiter, AuthController.verifyOtp); 
router.post('/change-password', verifyToken, AuthController.changePassword);
router.post('/request-reset', AuthController.requestPasswordReset);
router.post('/reset-password', resetValidator, otpLimiter, AuthController.resetPassword);
router.post('/logout', verifyToken, AuthController.logout);
module.exports = router;
