const express = require('express');
const { body } = require('express-validator');
const {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  getProfile,
  getSessions,
  revokeSession,
} = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');
const {
  authLimiter,
  registerLimiter,
  bruteForceProtection,
} = require('../middleware/rateLimiter');
const {
  registrationTimingAttack,
  detectSuspiciousActivity,
  honeypotProtection,
  automationDetection,
} = require('../middleware/security');

const router = express.Router();

/**
 * Input validation rules for user registration
 * Validates email format, password strength, and name requirements
 * @type {Array<ValidationChain>}
 */
const registerValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .isLength({ min: 5, max: 255 })
    .withMessage('Email must be between 5 and 255 characters'),
  
  body('fullName')
    .trim()
    .isLength({ min: 2, max: 100 })
    .withMessage('Full name must be between 2 and 100 characters')
    .matches(/^[a-zA-Z\s'-]+$/)
    .withMessage('Full name can only contain letters, spaces, hyphens, and apostrophes'),
  
  body('password')
    .isLength({ min: 8, max: 128 })
    .withMessage('Password must be between 8 and 128 characters')
    .matches(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .withMessage('Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'),
  
  // Honeypot fields for bot detection (should be empty)
  body('website').optional().isEmpty().withMessage('Invalid field'),
  body('url').optional().isEmpty().withMessage('Invalid field'),
  body('homepage').optional().isEmpty().withMessage('Invalid field'),
];

/**
 * Input validation rules for user login
 * Validates email format and password presence
 * @type {Array<ValidationChain>}
 */
const loginValidation = [
  body('email')
    .isEmail()
    .withMessage('Please provide a valid email address')
    .normalizeEmail()
    .isLength({ min: 5, max: 255 })
    .withMessage('Email must be between 5 and 255 characters'),
  
  body('password')
    .notEmpty()
    .withMessage('Password is required')
    .isLength({ max: 128 })
    .withMessage('Password is too long'),
];

/**
 * POST /api/auth/register
 * Register a new user account
 * 
 * Security Features:
 * - Rate limited to 3 registrations per hour per IP
 * - Email enumeration protection via timing normalization
 * - Bot detection using honeypot fields
 * - Automated request detection
 * - Suspicious activity monitoring
 * 
 * @route POST /api/auth/register
 * @access Public
 * @param {Object} req.body - Registration data
 * @param {string} req.body.email - User email address
 * @param {string} req.body.password - User password (plain text)
 * @param {string} req.body.fullName - User full name
 * @returns {Object} 201 - User created successfully with access token
 * @returns {Object} 400 - Validation errors
 * @returns {Object} 429 - Rate limit exceeded
 */
router.post('/register', 
  registerLimiter,
  detectSuspiciousActivity,
  automationDetection,
  honeypotProtection,
  registrationTimingAttack,
  registerValidation,
  register
);

/**
 * POST /api/auth/login
 * Authenticate user and create session
 * 
 * Security Features:
 * - Rate limited to 5 attempts per 5 minutes per IP+email
 * - Brute force protection with account locking
 * - Automated request detection
 * - Failed attempt tracking in Redis
 * 
 * @route POST /api/auth/login
 * @access Public
 * @param {Object} req.body - Login credentials
 * @param {string} req.body.email - User email address
 * @param {string} req.body.password - User password (plain text)
 * @returns {Object} 200 - Login successful with access token and user data
 * @returns {Object} 401 - Invalid credentials
 * @returns {Object} 423 - Account locked due to failed attempts
 * @returns {Object} 429 - Rate limit exceeded
 */
router.post('/login', 
  authLimiter,
  bruteForceProtection,
  automationDetection,
  loginValidation,
  login
);

/**
 * POST /api/auth/refresh
 * Refresh expired access token using refresh token
 * 
 * Uses HttpOnly cookie for refresh token to prevent XSS attacks
 * Validates token against database and user status
 * 
 * @route POST /api/auth/refresh
 * @access Public (requires valid refresh token in cookie)
 * @returns {Object} 200 - New access token generated successfully
 * @returns {Object} 401 - Invalid or expired refresh token
 */
router.post('/refresh', refreshToken);

/**
 * POST /api/auth/logout
 * Logout user from current device
 * 
 * Blacklists access token and invalidates refresh token
 * Clears HttpOnly cookie and user cache
 * 
 * @route POST /api/auth/logout
 * @access Private (requires valid access token)
 * @returns {Object} 200 - Logout successful
 * @returns {Object} 401 - Authentication required
 */
router.post('/logout', authenticateToken, logout);

/**
 * POST /api/auth/logout-all
 * Logout user from all devices
 * 
 * Invalidates all refresh tokens for the user
 * Blacklists current access token and clears cache
 * 
 * @route POST /api/auth/logout-all
 * @access Private (requires valid access token)
 * @returns {Object} 200 - Logged out from all devices successfully
 * @returns {Object} 401 - Authentication required
 */
router.post('/logout-all', authenticateToken, logoutAll);

/**
 * GET /api/auth/profile
 * Get current user profile information
 * 
 * Returns user data with caching for performance
 * Excludes sensitive information like password
 * 
 * @route GET /api/auth/profile
 * @access Private (requires valid access token)
 * @returns {Object} 200 - User profile data
 * @returns {Object} 401 - Authentication required
 * @returns {Object} 404 - User not found
 */
router.get('/profile', authenticateToken, getProfile);

/**
 * GET /api/auth/sessions
 * Get user's active sessions (devices)
 * 
 * Shows all devices where user is currently logged in
 * Includes device information and login timestamps
 * 
 * @route GET /api/auth/sessions
 * @access Private (requires valid access token)
 * @returns {Object} 200 - Array of active sessions
 * @returns {Object} 401 - Authentication required
 */
router.get('/sessions', authenticateToken, getSessions);

/**
 * DELETE /api/auth/sessions/:sessionId
 * Revoke specific user session
 * 
 * Allows users to logout from specific devices
 * Invalidates the specified refresh token
 * 
 * @route DELETE /api/auth/sessions/:sessionId
 * @access Private (requires valid access token)
 * @param {string} req.params.sessionId - Session ID to revoke
 * @returns {Object} 200 - Session revoked successfully
 * @returns {Object} 401 - Authentication required
 * @returns {Object} 404 - Session not found
 */
router.delete('/sessions/:sessionId', authenticateToken, revokeSession);

/**
 * GET /api/auth/health
 * Health check endpoint for monitoring
 * 
 * Returns service status and timestamp
 * Used by load balancers and monitoring systems
 * 
 * @route GET /api/auth/health
 * @access Public
 * @returns {Object} 200 - Service health status
 */
router.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    service: 'auth-backend',
  });
});

/**
 * Export configured router with all authentication routes
 */
module.exports = router;