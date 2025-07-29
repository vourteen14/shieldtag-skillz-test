const argon2 = require('argon2');
const { validationResult } = require('express-validator');
const { User, RefreshToken } = require('../models');
const { 
  generateAccessToken, 
  generateRefreshToken, 
  verifyRefreshToken,
  cacheUser,
  invalidateUserCache,
  blacklistToken,
  cacheAPIResponse,
  getCachedAPIResponse,
} = require('../utils/jwt');
const { redisClient } = require('../config/db');
const logger = require('../utils/logger');

/**
 * Argon2 password hashing configuration
 * Uses argon2id variant with 64MB memory cost for security
 * @type {Object}
 */
const argonOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16, // 64MB
  timeCost: 3,
  parallelism: 1,
};

/**
 * Track failed authentication attempts in Redis for brute force protection
 * @param {Object} bruteForceInfo - Brute force tracking information
 * @param {string} bruteForceInfo.ipKey - Redis key for IP-based tracking
 * @param {string} bruteForceInfo.emailKey - Redis key for email-based tracking
 */
const trackFailedAttempt = async (bruteForceInfo) => {
  if (!bruteForceInfo) return;

  try {
    const { ipKey, emailKey } = bruteForceInfo;
    
    // Increment IP attempts (expires in 1 hour)
    await redisClient.incr(ipKey);
    await redisClient.expire(ipKey, 3600);
    
    // Increment email attempts (expires in 30 minutes)
    await redisClient.incr(emailKey);
    await redisClient.expire(emailKey, 1800);
  } catch (error) {
    logger.error('Error tracking failed attempt:', error);
  }
};

/**
 * Clear brute force tracking data on successful authentication
 * @param {Object} bruteForceInfo - Brute force tracking information
 * @param {string} bruteForceInfo.ipKey - Redis key for IP-based tracking
 * @param {string} bruteForceInfo.emailKey - Redis key for email-based tracking
 */
const clearBruteForceAttempts = async (bruteForceInfo) => {
  if (!bruteForceInfo) return;

  try {
    const { ipKey, emailKey } = bruteForceInfo;
    await redisClient.del(ipKey);
    await redisClient.del(emailKey);
  } catch (error) {
    logger.error('Error clearing brute force attempts:', error);
  }
};

/**
 * Register new user account
 * Implements email enumeration protection and secure password hashing
 * @param {Object} req - Express request object
 * @param {Object} req.body - Request body
 * @param {string} req.body.email - User email address
 * @param {string} req.body.password - User password (plain text)
 * @param {string} req.body.fullName - User full name
 * @param {Object} res - Express response object
 */
const register = async (req, res) => {
  try {
    // Validate request data
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array(),
      });
    }

    const { email, password, fullName } = req.body;
    const normalizedEmail = email.toLowerCase().trim();
    const trimmedFullName = fullName.trim();

    // Check if user already exists (email enumeration protection)
    const existingUser = await User.findOne({ 
      where: { email: normalizedEmail } 
    });

    if (existingUser) {
      // Don't reveal that user exists - return success response
      return res.status(201).json({
        message: 'Registration successful. If this email is new, you can now log in.',
      });
    }

    // Hash password with argon2
    const hashedPassword = await argon2.hash(password, argonOptions);

    // Create new user record
    const user = await User.create({
      email: normalizedEmail,
      fullName: trimmedFullName,
      password: hashedPassword,
    });

    // Cache user data for future requests
    const userData = {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      isActive: user.isActive,
      lastLogin: null,
    };
    await cacheUser(user.id, userData);

    // Generate JWT tokens
    const tokenPayload = { userId: user.id, email: user.email };
    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

    // Store refresh token in database
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days expiration

    await RefreshToken.create({
      token: refreshToken,
      userId: user.id,
      expiresAt,
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
    });

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
      ...(process.env.COOKIE_DOMAIN && 
          !process.env.COOKIE_DOMAIN.match(/^\d+\.\d+\.\d+\.\d+$/) && 
          { domain: process.env.COOKIE_DOMAIN }),
    });

    logger.auth('User registered successfully', { 
      userId: user.id, 
      email: user.email,
      ip: req.ip 
    });

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: user.id,
        email: user.email,
        isActive: user.isActive,
      },
      accessToken,
    });

  } catch (error) {
    logger.error('Registration error:', error);
    res.status(500).json({
      error: 'Internal server error during registration',
    });
  }
};

/**
 * Authenticate user login
 * Implements account locking, brute force protection, and secure session management
 * @param {Object} req - Express request object
 * @param {Object} req.body - Request body
 * @param {string} req.body.email - User email address
 * @param {string} req.body.password - User password (plain text)
 * @param {Object} req.bruteForceInfo - Brute force tracking data from middleware
 * @param {Object} res - Express response object
 */
const login = async (req, res) => {
  try {
    // Validate request data
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      return res.status(400).json({
        error: 'Validation failed',
        details: errors.array(),
      });
    }

    const { email, password } = req.body;
    const normalizedEmail = email.toLowerCase().trim();

    // Find user by email
    const user = await User.findOne({ 
      where: { email: normalizedEmail } 
    });

    if (!user) {
      await trackFailedAttempt(req.bruteForceInfo);
      logger.security('Invalid login attempt - user not found', {
        email: normalizedEmail,
        ip: req.ip,
      });
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    // Check if account is locked
    if (user.isLocked()) {
      await trackFailedAttempt(req.bruteForceInfo);
      logger.security('Login attempt on locked account', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
        lockUntil: user.lockUntil,
      });
      return res.status(423).json({
        error: 'Account temporarily locked due to multiple failed attempts',
        lockUntil: user.lockUntil,
      });
    }

    // Check if account is active
    if (!user.isActive) {
      await trackFailedAttempt(req.bruteForceInfo);
      logger.security('Login attempt on inactive account', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
      });
      return res.status(401).json({
        error: 'Account is deactivated',
      });
    }

    // Verify password with argon2
    const validPassword = await argon2.verify(user.password, password, argonOptions);
    
    if (!validPassword) {
      await trackFailedAttempt(req.bruteForceInfo);
      await user.incLoginAttempts();
      logger.security('Invalid password attempt', {
        userId: user.id,
        email: user.email,
        ip: req.ip,
        attempts: user.loginAttempts + 1,
      });
      return res.status(401).json({
        error: 'Invalid email or password',
      });
    }

    // Reset login attempts on successful login
    await user.resetLoginAttempts();
    await clearBruteForceAttempts(req.bruteForceInfo);

    // Cache user data
    const userData = {
      id: user.id,
      email: user.email,
      fullName: user.fullName,
      isActive: user.isActive,
      lastLogin: new Date(),
    };
    await cacheUser(user.id, userData);

    // Generate JWT tokens
    const tokenPayload = { userId: user.id, email: user.email };
    const accessToken = generateAccessToken(tokenPayload);
    const refreshToken = generateRefreshToken(tokenPayload);

    // Clean up old refresh tokens for this user (keep only 5 most recent)
    const oldTokens = await RefreshToken.findAll({
      where: { userId: user.id },
      order: [['createdAt', 'DESC']],
      offset: 5,
    });

    if (oldTokens.length > 0) {
      await RefreshToken.destroy({
        where: {
          id: oldTokens.map(token => token.id),
        },
      });
    }

    // Store new refresh token
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days

    await RefreshToken.create({
      token: refreshToken,
      userId: user.id,
      expiresAt,
      userAgent: req.get('User-Agent'),
      ipAddress: req.ip || req.connection.remoteAddress,
    });

    // Set refresh token as HttpOnly cookie
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
      path: '/',
    });

    logger.auth('User logged in successfully', {
      userId: user.id,
      email: user.email,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    });

    res.json({
      message: 'Login successful',
      user: {
        id: user.id,
        email: user.email,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
      },
      accessToken,
    });

  } catch (error) {
    logger.error('Login error:', error);
    await trackFailedAttempt(req.bruteForceInfo);
    res.status(500).json({
      error: 'Internal server error during login',
    });
  }
};

/**
 * Refresh expired access token using refresh token
 * Validates refresh token from HttpOnly cookie and generates new access token
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Request cookies
 * @param {string} req.cookies.refreshToken - Refresh token from HttpOnly cookie
 * @param {Object} res - Express response object
 */
const refreshToken = async (req, res) => {
  try {
    // Get refresh token from HttpOnly cookie
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
      return res.status(401).json({
        error: 'Refresh token not provided',
      });
    }

    // Verify refresh token signature
    const decoded = verifyRefreshToken(refreshToken);

    // Check if refresh token exists in database and is active
    const tokenRecord = await RefreshToken.findOne({
      where: { 
        token: refreshToken,
        isActive: true,
      },
      include: [{
        model: User,
        as: 'user',
        attributes: ['id', 'email', 'fullName', 'isActive'],
      }],
    });

    if (!tokenRecord || tokenRecord.isExpired()) {
      return res.status(401).json({
        error: 'Invalid or expired refresh token',
      });
    }

    if (!tokenRecord.user || !tokenRecord.user.isActive) {
      return res.status(401).json({
        error: 'User not found or inactive',
      });
    }

    // Generate new access token
    const tokenPayload = { 
      userId: tokenRecord.user.id, 
      email: tokenRecord.user.email 
    };
    const newAccessToken = generateAccessToken(tokenPayload);

    // Update user cache
    const userData = {
      id: tokenRecord.user.id,
      email: tokenRecord.user.email,
      fullName: tokenRecord.user.fullName,
      isActive: tokenRecord.user.isActive,
      lastLogin: tokenRecord.user.lastLogin,
    };
    await cacheUser(tokenRecord.user.id, userData);

    logger.auth('Token refreshed successfully', {
      userId: tokenRecord.user.id,
      email: tokenRecord.user.email,
      ip: req.ip,
    });

    res.json({
      message: 'Token refreshed successfully',
      accessToken: newAccessToken,
      user: {
        id: tokenRecord.user.id,
        email: tokenRecord.user.email,
        fullName: tokenRecord.user.fullName,
        isActive: tokenRecord.user.isActive,
      },
    });

  } catch (error) {
    logger.error('Token refresh error:', error);
    res.status(401).json({
      error: 'Failed to refresh token',
    });
  }
};

/**
 * Logout user from current device
 * Blacklists access token and invalidates refresh token
 * @param {Object} req - Express request object
 * @param {Object} req.cookies - Request cookies
 * @param {string} req.cookies.refreshToken - Refresh token from HttpOnly cookie
 * @param {string} req.token - Access token from authorization header
 * @param {Object} req.user - Authenticated user data
 * @param {Object} res - Express response object
 */
const logout = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken;
    const accessToken = req.token;

    // Blacklist access token if provided
    if (accessToken) {
      await blacklistToken(accessToken, 900); // 15 minutes (access token TTL)
    }

    // Invalidate refresh token in database
    if (refreshToken) {
      await RefreshToken.update(
        { isActive: false },
        { 
          where: { 
            token: refreshToken,
            isActive: true,
          } 
        }
      );
    }

    // Clear user cache
    if (req.user) {
      await invalidateUserCache(req.user.id);
    }

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    });

    logger.auth('User logged out successfully', {
      userId: req.user?.id,
      email: req.user?.email,
      ip: req.ip,
    });

    res.json({
      message: 'Logout successful',
    });

  } catch (error) {
    logger.error('Logout error:', error);
    res.status(500).json({
      error: 'Internal server error during logout',
    });
  }
};

/**
 * Logout user from all devices
 * Blacklists current access token and invalidates all user's refresh tokens
 * @param {Object} req - Express request object
 * @param {Object} req.user - Authenticated user data
 * @param {string} req.token - Access token from authorization header
 * @param {Object} res - Express response object
 */
const logoutAll = async (req, res) => {
  try {
    const userId = req.user.id;
    const accessToken = req.token;

    // Blacklist current access token
    if (accessToken) {
      await blacklistToken(accessToken, 900);
    }

    // Invalidate all refresh tokens for this user
    await RefreshToken.update(
      { isActive: false },
      { 
        where: { 
          userId: userId,
          isActive: true,
        } 
      }
    );

    // Clear user cache
    await invalidateUserCache(userId);

    // Clear refresh token cookie
    res.clearCookie('refreshToken', {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: process.env.NODE_ENV === 'production' ? 'none' : 'lax',
      path: '/',
    });

    logger.auth('User logged out from all devices', {
      userId: req.user.id,
      email: req.user.email,
      ip: req.ip,
    });

    res.json({
      message: 'Logged out from all devices successfully',
    });

  } catch (error) {
    logger.error('Logout all error:', error);
    res.status(500).json({
      error: 'Internal server error during logout',
    });
  }
};

/**
 * Get current user profile information
 * Uses caching for performance optimization
 * @param {Object} req - Express request object
 * @param {Object} req.user - Authenticated user data
 * @param {Object} res - Express response object
 */
const getProfile = async (req, res) => {
  try {
    const cacheKey = `profile:${req.user.id}`;
    
    // Try to get from cache first
    let profile = await getCachedAPIResponse(cacheKey);
    
    if (!profile) {
      // Get fresh data from database
      const user = await User.findByPk(req.user.id, {
        attributes: ['id', 'email', 'fullName', 'isActive', 'lastLogin', 'createdAt'],
      });

      if (!user) {
        return res.status(404).json({
          error: 'User not found',
        });
      }

      profile = {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
        memberSince: user.createdAt,
      };

      // Cache profile for 5 minutes
      await cacheAPIResponse(cacheKey, profile, 300);
    }

    res.json({
      message: 'Profile retrieved successfully',
      user: profile,
    });

  } catch (error) {
    logger.error('Get profile error:', error);
    res.status(500).json({
      error: 'Internal server error while fetching profile',
    });
  }
};

/**
 * Get user's active sessions (refresh tokens)
 * Shows all devices where user is currently logged in
 * @param {Object} req - Express request object
 * @param {Object} req.user - Authenticated user data
 * @param {Object} req.cookies - Request cookies
 * @param {Object} res - Express response object
 */
const getSessions = async (req, res) => {
  try {
    const sessions = await RefreshToken.findAll({
      where: { 
        userId: req.user.id,
        isActive: true,
      },
      attributes: ['id', 'userAgent', 'ipAddress', 'createdAt', 'expiresAt'],
      order: [['createdAt', 'DESC']],
    });

    res.json({
      message: 'Sessions retrieved successfully',
      sessions: sessions.map(session => ({
        id: session.id,
        userAgent: session.userAgent,
        ipAddress: session.ipAddress,
        createdAt: session.createdAt,
        expiresAt: session.expiresAt,
        isCurrent: req.cookies.refreshToken && 
                   session.token === req.cookies.refreshToken,
      })),
    });

  } catch (error) {
    logger.error('Get sessions error:', error);
    res.status(500).json({
      error: 'Internal server error while fetching sessions',
    });
  }
};

/**
 * Revoke specific user session
 * Allows users to log out from specific devices
 * @param {Object} req - Express request object
 * @param {Object} req.params - Request parameters
 * @param {string} req.params.sessionId - Session ID to revoke
 * @param {Object} req.user - Authenticated user data
 * @param {Object} res - Express response object
 */
const revokeSession = async (req, res) => {
  try {
    const { sessionId } = req.params;
    
    const result = await RefreshToken.update(
      { isActive: false },
      { 
        where: { 
          id: sessionId,
          userId: req.user.id,
          isActive: true,
        } 
      }
    );

    if (result[0] === 0) {
      return res.status(404).json({
        error: 'Session not found or already revoked',
      });
    }

    logger.auth('Session revoked', {
      userId: req.user.id,
      sessionId,
      ip: req.ip,
    });

    res.json({
      message: 'Session revoked successfully',
    });

  } catch (error) {
    logger.error('Revoke session error:', error);
    res.status(500).json({
      error: 'Internal server error while revoking session',
    });
  }
};

/**
 * Export all authentication controller functions
 */
module.exports = {
  register,
  login,
  refreshToken,
  logout,
  logoutAll,
  getProfile,
  getSessions,
  revokeSession,
};