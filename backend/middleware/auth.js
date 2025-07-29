const { verifyAccessToken, getCachedUser, cacheUser, isTokenBlacklisted } = require('../utils/jwt');
const { User } = require('../models');
const logger = require('../utils/logger');

/**
 * Middleware to authenticate JWT access tokens
 * Verifies token signature, checks blacklist, and attaches user data to request
 * @param {Object} req - Express request object
 * @param {Object} req.headers - Request headers
 * @param {string} req.headers.authorization - Bearer token authorization header
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void|Object} Continues to next middleware or returns error response
 */
const authenticateToken = async (req, res, next) => {
  try {
    // Extract token from Authorization header (Bearer TOKEN)
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'Access token required',
      });
    }

    // Check if token has been blacklisted (logged out)
    const blacklisted = await isTokenBlacklisted(token);
    if (blacklisted) {
      return res.status(401).json({
        error: 'Token has been revoked',
      });
    }

    // Verify JWT token signature and decode payload
    const decoded = verifyAccessToken(token);
    
    // Try to get user data from Redis cache first
    let userData = await getCachedUser(decoded.userId);
    
    if (!userData) {
      // Cache miss - fetch user from database
      const user = await User.findByPk(decoded.userId, {
        attributes: ['id', 'email', 'fullName', 'isActive', 'lastLogin'],
      });

      if (!user || !user.isActive) {
        return res.status(401).json({
          error: 'User not found or inactive',
        });
      }

      userData = {
        id: user.id,
        email: user.email,
        fullName: user.fullName,
        isActive: user.isActive,
        lastLogin: user.lastLogin,
      };

      // Cache user data for future requests (15 minutes)
      await cacheUser(user.id, userData, 900);
    }

    // Attach user data and token to request object
    req.user = userData;
    req.token = token;

    next();
  } catch (error) {
    logger.debug('Authentication error:', { error: error.message });
    
    // Handle specific JWT errors
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        error: 'Access token expired',
        code: 'TOKEN_EXPIRED',
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        error: 'Invalid access token',
        code: 'INVALID_TOKEN',
      });
    }

    return res.status(401).json({
      error: 'Authentication failed',
    });
  }
};

/**
 * Optional authentication middleware
 * Attempts to authenticate but doesn't fail if no token is provided
 * Useful for endpoints that work for both authenticated and anonymous users
 * @param {Object} req - Express request object
 * @param {Object} req.headers - Request headers
 * @param {string} req.headers.authorization - Bearer token authorization header (optional)
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      req.user = null;
      return next();
    }

    // Check if token is blacklisted
    const blacklisted = await isTokenBlacklisted(token);
    if (blacklisted) {
      req.user = null;
      return next();
    }

    const decoded = verifyAccessToken(token);
    
    // Try cache first
    let userData = await getCachedUser(decoded.userId);
    
    if (!userData) {
      const user = await User.findByPk(decoded.userId, {
        attributes: ['id', 'email', 'fullName', 'isActive', 'lastLogin'],
      });

      if (user && user.isActive) {
        userData = {
          id: user.id,
          email: user.email,
          fullName: user.fullName,
          isActive: user.isActive,
          lastLogin: user.lastLogin,
        };
        await cacheUser(user.id, userData, 900);
      }
    }

    req.user = userData;
    req.token = token;
    next();
  } catch (error) {
    // On any error in optional auth, just set user as null and continue
    req.user = null;
    next();
  }
};

/**
 * Admin role middleware (for future role-based access control)
 * Ensures authenticated user has admin privileges
 * @param {Object} req - Express request object
 * @param {Object} req.user - Authenticated user data (set by authenticateToken)
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void|Object} Continues to next middleware or returns error response
 */
const requireAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({
      error: 'Authentication required',
    });
  }

  // TODO: Add admin role check logic here when implementing RBAC
  // Example: if (!req.user.isAdmin) { return res.status(403).json({ error: 'Admin access required' }); }
  
  next();
};

/**
 * Export authentication middleware functions
 */
module.exports = {
  authenticateToken,
  optionalAuth,
  requireAdmin,
};