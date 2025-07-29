const { redisClient } = require('../config/db');
const logger = require('../utils/logger');

/**
 * Email enumeration protection for registration endpoints
 * Normalizes response times to prevent attackers from distinguishing existing vs new users
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const registrationTimingAttack = async (req, res, next) => {
  // Track processing start time
  const startTime = Date.now();
  
  // Store original res.json method for response time normalization
  const originalJson = res.json;
  
  /**
   * Override res.json to add artificial delay for timing attack prevention
   * @param {Object} data - Response data to send
   */
  res.json = function(data) {
    const processingTime = Date.now() - startTime;
    const targetTime = 800; // Target 800ms response time
    
    if (processingTime < targetTime) {
      const delay = targetTime - processingTime;
      setTimeout(() => {
        originalJson.call(this, data);
      }, delay);
    } else {
      originalJson.call(this, data);
    }
  };
  
  next();
};

/**
 * Suspicious activity detection middleware
 * Monitors for email enumeration attempts and other suspicious patterns
 * @param {Object} req - Express request object
 * @param {string} req.path - Request path
 * @param {Object} req.body - Request body
 * @param {string} req.body.email - Email address from request
 * @param {string} req.ip - Client IP address
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const detectSuspiciousActivity = async (req, res, next) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const endpoint = req.path;
    const email = req.body?.email?.toLowerCase();
    
    // Track different emails from same IP (potential enumeration attack)
    if (endpoint === '/register' && email) {
      const key = `enum_protection:${ip}`;
      const emails = await redisClient.sMembers(key);
      
      if (!emails.includes(email)) {
        await redisClient.sAdd(key, email);
        await redisClient.expire(key, 3600); // 1 hour expiration
      }
      
      // If same IP tries > 10 different emails in 1 hour, flag as suspicious
      const emailCount = await redisClient.sCard(key);
      if (emailCount > 10) {
        logger.security('Suspicious enumeration activity detected', {
          ip,
          emailCount,
          endpoint,
          lastEmail: email,
        });
        
        // Block with extra rate limiting
        return res.status(429).json({
          error: 'Too many registration attempts. Please try again later.',
        });
      }
    }
    
    next();
  } catch (error) {
    logger.error('Suspicious activity detection error:', error);
    next(); // Continue on error to avoid blocking legitimate users
  }
};

/**
 * Generic error response sanitizer to prevent information leakage
 * Ensures internal errors are not exposed to clients in production
 * @param {Error} error - Error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const sanitizeErrorResponse = (error, req, res, next) => {
  // Only sanitize errors in production environment
  if (process.env.NODE_ENV === 'production') {
    // Log detailed error internally for debugging
    logger.error('Internal error occurred:', {
      error: error.message,
      stack: error.stack,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      path: req.path,
      method: req.method,
      body: req.body,
    });
    
    // Return generic error message to client
    if (!res.headersSent) {
      return res.status(500).json({
        error: 'An internal error occurred. Please try again later.',
      });
    }
  }
  
  next(error);
};

/**
 * Honeypot field detection for bot protection
 * Detects automated submissions by checking for filled honeypot fields
 * @param {Object} req - Express request object
 * @param {Object} req.body - Request body
 * @param {string} req.ip - Client IP address
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const honeypotProtection = (req, res, next) => {
  // List of honeypot fields that should remain empty
  const honeypotFields = ['website', 'url', 'homepage', 'company'];
  
  for (const field of honeypotFields) {
    if (req.body[field] && req.body[field].trim() !== '') {
      // Silent detection - don't reveal to bots that they've been caught
      logger.security('Honeypot field triggered - bot detected', {
        ip: req.ip,
        field,
        value: req.body[field],
        userAgent: req.get('User-Agent'),
      });
      
      // Return fake success response to avoid bot detection
      return res.status(201).json({
        message: 'Registration successful. Please check your email.',
      });
    }
  }
  
  next();
};

/**
 * Automation detection based on request timing patterns
 * Analyzes request intervals to identify potential bot behavior
 * @param {Object} req - Express request object
 * @param {string} req.ip - Client IP address
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const automationDetection = async (req, res, next) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    const key = `automation:${ip}`;
    
    // Track request timestamps for interval analysis
    const now = Date.now();
    const intervals = await redisClient.lRange(key, 0, -1);
    
    // Add current timestamp to the list
    await redisClient.lPush(key, now.toString());
    await redisClient.lTrim(key, 0, 9); // Keep last 10 requests
    await redisClient.expire(key, 300); // 5 minutes expiration
    
    // Analyze request intervals for automation patterns
    if (intervals.length >= 5) {
      const recentIntervals = intervals.slice(0, 4).map(Number);
      const timeDiffs = [];
      
      // Calculate time differences between consecutive requests
      for (let i = 0; i < recentIntervals.length - 1; i++) {
        timeDiffs.push(Math.abs(recentIntervals[i] - recentIntervals[i + 1]));
      }
      
      // Calculate average interval and variance
      const avgInterval = timeDiffs.reduce((a, b) => a + b, 0) / timeDiffs.length;
      const variance = timeDiffs.reduce((sum, diff) => sum + Math.pow(diff - avgInterval, 2), 0) / timeDiffs.length;
      
      // If intervals are too consistent (low variance) and fast, likely automation
      if (variance < 10000 && avgInterval < 2000) { // Very consistent < 2s intervals
        logger.security('Potential automation detected', {
          ip,
          userAgent,
          avgInterval,
          variance,
          requestCount: intervals.length,
        });
        
        // Add random delay for suspected automated requests
        const delay = Math.random() * 2000 + 1000; // 1-3 second random delay
        await new Promise(resolve => setTimeout(resolve, delay));
      }
    }
    
    next();
  } catch (error) {
    logger.error('Automation detection error:', error);
    next(); // Continue on error
  }
};

/**
 * Advanced request fingerprinting for anomaly detection
 * Analyzes request patterns to identify suspicious behavior
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const requestFingerprinting = async (req, res, next) => {
  try {
    const ip = req.ip || req.connection.remoteAddress;
    const userAgent = req.get('User-Agent') || '';
    const acceptLanguage = req.get('Accept-Language') || '';
    const acceptEncoding = req.get('Accept-Encoding') || '';
    
    // Create request fingerprint
    const fingerprint = {
      ip,
      userAgent,
      acceptLanguage,
      acceptEncoding,
      timestamp: Date.now(),
    };
    
    // Store fingerprint for analysis (optional - can be used for advanced security)
    const fingerprintKey = `fingerprint:${ip}`;
    await redisClient.lPush(fingerprintKey, JSON.stringify(fingerprint));
    await redisClient.lTrim(fingerprintKey, 0, 99); // Keep last 100 fingerprints
    await redisClient.expire(fingerprintKey, 86400); // 24 hours
    
    // Attach fingerprint to request for other middleware to use
    req.fingerprint = fingerprint;
    
    next();
  } catch (error) {
    logger.error('Request fingerprinting error:', error);
    next();
  }
};

/**
 * Export security middleware functions
 */
module.exports = {
  registrationTimingAttack,
  detectSuspiciousActivity,
  sanitizeErrorResponse,
  honeypotProtection,
  automationDetection,
  requestFingerprinting,
};