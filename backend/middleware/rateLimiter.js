const rateLimit = require('express-rate-limit');
const { redisClient } = require('../config/db');
const logger = require('../utils/logger');

/**
 * Redis-based store for express-rate-limit
 * Provides distributed rate limiting across multiple server instances
 */
class RedisStore {
  /**
   * Initialize Redis store for rate limiting
   * @param {Object} options - Store configuration options
   * @param {string} options.prefix - Redis key prefix for rate limit data
   */
  constructor(options = {}) {
    this.prefix = options.prefix || 'rl:';
    this.client = redisClient;
  }

  /**
   * Increment rate limit counter for a given key
   * @param {string} key - Unique identifier for rate limiting (usually IP or IP+email)
   * @returns {Promise<Object>} Object containing totalHits and resetTime
   */
  async increment(key) {
    const fullKey = this.prefix + key;
    const current = await this.client.incr(fullKey);
    
    // Set expiration on first increment
    if (current === 1) {
      await this.client.expire(fullKey, 300); // 5 minutes window
    }
    
    const ttl = await this.client.ttl(fullKey);
    return {
      totalHits: current,
      resetTime: new Date(Date.now() + ttl * 1000),
    };
  }

  /**
   * Decrement rate limit counter for a given key
   * @param {string} key - Unique identifier for rate limiting
   * @returns {Promise<number>} Updated counter value (minimum 0)
   */
  async decrement(key) {
    const fullKey = this.prefix + key;
    const current = await this.client.decr(fullKey);
    return Math.max(0, current);
  }

  /**
   * Reset rate limit counter for a given key
   * @param {string} key - Unique identifier for rate limiting
   * @returns {Promise<void>}
   */
  async resetKey(key) {
    const fullKey = this.prefix + key;
    await this.client.del(fullKey);
  }
}

/**
 * General API rate limiter for all endpoints
 * Prevents API abuse with moderate limits
 * @type {Function}
 */
const generalLimiter = rateLimit({
  store: new RedisStore({ prefix: 'api:' }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // 100 requests per window per IP
  message: {
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return req.ip || req.connection.remoteAddress;
  },
});

/**
 * Strict authentication rate limiter
 * Prevents brute force attacks on login/auth endpoints
 * @type {Function}
 */
const authLimiter = rateLimit({
  store: new RedisStore({ prefix: 'auth:' }),
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // 5 attempts per window
  message: {
    error: 'Too many authentication attempts, please try again in 5 minutes.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    // Rate limit by IP + email combination for precise control
    const email = req.body?.email?.toLowerCase() || '';
    const ip = req.ip || req.connection.remoteAddress;
    return `${ip}:${email}`;
  },
  skipSuccessfulRequests: true, // Don't count successful logins against limit
});

/**
 * Registration rate limiter
 * Prevents automated account creation and spam
 * @type {Function}
 */
const registerLimiter = rateLimit({
  store: new RedisStore({ prefix: 'register:' }),
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 registrations per hour per IP
  message: {
    error: 'Too many registration attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Password reset rate limiter
 * Prevents abuse of password reset functionality
 * @type {Function}
 */
const passwordResetLimiter = rateLimit({
  store: new RedisStore({ prefix: 'reset:' }),
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 3, // 3 reset attempts per window
  message: {
    error: 'Too many password reset attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * Brute force protection middleware using Redis
 * Tracks failed login attempts per IP and email to prevent credential stuffing
 * @param {Object} req - Express request object
 * @param {Object} req.body - Request body
 * @param {string} req.body.email - Email address being attempted
 * @param {string} req.ip - Client IP address
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 */
const bruteForceProtection = async (req, res, next) => {
  const email = req.body?.email?.toLowerCase();
  const ip = req.ip || req.connection.remoteAddress;
  
  if (!email) {
    return next();
  }

  try {
    // Check for IP-based blocks (protects against distributed attacks)
    const ipKey = `brute:ip:${ip}`;
    const ipAttempts = await redisClient.get(ipKey);
    
    if (ipAttempts && parseInt(ipAttempts) >= 20) { // 20 attempts per IP
      logger.security('IP blocked due to brute force', { 
        ip, 
        attempts: ipAttempts,
        email 
      });
      return res.status(429).json({
        error: 'IP temporarily blocked due to suspicious activity',
      });
    }

    // Check for email-based blocks (protects individual accounts)
    const emailKey = `brute:email:${email}`;
    const emailAttempts = await redisClient.get(emailKey);
    
    if (emailAttempts && parseInt(emailAttempts) >= 10) { // 10 attempts per email
      logger.security('Account locked due to brute force', { 
        email, 
        attempts: emailAttempts,
        ip 
      });
      return res.status(429).json({
        error: 'Account temporarily locked due to multiple failed attempts',
      });
    }

    // Store attempts info for use in auth controller
    req.bruteForceInfo = {
      ipKey,
      emailKey,
      ipAttempts: parseInt(ipAttempts) || 0,
      emailAttempts: parseInt(emailAttempts) || 0,
    };

    next();
  } catch (error) {
    logger.error('Brute force protection error:', error);
    next(); // Continue on Redis error to avoid blocking legitimate users
  }
};

/**
 * Export rate limiting middleware functions
 */
module.exports = {
  generalLimiter,
  authLimiter,
  registerLimiter,
  passwordResetLimiter,
  bruteForceProtection,
};