const jwt = require('jsonwebtoken');
const { redisClient } = require('../config/db');
const logger = require('./logger');
require('dotenv').config();

/**
 * Generate JWT access token with short expiration
 * Used for API authentication with 15-minute lifetime
 * @param {Object} payload - Token payload data
 * @param {string} payload.userId - User UUID
 * @param {string} payload.email - User email address
 * @returns {string} Signed JWT access token
 */
const generateAccessToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_ACCESS_SECRET, {
    expiresIn: process.env.JWT_ACCESS_EXPIRES_IN,
    issuer: 'auth-backend',
    audience: 'auth-frontend',
  });
};

/**
 * Generate JWT refresh token with long expiration
 * Used for token refresh with 7-day lifetime
 * @param {Object} payload - Token payload data
 * @param {string} payload.userId - User UUID
 * @param {string} payload.email - User email address
 * @returns {string} Signed JWT refresh token
 */
const generateRefreshToken = (payload) => {
  return jwt.sign(payload, process.env.JWT_REFRESH_SECRET, {
    expiresIn: process.env.JWT_REFRESH_EXPIRES_IN,
    issuer: 'auth-backend',
    audience: 'auth-frontend',
  });
};

/**
 * Verify and decode JWT access token
 * Validates token signature and expiration
 * @param {string} token - JWT access token to verify
 * @returns {Object} Decoded token payload
 * @throws {Error} If token is invalid or expired
 */
const verifyAccessToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_ACCESS_SECRET, {
      issuer: 'auth-backend',
      audience: 'auth-frontend',
    });
  } catch (error) {
    throw new Error('Invalid access token');
  }
};

/**
 * Verify and decode JWT refresh token
 * Validates token signature and expiration
 * @param {string} token - JWT refresh token to verify
 * @returns {Object} Decoded token payload
 * @throws {Error} If token is invalid or expired
 */
const verifyRefreshToken = (token) => {
  try {
    return jwt.verify(token, process.env.JWT_REFRESH_SECRET, {
      issuer: 'auth-backend',
      audience: 'auth-frontend',
    });
  } catch (error) {
    throw new Error('Invalid refresh token');
  }
};

/**
 * Cache user data in Redis for performance optimization
 * Reduces database queries for frequently accessed user data
 * @param {string} userId - User UUID to cache data for
 * @param {Object} userData - User data object to cache
 * @param {string} userData.id - User UUID
 * @param {string} userData.email - User email address
 * @param {string} userData.fullName - User display name
 * @param {boolean} userData.isActive - Account activation status
 * @param {Date} userData.lastLogin - Last login timestamp
 * @param {number} ttl - Time to live in seconds (default: 900 = 15 minutes)
 */
const cacheUser = async (userId, userData, ttl = 900) => {
  try {
    const key = `user:${userId}`;
    await redisClient.setEx(key, ttl, JSON.stringify(userData));
    logger.debug('User data cached successfully', { userId, ttl });
  } catch (error) {
    logger.error('Cache error while storing user data:', error);
  }
};

/**
 * Retrieve cached user data from Redis
 * Returns null if cache miss or error occurs
 * @param {string} userId - User UUID to retrieve data for
 * @returns {Promise<Object|null>} Cached user data or null if not found
 */
const getCachedUser = async (userId) => {
  try {
    const key = `user:${userId}`;
    const cached = await redisClient.get(key);
    if (cached) {
      logger.debug('User data retrieved from cache', { userId });
      return JSON.parse(cached);
    }
    return null;
  } catch (error) {
    logger.error('Cache retrieval error for user data:', error);
    return null;
  }
};

/**
 * Invalidate cached user data
 * Used when user data changes or user logs out
 * @param {string} userId - User UUID to invalidate cache for
 */
const invalidateUserCache = async (userId) => {
  try {
    const key = `user:${userId}`;
    await redisClient.del(key);
    logger.debug('User cache invalidated successfully', { userId });
  } catch (error) {
    logger.error('Cache invalidation error for user data:', error);
  }
};

/**
 * Cache API response data for performance optimization
 * Reduces computation time for frequently requested data
 * @param {string} key - Cache key identifier
 * @param {Object} data - Response data to cache
 * @param {number} ttl - Time to live in seconds (default: 300 = 5 minutes)
 */
const cacheAPIResponse = async (key, data, ttl = 300) => {
  try {
    await redisClient.setEx(`api:${key}`, ttl, JSON.stringify(data));
    logger.debug('API response cached successfully', { key, ttl });
  } catch (error) {
    logger.error('API cache error while storing response:', error);
  }
};

/**
 * Retrieve cached API response data
 * Returns null if cache miss or error occurs
 * @param {string} key - Cache key identifier
 * @returns {Promise<Object|null>} Cached response data or null if not found
 */
const getCachedAPIResponse = async (key) => {
  try {
    const cached = await redisClient.get(`api:${key}`);
    if (cached) {
      logger.debug('API response retrieved from cache', { key });
      return JSON.parse(cached);
    }
    return null;
  } catch (error) {
    logger.error('API cache retrieval error:', error);
    return null;
  }
};

/**
 * Blacklist JWT access token to prevent reuse after logout
 * Stores token in Redis with TTL matching token expiration
 * @param {string} token - JWT access token to blacklist
 * @param {number} ttl - Time to live in seconds (should match token expiration)
 */
const blacklistToken = async (token, ttl = 900) => {
  try {
    const key = `blacklist:${token}`;
    await redisClient.setEx(key, ttl, 'blacklisted');
    logger.debug('Token blacklisted successfully');
  } catch (error) {
    logger.error('Token blacklist error:', error);
  }
};

/**
 * Check if JWT access token is blacklisted
 * Used during token verification to reject logged out tokens
 * @param {string} token - JWT access token to check
 * @returns {Promise<boolean>} True if token is blacklisted
 */
const isTokenBlacklisted = async (token) => {
  try {
    const key = `blacklist:${token}`;
    const result = await redisClient.get(key);
    return !!result;
  } catch (error) {
    logger.error('Token blacklist check error:', error);
    return false; // Assume not blacklisted on error to avoid blocking users
  }
};

/**
 * Clear all cached data for a specific user
 * Used during logout or when user data needs complete refresh
 * @param {string} userId - User UUID to clear all cache for
 */
const clearAllUserCache = async (userId) => {
  try {
    const patterns = [
      `user:${userId}`,
      `api:profile:${userId}`,
      `api:sessions:${userId}`,
    ];
    
    for (const pattern of patterns) {
      await redisClient.del(pattern);
    }
    
    logger.debug('All user cache cleared successfully', { userId });
  } catch (error) {
    logger.error('Error clearing all user cache:', error);
  }
};

/**
 * Get cache statistics for monitoring
 * Provides insights into cache performance and usage
 * @returns {Promise<Object>} Cache statistics object
 */
const getCacheStats = async () => {
  try {
    const info = await redisClient.info('memory');
    const keyspace = await redisClient.info('keyspace');
    
    return {
      memory: info,
      keyspace: keyspace,
      timestamp: new Date().toISOString(),
    };
  } catch (error) {
    logger.error('Error getting cache stats:', error);
    return {
      error: 'Unable to retrieve cache statistics',
      timestamp: new Date().toISOString(),
    };
  }
};

/**
 * Export all JWT and caching utility functions
 */
module.exports = {
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  cacheUser,
  getCachedUser,
  invalidateUserCache,
  cacheAPIResponse,
  getCachedAPIResponse,
  blacklistToken,
  isTokenBlacklisted,
  clearAllUserCache,
  getCacheStats,
};