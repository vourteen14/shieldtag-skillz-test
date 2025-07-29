const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');
const logger = require('../utils/logger');

/**
 * RefreshToken Sequelize Model Definition
 * @typedef {Object} RefreshTokenModel
 * @property {string} id - UUID primary key
 * @property {string} token - JWT refresh token string
 * @property {string} userId - Foreign key reference to User model
 * @property {Date} expiresAt - Token expiration timestamp
 * @property {boolean} isActive - Token activation status
 * @property {string} userAgent - Browser/client user agent string
 * @property {string} ipAddress - Client IP address when token was created
 * @property {Date} createdAt - Token creation timestamp
 * @property {Date} updatedAt - Last token update timestamp
 */
const RefreshToken = sequelize.define('RefreshToken', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    comment: 'Primary key - UUID for security and scalability',
  },
  token: {
    type: DataTypes.TEXT,
    allowNull: false,
    unique: true,
    comment: 'JWT refresh token string - stored for validation and revocation',
  },
  userId: {
    type: DataTypes.UUID,
    allowNull: false,
    comment: 'Foreign key reference to users table',
    references: {
      model: 'users',
      key: 'id',
    },
  },
  expiresAt: {
    type: DataTypes.DATE,
    allowNull: false,
    comment: 'Token expiration timestamp - typically 7 days from creation',
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    comment: 'Token activation status - false for revoked/logged out tokens',
  },
  userAgent: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Client user agent string for device identification',
  },
  ipAddress: {
    type: DataTypes.STRING,
    allowNull: true,
    comment: 'Client IP address for security monitoring',
  },
}, {
  tableName: 'refresh_tokens',
  timestamps: true,
  indexes: [
    {
      unique: true,
      fields: ['token'],
      name: 'refresh_tokens_token_unique_idx',
    },
    {
      fields: ['userId'],
      name: 'refresh_tokens_user_id_idx',
    },
    {
      fields: ['expiresAt'],
      name: 'refresh_tokens_expires_at_idx',
    },
    {
      fields: ['isActive'],
      name: 'refresh_tokens_is_active_idx',
    },
    {
      fields: ['userId', 'isActive'],
      name: 'refresh_tokens_user_active_idx',
    },
  ],
  comment: 'Refresh tokens table for JWT session management',
});

/**
 * Check if refresh token has expired
 * Compares expiration time with current time
 * @returns {boolean} True if token has expired
 */
RefreshToken.prototype.isExpired = function() {
  return this.expiresAt < new Date();
};

/**
 * Check if refresh token is valid for use
 * Validates both expiration and active status
 * @returns {boolean} True if token is valid and can be used
 */
RefreshToken.prototype.isValid = function() {
  return this.isActive && !this.isExpired();
};

/**
 * Revoke this specific refresh token
 * Sets isActive to false without deleting the record for audit purposes
 * @returns {Promise<RefreshTokenModel>} Updated token instance
 */
RefreshToken.prototype.revoke = function() {
  return this.update({ isActive: false });
};

/**
 * Get device information from user agent string
 * Extracts basic device/browser info for session display
 * @returns {Object} Parsed device information
 */
RefreshToken.prototype.getDeviceInfo = function() {
  const userAgent = this.userAgent || '';
  
  // Basic device detection (can be enhanced with a proper library)
  const isMobile = /Mobile|Android|iPhone|iPad/i.test(userAgent);
  const isTablet = /iPad|Tablet/i.test(userAgent);
  const browser = userAgent.match(/(Chrome|Firefox|Safari|Edge|Opera)/i)?.[1] || 'Unknown';
  
  return {
    deviceType: isTablet ? 'Tablet' : isMobile ? 'Mobile' : 'Desktop',
    browser,
    userAgent: userAgent.substring(0, 100), // Truncate for display
  };
};

/**
 * Static method to cleanup expired refresh tokens
 * Removes old tokens to maintain database hygiene
 * @returns {Promise<number>} Number of tokens cleaned up
 */
RefreshToken.cleanup = async function() {
  try {
    const result = await this.destroy({
      where: {
        expiresAt: {
          [sequelize.Sequelize.Op.lt]: new Date(),
        },
      },
    });
    
    if (result > 0) {
      logger.info('Cleaned up expired refresh tokens', { count: result });
    }
    
    return result;
  } catch (error) {
    logger.error('Error cleaning up expired tokens:', error);
    return 0;
  }
};

/**
 * Static method to revoke all tokens for a specific user
 * Used for "logout from all devices" functionality
 * @param {string} userId - User ID to revoke tokens for
 * @returns {Promise<number>} Number of tokens revoked
 */
RefreshToken.revokeAllForUser = async function(userId) {
  try {
    const [affectedRows] = await this.update(
      { isActive: false },
      {
        where: {
          userId,
          isActive: true,
        },
      }
    );
    
    logger.info('Revoked all tokens for user', { userId, count: affectedRows });
    return affectedRows;
  } catch (error) {
    logger.error('Error revoking user tokens:', error);
    return 0;
  }
};

/**
 * Static method to find active tokens for a user
 * Returns all valid sessions for session management
 * @param {string} userId - User ID to find tokens for
 * @returns {Promise<RefreshTokenModel[]>} Array of active tokens
 */
RefreshToken.findActiveForUser = async function(userId) {
  return this.findAll({
    where: {
      userId,
      isActive: true,
      expiresAt: {
        [sequelize.Sequelize.Op.gt]: new Date(),
      },
    },
    order: [['createdAt', 'DESC']],
  });
};

/**
 * Static method to cleanup old tokens for a user (keep only N most recent)
 * Maintains reasonable number of active sessions per user
 * @param {string} userId - User ID to cleanup tokens for
 * @param {number} keepCount - Number of recent tokens to keep (default: 5)
 * @returns {Promise<number>} Number of tokens cleaned up
 */
RefreshToken.cleanupOldForUser = async function(userId, keepCount = 5) {
  try {
    const oldTokens = await this.findAll({
      where: { userId },
      order: [['createdAt', 'DESC']],
      offset: keepCount,
    });

    if (oldTokens.length > 0) {
      const result = await this.destroy({
        where: {
          id: oldTokens.map(token => token.id),
        },
      });
      
      logger.debug('Cleaned up old tokens for user', { 
        userId, 
        cleaned: result, 
        kept: keepCount 
      });
      
      return result;
    }
    
    return 0;
  } catch (error) {
    logger.error('Error cleaning up old user tokens:', error);
    return 0;
  }
};

/**
 * Static method to get session statistics
 * Provides analytics data about active sessions
 * @returns {Promise<Object>} Session statistics
 */
RefreshToken.getSessionStats = async function() {
  try {
    const totalActive = await this.count({
      where: {
        isActive: true,
        expiresAt: {
          [sequelize.Sequelize.Op.gt]: new Date(),
        },
      },
    });

    const totalExpired = await this.count({
      where: {
        expiresAt: {
          [sequelize.Sequelize.Op.lt]: new Date(),
        },
      },
    });

    const totalRevoked = await this.count({
      where: {
        isActive: false,
      },
    });

    return {
      active: totalActive,
      expired: totalExpired,
      revoked: totalRevoked,
      total: totalActive + totalExpired + totalRevoked,
    };
  } catch (error) {
    logger.error('Error getting session stats:', error);
    return {
      active: 0,
      expired: 0,
      revoked: 0,
      total: 0,
    };
  }
};

module.exports = RefreshToken;