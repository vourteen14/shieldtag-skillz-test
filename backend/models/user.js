const { DataTypes } = require('sequelize');
const { sequelize } = require('../config/db');

/**
 * User Sequelize Model Definition
 * @typedef {Object} UserModel
 * @property {string} id - UUID primary key
 * @property {string} email - Unique email address with validation
 * @property {string} fullName - User's display name
 * @property {string} password - Hashed password using argon2
 * @property {boolean} isActive - Account activation status
 * @property {Date} lastLogin - Timestamp of last successful login
 * @property {number} loginAttempts - Counter for failed login attempts
 * @property {Date} lockUntil - Account lock expiration timestamp
 * @property {Date} createdAt - Account creation timestamp
 * @property {Date} updatedAt - Last account update timestamp
 */
const User = sequelize.define('User', {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
    comment: 'Primary key - UUID for security and scalability',
  },
  email: {
    type: DataTypes.STRING,
    allowNull: false,
    unique: true,
    validate: {
      isEmail: true,
      len: [5, 255],
    },
    comment: 'User email address - unique identifier for authentication',
  },
  fullName: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [2, 100],
      notEmpty: true,
    },
    comment: 'User display name with length validation',
  },
  password: {
    type: DataTypes.STRING,
    allowNull: false,
    validate: {
      len: [6, 255],
    },
    comment: 'Hashed password using argon2 algorithm',
  },
  isActive: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
    comment: 'Account activation status - false for deactivated accounts',
  },
  lastLogin: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Timestamp of last successful authentication',
  },
  loginAttempts: {
    type: DataTypes.INTEGER,
    defaultValue: 0,
    comment: 'Counter for failed login attempts - used for account locking',
  },
  lockUntil: {
    type: DataTypes.DATE,
    allowNull: true,
    comment: 'Account lock expiration timestamp - null if not locked',
  },
}, {
  tableName: 'users',
  timestamps: true,
  indexes: [
    {
      unique: true,
      fields: ['email'],
      name: 'users_email_unique_idx',
    },
    {
      fields: ['isActive'],
      name: 'users_is_active_idx',
    },
    {
      fields: ['lockUntil'],
      name: 'users_lock_until_idx',
    },
  ],
  comment: 'User accounts table with security features',
});

/**
 * Check if user account is currently locked
 * Compares lock expiration time with current time
 * @returns {boolean} True if account is locked and lock hasn't expired
 */
User.prototype.isLocked = function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

/**
 * Increment login attempt counter and implement progressive account locking
 * Locks account after 5 failed attempts for 2 hours
 * @returns {Promise<UserModel>} Updated user instance with incremented attempts
 */
User.prototype.incLoginAttempts = function() {
  // If previous lock has expired, restart attempt counter
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.update({
      loginAttempts: 1,
      lockUntil: null,
    });
  }
  
  const updates = { loginAttempts: this.loginAttempts + 1 };
  
  // Lock account if maximum attempts reached and not already locked
  if (this.loginAttempts + 1 >= 5 && !this.isLocked()) {
    updates.lockUntil = Date.now() + (2 * 60 * 60 * 1000); // 2 hours lock
  }
  
  return this.update(updates);
};

/**
 * Reset login attempts and update last login timestamp
 * Called after successful authentication
 * @returns {Promise<UserModel>} Updated user instance with reset attempts
 */
User.prototype.resetLoginAttempts = function() {
  return this.update({
    loginAttempts: 0,
    lockUntil: null,
    lastLogin: new Date(),
  });
};

/**
 * Get user's public profile data (safe for API responses)
 * Excludes sensitive information like password and login attempts
 * @returns {Object} Public user profile data
 */
User.prototype.getPublicProfile = function() {
  return {
    id: this.id,
    email: this.email,
    fullName: this.fullName,
    isActive: this.isActive,
    lastLogin: this.lastLogin,
    memberSince: this.createdAt,
  };
};

/**
 * Check if user can perform login (not locked and active)
 * @returns {boolean} True if user can attempt login
 */
User.prototype.canLogin = function() {
  return this.isActive && !this.isLocked();
};

/**
 * Static method to find user by email with case-insensitive search
 * @param {string} email - Email address to search for
 * @returns {Promise<UserModel|null>} User instance or null if not found
 */
User.findByEmail = async function(email) {
  return this.findOne({
    where: {
      email: email.toLowerCase().trim(),
    },
  });
};

/**
 * Static method to get active users count for analytics
 * @returns {Promise<number>} Number of active user accounts
 */
User.getActiveUsersCount = async function() {
  return this.count({
    where: {
      isActive: true,
    },
  });
};

module.exports = User;