const { sequelize } = require('../config/db');
const User = require('./user');
const RefreshToken = require('./token');

/**
 * Model collection with sequelize instance
 * Contains all registered models and the database connection
 * @type {Object}
 * @property {typeof User} User - User model class
 * @property {typeof RefreshToken} RefreshToken - RefreshToken model class
 * @property {Sequelize} sequelize - Sequelize database instance
 */
const models = {
  User,
  RefreshToken,
  sequelize,
};

/**
 * Initialize model associations if not already established
 * Sets up the foreign key relationships between User and RefreshToken models
 * This creates a one-to-many relationship: User hasMany RefreshTokens
 */
if (!User.associations.refreshTokens) {
  // RefreshToken belongs to User (many-to-one relationship)
  RefreshToken.belongsTo(User, { 
    foreignKey: 'userId', 
    as: 'user',
    onDelete: 'CASCADE', // Delete tokens when user is deleted
    onUpdate: 'CASCADE', // Update tokens when user ID changes
  });
  
  // User has many RefreshTokens (one-to-many relationship)
  User.hasMany(RefreshToken, { 
    foreignKey: 'userId', 
    as: 'refreshTokens',
    onDelete: 'CASCADE', // Delete tokens when user is deleted
    onUpdate: 'CASCADE', // Update tokens when user ID changes
  });
}

/**
 * Export models collection for application use
 * Other modules can import specific models: const { User, RefreshToken } = require('./models')
 * Or import the entire collection: const models = require('./models')
 */
module.exports = models;