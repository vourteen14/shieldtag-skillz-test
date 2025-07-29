const { Sequelize } = require('sequelize');
const redis = require('redis');
const logger = require('../utils/logger');
require('dotenv').config();

/**
 * Sequelize configuration object for different environments
 * @type {Object.<string, Object>}
 */
const dbConfig = {
  development: {
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    dialect: 'postgres',
    logging: (msg) => logger.debug('DB Query:', { query: msg }),
    pool: {
      max: 5,
      min: 0,
      acquire: 30000,
      idle: 10000,
    },
  },
  test: {
    username: process.env.DB_USER || 'postgres',
    password: process.env.DB_PASSWORD || 'password',
    database: process.env.DB_NAME_TEST || 'auth_db_test',
    host: process.env.DB_HOST || 'localhost',
    port: process.env.DB_PORT || 5432,
    dialect: 'postgres',
    logging: false,
  },
  production: {
    username: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    host: process.env.DB_HOST,
    port: process.env.DB_PORT || 5432,
    dialect: 'postgres',
    logging: false,
    pool: {
      max: 20,
      min: 5,
      acquire: 30000,
      idle: 10000,
    },
    dialectOptions: {
      ssl: process.env.DB_SSL === 'true' ? {
        require: true,
        rejectUnauthorized: false,
      } : false,
    },
  },
};

// Get current environment configuration
const currentEnv = process.env.NODE_ENV || 'development';
const currentConfig = dbConfig[currentEnv];

/**
 * PostgreSQL Sequelize instance
 * @type {Sequelize}
 */
const sequelize = new Sequelize(
  currentConfig.database,
  currentConfig.username,
  currentConfig.password,
  currentConfig
);

/**
 * Redis client instance for caching and rate limiting
 * @type {RedisClientType}
 */
const redisClient = redis.createClient({
  url: process.env.REDIS_URL,
  password: process.env.REDIS_PASSWORD || undefined,
});

/**
 * Redis event handlers for connection monitoring
 */
redisClient.on('error', (err) => {
  logger.error('Redis Client Error:', err);
});

redisClient.on('connect', () => {
  logger.info('Redis connected successfully');
});

/**
 * Establish Redis connection with error handling
 * @returns {Promise<void>}
 * @throws {Error} If Redis connection fails
 */
const connectRedis = async () => {
  try {
    await redisClient.connect();
  } catch (error) {
    logger.error('Redis connection failed:', error);
    throw error;
  }
};

/**
 * Test PostgreSQL database connection and verify tables
 * @returns {Promise<void>}
 * @throws {Error} If database connection fails
 */
const connectDB = async () => {
  try {
    await sequelize.authenticate();
    logger.info('PostgreSQL connected successfully');
    
    // Verify tables exist in development environment
    if (process.env.NODE_ENV === 'development') {
      try {
        await sequelize.query('SELECT 1 FROM users LIMIT 1');
        logger.info('Database tables verified');
      } catch (error) {
        logger.warn('Tables not found. Run migrations: npm run db:migrate');
      }
    }
  } catch (error) {
    logger.error('Database connection failed:', error);
    throw error;
  }
};

/**
 * Export configuration for Sequelize CLI
 * @type {Object.<string, Object>}
 */
module.exports = dbConfig;

/**
 * Export database instances for application use
 */
module.exports.sequelize = sequelize;
module.exports.redisClient = redisClient;
module.exports.connectDB = connectDB;
module.exports.connectRedis = connectRedis;