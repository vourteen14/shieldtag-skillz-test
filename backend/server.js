/**
 * Express.js Authentication Backend Server
 * Production-ready authentication system with JWT, Redis caching, and PostgreSQL
 * @author Backend Team
 * @version 1.0.0
 */

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { connectDB, connectRedis } = require('./config/db');
const { generalLimiter } = require('./middleware/rateLimiter');
const authRoutes = require('./routes/authRoutes');
const { RefreshToken } = require('./models');
const logger = require('./utils/logger');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;

/**
 * Configure Express.js application with security middleware and routes
 */
const configureApp = () => {
  // Trust proxy for rate limiting and IP detection
  app.set('trust proxy', 1);

  // Security middleware configuration
  app.use(helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        styleSrc: ["'self'", "'unsafe-inline'"],
        scriptSrc: ["'self'"],
        imgSrc: ["'self'", "data:", "https:"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
  }));

  // CORS configuration for frontend communication
  const corsOptions = {
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, etc.)
      if (!origin) return callback(null, true);
      
      const allowedOrigins = [
        process.env.FRONTEND_URL,
        'http://localhost:3000',
        'http://localhost:3001',
        'http://localhost:3002',
      ].filter(Boolean);

      if (allowedOrigins.includes(origin)) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    },
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization', 'X-Requested-With'],
    exposedHeaders: ['Set-Cookie'],
    optionsSuccessStatus: 200,
  };

  app.use(cors(corsOptions));

  // Body parsing middleware with size limits
  app.use(express.json({ 
    limit: '10mb',
    strict: true,
  }));
  app.use(express.urlencoded({ 
    extended: true,
    limit: '10mb',
  }));

  // Cookie parsing middleware for refresh tokens
  app.use(cookieParser());

  // Apply general rate limiting
  app.use(generalLimiter);

  // Development request logging
  if (process.env.NODE_ENV === 'development') {
    app.use((req, res, next) => {
      logger.debug(`${req.method} ${req.url}`, { ip: req.ip });
      next();
    });
  }
};

/**
 * Configure application routes and endpoints
 */
const configureRoutes = () => {
  // Health check endpoint
  app.get('/health', (req, res) => {
    res.json({
      status: 'healthy',
      timestamp: new Date().toISOString(),
      service: 'auth-backend',
      environment: process.env.NODE_ENV,
    });
  });

  // Authentication API routes
  app.use('/api/auth', authRoutes);

  // 404 handler for undefined routes
  app.use((req, res) => {
    logger.warn('Route not found', {
      method: req.method,
      url: req.originalUrl,
      ip: req.ip,
    });
    res.status(404).json({
      error: 'Endpoint not found',
      path: req.originalUrl,
      method: req.method,
    });
  });
};

/**
 * Global error handler for application-wide error management
 * @param {Error} error - The error object
 * @param {Object} req - Express request object
 * @param {Object} res - Express response object
 * @param {Function} next - Express next function
 */
const configureErrorHandling = () => {
  app.use((error, req, res, next) => {
    logger.error('Global error handler triggered', {
      error: error.message,
      stack: process.env.NODE_ENV === 'development' ? error.stack : undefined,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
    });

    // Handle specific error types
    if (error.message === 'Not allowed by CORS') {
      return res.status(403).json({ error: 'CORS policy violation' });
    }

    if (error instanceof SyntaxError && error.status === 400 && 'body' in error) {
      return res.status(400).json({ error: 'Invalid JSON format' });
    }

    if (error.status === 429) {
      return res.status(429).json({
        error: 'Too many requests',
        retryAfter: error.retryAfter,
      });
    }

    if (error.name === 'ValidationError') {
      return res.status(400).json({
        error: 'Validation failed',
        details: error.errors,
      });
    }

    if (error.name === 'SequelizeValidationError') {
      return res.status(400).json({
        error: 'Database validation failed',
        details: error.errors.map(err => ({
          field: err.path,
          message: err.message,
        })),
      });
    }

    if (error.name === 'SequelizeUniqueConstraintError') {
      return res.status(409).json({
        error: 'Resource already exists',
        field: error.errors[0]?.path,
      });
    }

    // Default error response
    res.status(error.status || 500).json({
      error: process.env.NODE_ENV === 'production' 
        ? 'Internal server error' 
        : error.message,
      ...(process.env.NODE_ENV === 'development' && { stack: error.stack }),
    });
  });
};

/**
 * Handle graceful server shutdown
 * @param {string} signal - The shutdown signal received
 */
const gracefulShutdown = (signal) => {
  logger.info(`${signal} received. Starting graceful shutdown...`);
  
  server.close(async (err) => {
    if (err) {
      logger.error('Error during server shutdown:', err);
      process.exit(1);
    }

    try {
      // Close database connections
      const { sequelize, redisClient } = require('./config/db');
      await sequelize.close();
      await redisClient.quit();
      logger.info('Database connections closed');
    } catch (error) {
      logger.error('Error closing database connections:', error);
    }

    logger.info('Graceful shutdown completed');
    process.exit(0);
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Forced shutdown after timeout');
    process.exit(1);
  }, 30000);
};

/**
 * Cleanup expired refresh tokens from database
 * Runs periodically to maintain database hygiene
 */
const cleanupExpiredTokens = async () => {
  try {
    await RefreshToken.cleanup();
  } catch (error) {
    logger.error('Token cleanup error:', error);
  }
};

/**
 * Initialize and start the Express server
 * Sets up database connections, middleware, routes, and error handling
 */
const startServer = async () => {
  try {
    // Configure application middleware and routes
    configureApp();
    configureRoutes();
    configureErrorHandling();

    // Connect to databases
    await connectDB();
    await connectRedis();

    // Start the HTTP server
    const server = global.server = app.listen(PORT, () => {
      logger.info('Auth Backend Server Started', {
        port: PORT,
        environment: process.env.NODE_ENV,
        timestamp: new Date().toISOString(),
      });
      
      if (process.env.NODE_ENV === 'development') {
        logger.debug(`Health check: http://localhost:${PORT}/health`);
        logger.debug(`API base URL: http://localhost:${PORT}/api/auth`);
      }
    });

    // Setup cleanup interval (run every hour)
    setInterval(cleanupExpiredTokens, 60 * 60 * 1000);

    // Setup graceful shutdown handlers
    process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
    process.on('SIGINT', () => gracefulShutdown('SIGINT'));

    // Handle uncaught exceptions and promise rejections
    process.on('uncaughtException', (error) => {
      logger.error('Uncaught Exception:', error);
      gracefulShutdown('UNCAUGHT_EXCEPTION');
    });

    process.on('unhandledRejection', (reason, promise) => {
      logger.error('Unhandled Rejection:', { reason, promise });
      gracefulShutdown('UNHANDLED_REJECTION');
    });

  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Initialize application
startServer();