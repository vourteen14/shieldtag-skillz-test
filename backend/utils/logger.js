/**
 * Log level hierarchy (lower numbers = higher priority)
 * @enum {number}
 */
const LOG_LEVELS = {
  ERROR: 0,
  WARN: 1,
  INFO: 2,
  DEBUG: 3,
};

/**
 * ANSI color codes for console output formatting
 * @enum {string}
 */
const LOG_COLORS = {
  ERROR: '\x1b[31m', // Red
  WARN: '\x1b[33m',  // Yellow
  INFO: '\x1b[36m',  // Cyan
  DEBUG: '\x1b[90m', // Gray
  RESET: '\x1b[0m',
};

/**
 * Logger class for structured application logging
 * Automatically formats logs for production (JSON) vs development (colorized)
 */
class Logger {
  /**
   * Initialize logger with environment-specific configuration
   */
  constructor() {
    this.level = this.getLogLevel();
    this.isDevelopment = process.env.NODE_ENV === 'development';
    this.isProduction = process.env.NODE_ENV === 'production';
  }

  /**
   * Determine log level from environment variable
   * @returns {number} Numeric log level from LOG_LEVELS enum
   */
  getLogLevel() {
    const envLevel = process.env.LOG_LEVEL || 'INFO';
    return LOG_LEVELS[envLevel.toUpperCase()] || LOG_LEVELS.INFO;
  }

  /**
   * Format log message based on environment
   * @param {string} level - Log level (ERROR, WARN, INFO, DEBUG)
   * @param {string} message - Primary log message
   * @param {Object} meta - Additional metadata object
   * @returns {string} Formatted log string
   */
  formatMessage(level, message, meta = {}) {
    const timestamp = new Date().toISOString();
    const baseLog = {
      timestamp,
      level,
      message,
      ...meta,
    };

    if (this.isProduction) {
      // Production: JSON format for log aggregation systems
      return JSON.stringify(baseLog);
    } else {
      // Development: Colorized console format for readability
      const color = LOG_COLORS[level];
      const reset = LOG_COLORS.RESET;
      const metaStr = Object.keys(meta).length > 0 ? ` | ${JSON.stringify(meta)}` : '';
      return `${color}[${timestamp}] ${level}: ${message}${metaStr}${reset}`;
    }
  }

  /**
   * Core logging method that handles level filtering and output
   * @param {string} level - Log level
   * @param {string} message - Log message
   * @param {Object} meta - Additional metadata
   */
  log(level, message, meta = {}) {
    if (LOG_LEVELS[level] <= this.level) {
      const formattedMessage = this.formatMessage(level, message, meta);
      
      // Route to appropriate console method based on level
      if (level === 'ERROR') {
        console.error(formattedMessage);
      } else if (level === 'WARN') {
        console.warn(formattedMessage);
      } else {
        console.log(formattedMessage);
      }
    }
  }

  /**
   * Log error-level messages
   * @param {string} message - Error message
   * @param {Object} meta - Additional error context
   */
  error(message, meta = {}) {
    this.log('ERROR', message, meta);
  }

  /**
   * Log warning-level messages
   * @param {string} message - Warning message
   * @param {Object} meta - Additional warning context
   */
  warn(message, meta = {}) {
    this.log('WARN', message, meta);
  }

  /**
   * Log info-level messages
   * @param {string} message - Info message
   * @param {Object} meta - Additional info context
   */
  info(message, meta = {}) {
    this.log('INFO', message, meta);
  }

  /**
   * Log debug-level messages (only in development)
   * @param {string} message - Debug message
   * @param {Object} meta - Additional debug context
   */
  debug(message, meta = {}) {
    this.log('DEBUG', message, meta);
  }

  /**
   * Log security-related events with special categorization
   * @param {string} message - Security event message
   * @param {Object} meta - Security event context (IP, user ID, etc.)
   */
  security(message, meta = {}) {
    this.warn(`SECURITY: ${message}`, {
      ...meta,
      category: 'security',
    });
  }

  /**
   * Log authentication-related events
   * @param {string} message - Auth event message
   * @param {Object} meta - Auth event context (user ID, email, IP, etc.)
   */
  auth(message, meta = {}) {
    this.info(`AUTH: ${message}`, {
      ...meta,
      category: 'authentication',
    });
  }
}

/**
 * Singleton logger instance for application-wide use
 * @type {Logger}
 */
module.exports = new Logger();