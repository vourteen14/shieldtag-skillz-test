/**
 * Production-ready logger utility
 * Only logs in development environment
 * Supports multiple log levels: debug, info, warn, error
 */

const isDevelopment = process.env.NODE_ENV === 'development';

const Logger = {
  /**
   * Debug level logging - detailed information for debugging
   * @param {string} message - Log message
   * @param {*} data - Additional data to log
   */
  debug: (message, data = null) => {
    if (!isDevelopment) return;
    
    if (data) {
      console.log(`DEBUG: ${message}`, data);
    } else {
      console.log(`DEBUG: ${message}`);
    }
  },

  /**
   * Info level logging - general information
   * @param {string} message - Log message  
   * @param {*} data - Additional data to log
   */
  info: (message, data = null) => {
    if (!isDevelopment) return;
    
    if (data) {
      console.log(`INFO: ${message}`, data);
    } else {
      console.log(`INFO: ${message}`);
    }
  },

  /**
   * Warning level logging - something unexpected but not critical
   * @param {string} message - Log message
   * @param {*} data - Additional data to log
   */
  warn: (message, data = null) => {
    if (!isDevelopment) return;
    
    if (data) {
      console.warn(`WARN: ${message}`, data);
    } else {
      console.warn(`WARN: ${message}`);
    }
  },

  /**
   * Error level logging - critical errors that need attention
   * @param {string} message - Log message
   * @param {*} data - Additional data to log
   */
  error: (message, data = null) => {
    if (!isDevelopment) return;
    
    if (data) {
      console.error(`ERROR: ${message}`, data);
    } else {
      console.error(`ERROR: ${message}`);
    }
  }
};

export default Logger;