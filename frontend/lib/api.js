import axios from 'axios';
import Logger from './logger';

/**
 * Axios instance for API requests
 * Configured with base URL, credentials, and timeout
 */
const api = axios.create({
  baseURL: process.env.NEXT_PUBLIC_API_URL,
  withCredentials: true,
  timeout: 10000,
  headers: {
    'Content-Type': 'application/json',
  },
});

/**
 * Request interceptor
 * Adds authentication token to requests
 */
api.interceptors.request.use(
  (config) => {
    Logger.debug('API Request initiated', {
      method: config.method?.toUpperCase(),
      url: `${config.baseURL}${config.url}`,
    });

    // Add authorization token if available (client-side only)
    if (typeof window !== 'undefined') {
      const token = localStorage.getItem('accessToken');
      if (token) {
        config.headers.Authorization = `Bearer ${token}`;
        Logger.debug('Authorization token added to request');
      }
    }
    
    return config;
  },
  (error) => {
    Logger.error('Request configuration failed', error.message);
    return Promise.reject(error);
  }
);

/**
 * Response interceptor
 * Handles successful responses and token refresh logic
 */
api.interceptors.response.use(
  (response) => {
    Logger.debug('API Response received', {
      status: response.status,
      url: response.config.url,
    });
    return response;
  },
  async (error) => {
    const { response, config: originalRequest } = error;
    
    Logger.error('API Error occurred', {
      status: response?.status,
      message: error.message,
      url: originalRequest?.url,
    });

    // Handle token refresh for 401 errors (client-side only)
    if (response?.status === 401 && typeof window !== 'undefined') {
      
      // Skip refresh for auth endpoints to prevent infinite loops
      if (originalRequest.url?.includes('/auth/refresh') || 
          originalRequest.url?.includes('/auth/login')) {
        Logger.warn('Skipping token refresh for auth endpoints');
        return Promise.reject(error);
      }

      Logger.info('Attempting automatic token refresh');
      
      try {
        const refreshResponse = await axios.post(
          `${process.env.NEXT_PUBLIC_API_URL}/auth/refresh`,
          {},
          { 
            withCredentials: true,
            timeout: 5000,
          }
        );
        
        const { accessToken } = refreshResponse.data;
        localStorage.setItem('accessToken', accessToken);
        
        Logger.info('Token refresh successful, retrying original request');
        
        // Retry the original request with new token
        originalRequest.headers.Authorization = `Bearer ${accessToken}`;
        return api.request(originalRequest);
        
      } catch (refreshError) {
        Logger.error('Token refresh failed', refreshError.message);
        
        // Clean up and redirect to login
        localStorage.removeItem('accessToken');
        window.location.href = '/login';
        return Promise.reject(refreshError);
      }
    }
    
    return Promise.reject(error);
  }
);

export default api;