'use client';

import { useState, useEffect } from 'react';
import { useRouter } from 'next/navigation';
import api from '@/lib/api';
import Logger from '@/lib/logger';

/**
 * Dashboard page component
 * Protected route that displays user profile information
 * Auto-redirects to login if token is invalid/expired
 */
export default function Dashboard() {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [authChecked, setAuthChecked] = useState(false);
  const router = useRouter();

  /**
   * Check if user has valid tokens
   */
  const checkAuthStatus = () => {
    const accessToken = localStorage.getItem('accessToken');
    const refreshToken = document.cookie
      .split('; ')
      .find(row => row.startsWith('refreshToken='))
      ?.split('=')[1];

    Logger.debug('Auth status check', {
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
    });

    // If no tokens at all, redirect immediately
    if (!accessToken && !refreshToken) {
      Logger.warn('No authentication tokens found, redirecting to login');
      router.push('/login');
      return false;
    }

    return true;
  };

  /**
   * Fetch user profile data with token validation
   */
  const fetchProfile = async () => {
    try {
      Logger.info('Fetching user profile');
      
      const response = await api.get('/auth/profile');
      setUser(response.data.user);
      
      Logger.info('Profile fetched successfully');
      
    } catch (error) {
      Logger.error('Failed to fetch user profile', {
        status: error.response?.status,
        message: error.message,
      });
      
      // Handle different error scenarios
      if (error.response?.status === 401) {
        Logger.warn('Unauthorized access - token expired or invalid');
        handleAuthFailure();
      } else if (error.response?.status === 403) {
        Logger.warn('Forbidden access - insufficient permissions');
        handleAuthFailure();
      } else {
        Logger.error('Network or server error occurred');
        // For network errors, we might want to retry or show error message
        // But for now, redirect to login for safety
        handleAuthFailure();
      }
    } finally {
      setLoading(false);
      setAuthChecked(true);
    }
  };

  /**
   * Handle authentication failure
   * Clean up tokens and redirect to login
   */
  const handleAuthFailure = () => {
    Logger.info('Handling authentication failure - cleaning up and redirecting');
    
    // Clean up access token
    localStorage.removeItem('accessToken');
    
    // Note: Refresh token cleanup will be handled by the logout endpoint
    // or naturally expire from the HTTP-only cookie
    
    // Redirect to login
    router.push('/login');
  };

  /**
   * Initialize component - check auth and fetch profile
   */
  useEffect(() => {
    // First check if tokens exist
    const hasValidTokens = checkAuthStatus();
    
    if (hasValidTokens) {
      // If tokens exist, try to fetch profile
      fetchProfile();
    } else {
      // If no tokens, loading is done
      setLoading(false);
      setAuthChecked(true);
    }
  }, []);

  /**
   * Handle user logout from current device
   */
  const handleLogout = async () => {
    try {
      Logger.info('Initiating logout');
      
      await api.post('/auth/logout');
      
      Logger.info('Logout successful');
      
    } catch (error) {
      Logger.error('Logout request failed', error.message);
      
    } finally {
      // Clean up local storage and redirect regardless of API response
      localStorage.removeItem('accessToken');
      router.push('/login');
    }
  };

  /**
   * Handle user logout from all devices
   */
  const handleLogoutAll = async () => {
    try {
      Logger.info('Initiating logout from all devices');
      
      await api.post('/auth/logout-all');
      
      Logger.info('Logout all devices successful');
      
    } catch (error) {
      Logger.error('Logout all devices request failed', error.message);
      
    } finally {
      // Clean up local storage and redirect regardless of API response
      localStorage.removeItem('accessToken');
      router.push('/login');
    }
  };

  // Show loading state while checking authentication
  if (loading || !authChecked) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
          <div className="text-xl text-gray-600">Verifying authentication...</div>
        </div>
      </div>
    );
  }

  // If we reach here without user data, something went wrong
  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gray-50">
        <div className="text-center">
          <div className="text-xl text-red-600 mb-4">Authentication failed</div>
          <div className="text-gray-600 mb-4">Unable to verify your identity</div>
          <button
            onClick={() => router.push('/login')}
            className="bg-blue-500 text-white px-4 py-2 rounded-lg hover:bg-blue-600 transition-colors"
          >
            Go to Login
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-gray-50">
      <div className="max-w-4xl mx-auto p-6">
        <div className="bg-white p-8 rounded-lg shadow-md">
          <h1 className="text-3xl font-bold mb-6">Dashboard</h1>
          
          <div className="mb-6">
            <h2 className="text-xl font-semibold mb-4">Welcome, {user?.fullName}!</h2>
            
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-gray-700">Full Name</label>
                <p className="text-gray-900">{user?.fullName}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Email</label>
                <p className="text-gray-900">{user?.email}</p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Last Login</label>
                <p className="text-gray-900">
                  {user?.lastLogin ? new Date(user.lastLogin).toLocaleString() : 'N/A'}
                </p>
              </div>
              
              <div>
                <label className="block text-sm font-medium text-gray-700">Member Since</label>
                <p className="text-gray-900">
                  {user?.memberSince ? new Date(user.memberSince).toLocaleDateString() : 'N/A'}
                </p>
              </div>
            </div>
          </div>
          
          <div className="flex space-x-4">
            <button
              onClick={handleLogout}
              className="bg-red-500 text-white px-4 py-2 rounded-lg hover:bg-red-600 transition-colors"
            >
              Logout
            </button>
            
            <button
              onClick={handleLogoutAll}
              className="bg-orange-500 text-white px-4 py-2 rounded-lg hover:bg-orange-600 transition-colors"
            >
              Logout All Devices
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}