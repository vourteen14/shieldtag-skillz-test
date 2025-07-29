'use client';

import { useEffect } from 'react';
import { useRouter } from 'next/navigation';
import Logger from '@/lib/logger';

/**
 * Home page component
 * Smart redirect based on authentication status
 * - If tokens exist: redirect to dashboard
 * - If no tokens: redirect to login
 */
export default function Home() {
  const router = useRouter();

  useEffect(() => {
    checkAuthAndRedirect();
  }, []);

  /**
   * Check authentication status and redirect accordingly
   */
  const checkAuthAndRedirect = () => {
    // Check if we're in browser environment
    if (typeof window === 'undefined') return;

    // Check for access token in localStorage
    const accessToken = localStorage.getItem('accessToken');
    
    // Check for refresh token in cookies (client-side)
    const refreshToken = document.cookie
      .split('; ')
      .find(row => row.startsWith('refreshToken='))
      ?.split('=')[1];

    Logger.debug('Authentication check', {
      hasAccessToken: !!accessToken,
      hasRefreshToken: !!refreshToken,
    });

    if (accessToken || refreshToken) {
      // User has active tokens, redirect to dashboard
      Logger.info('Active tokens found, redirecting to dashboard');
      router.push('/dashboard');
    } else {
      // No active tokens, redirect to login
      Logger.info('No active tokens found, redirecting to login');
      router.push('/login');
    }
  };

  // Show loading while checking authentication
  return (
    <div className="min-h-screen flex items-center justify-center bg-gray-50">
      <div className="text-center">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500 mx-auto mb-4"></div>
        <p className="text-gray-600">Checking authentication...</p>
      </div>
    </div>
  );
}