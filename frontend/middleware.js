import { NextResponse } from 'next/server';

/**
 * Next.js middleware for route protection and authentication
 * Protects dashboard routes and handles login redirects
 */
export function middleware(request) {
  const { pathname } = request.nextUrl;
  const refreshToken = request.cookies.get('refreshToken');
  
  // Protect dashboard routes - require authentication
  if (pathname.startsWith('/dashboard')) {
    if (!refreshToken) {
      // No refresh token found, redirect to login
      return NextResponse.redirect(new URL('/login', request.url));
    }
    // Token exists, allow access to dashboard
    return NextResponse.next();
  }
  
  // Redirect authenticated users away from auth pages
  if ((pathname === '/login' || pathname === '/register') && refreshToken) {
    // User is already logged in, redirect to dashboard
    return NextResponse.redirect(new URL('/dashboard', request.url));
  }
  
  // Allow access to other routes
  return NextResponse.next();
}

/**
 * Configure which routes the middleware should run on
 */
export const config = {
  matcher: ['/dashboard/:path*', '/login', '/register'],
};