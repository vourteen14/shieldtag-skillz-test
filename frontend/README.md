# Shieldtag Skill Test Frontend

A frontend application for a secure login system built with Next.js 14, showcasing modern authentication practices and robust security implementations.

## Overview

This is the frontend component of the secure login system skill test for **Shieldtag**. It demonstrates a secure authentication flow using JWT tokens, automatic token refresh, and safeguards against common web vulnerabilities.

## Features

* **Secure Login System** – Email/password authentication with JWT
* **Auto Token Refresh** – Seamless token renewal without disrupting user sessions
* **Protected Routes** – Middleware-based route access control
* **Input Validation** – Client-side validation with clear error handling
* **Security-Focused** – XSS protection and secure token storage
* **Responsive Design** – Mobile-friendly and adaptive layout

## Tech Stack

* **Framework**: Next.js 14 (App Router)
* **Styling**: Tailwind CSS
* **HTTP Client**: Axios with interceptors
* **Authentication**: JWT with Refresh Token strategy

## Getting Started

### Prerequisites

* Node.js v18 or higher
* Running backend API server

### Installation

1. **Install dependencies**

   ```bash
   npm install
   ```

2. **Set up environment variables**

   ```bash
   cp .env.local.example .env.local
   ```

   Then edit `.env.local`:

   ```env
   NEXT_PUBLIC_API_URL=http://localhost:5000/api
   NODE_ENV=development
   ```

3. **Run development server**

   ```bash
   npm run dev
   ```

4. **Open the app in browser**

   ```
   http://localhost:3000
   ```

## Authentication Flow

### Token Strategy

* **Access Token**

  * Expiration: 15 minutes
  * Stored in application memory (non-persistent)
  * Sent via `Authorization` header in API requests

* **Refresh Token**

  * Expiration: 7 days
  * Stored in `HttpOnly`, `Secure`, and `SameSite=Strict` cookie
  * Inaccessible from JavaScript
  * Used once to obtain a new access token

* **Token Rotation**

  * Old refresh token is invalidated immediately upon use
  * New refresh token is sent back in the response cookie

### Route Handling

* **Middleware** is used to check authentication status
* **Routing Rules**:

  * `/dashboard/*` → requires login
  * `/login`, `/register` → redirects if already authenticated
  * `/` → smart redirect based on token status

## Security Implementations

### Frontend Security Measures

1. **XSS Protection**

   * Refresh tokens are stored in `HttpOnly` cookies
   * Inputs are sanitized and validated
   * No sensitive data stored in `localStorage`

2. **Token Security**

   * Access tokens stored only in memory
   * Cleared on logout
   * Refresh tokens securely configured in cookies

3. **Input Validation**

   * Validates email format and required fields
   * Displays proper error messages

4. **CSRF Protection**

   * Uses `SameSite=Strict` cookie policy
   * Backend performs origin validation via CORS settings

## API Integration

### API Endpoints Used

* `POST /auth/register` – Register a new user
* `POST /auth/login` – User login
* `POST /auth/refresh` – Refresh the access token
* `GET /auth/profile` – Get authenticated user profile
* `POST /auth/logout` – Logout and invalidate session

### Auto Token Refresh

```javascript
// Axios interceptor for auto-refreshing token on 401 errors
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    if (error.response?.status === 401) {
      // Try refreshing the token
      const refreshResponse = await axios.post('/auth/refresh');
      // Retry the original request with new token
    }
  }
);
```

## Libraries Used & Rationale

### Core Dependencies

1. **Next.js 14**

   * **Why**: A modern React framework with App Router support
   * **Benefits**: Built-in routing, SSR/SSG, and performance optimizations

2. **Axios**

   * **Why**: HTTP client with robust interceptor support
   * **Benefits**: Automatically handle token refresh and retries

3. **Tailwind CSS**

   * **Why**: Utility-first CSS framework
   * **Benefits**: Fast prototyping, consistent styling, responsive support

## Security Implementation Details

### 1. Token Storage

* Access tokens are stored in memory only, not in `localStorage`
* Refresh tokens are stored in `HttpOnly` cookies, inaccessible to JavaScript

### 2. XSS Mitigation

* No token exposure in browser storage
* Input fields are validated before submission

### 3. CSRF Mitigation

* Cookies are set with `SameSite=Strict` to prevent cross-origin use
* Origin and credentials are validated on the backend (via CORS)

### 4. Session Cleanup

* Logout API call deletes refresh token on the server
* Access token is removed from memory

## Error Handling

* **Form Validation**: Realtime client-side checks and messages
* **API Errors**: Clean and user-friendly feedback
* **Network Issues**: Graceful fallbacks and retry logic
* **Auth Failures**: Automatic cleanup and redirection

## Building for Production

```bash
# Build the optimized production version
npm run build

# Start production server
npm start
```

### Production Enhancements

* Code splitting for faster loading
* Image optimization via Next.js
* Static asset caching
* Debug logs disabled

## Key Screenshots to Capture

1. **Registration Page** – Input validation and success message
2. **Login Page** – Form behavior and error display
3. **Dashboard** – Protected content with authenticated user data
4. **Network Tab** – JWT tokens in API requests
5. **Error States** – Form and API error scenarios

## Development Notes

* All console logs are limited to development mode
* Production builds are automatically minified and optimized
* Route protection is enforced via middleware
* Token refresh is handled transparently in the background