# Shieldtag Skill Test Backend

A backend application for a secure login system built with Express.js and PostgreSQL, designed to meet the **Shieldtag backend skill test** requirements with a strong focus on security, input validation, and session management.

## Overview

This is the backend component of the secure login system for **Shieldtag**. It implements modern authentication practices using access and refresh tokens, enforces strict input validation, rate limiting, and safeguards against common web vulnerabilities such as XSS and SQL injection.

## Features

* **Email/Password Login** – Authentication with secure password hashing using Argon2
* **Token-Based Auth** – JWT-based access and refresh tokens
* **Secure Storage** – Refresh tokens stored in HTTP-only, secure cookies
* **Session Management** – Per-device session control with logout and token blacklisting
* **Brute Force Protection** – Rate limiting by IP and email with Redis
* **XSS & SQL Injection Protection** – Helmet headers and Sequelize ORM
* **Input Validation** – All inputs validated with `express-validator`

## Tech Stack

* **Backend Framework**: Express.js
* **Database**: PostgreSQL (ORM: Sequelize)
* **Authentication**: JWT (Access + Refresh Tokens)
* **Password Hashing**: Argon2 (argon2id)
* **Caching & Rate Limiting**: Redis
* **Validation**: express-validator
* **Security Middleware**: Helmet, CORS, custom Redis-based rate limiter

## Security Implementations

### Token Strategy

* **Access Token**

  * Expiration: 15 minutes
  * Sent in response JSON
  * Blacklisted on logout

* **Refresh Token**

  * Expiration: 7 days
  * Stored in `HttpOnly`, `Secure`, `SameSite=Strict` cookie
  * Rotated and re-issued on each refresh
  * Never exposed to JavaScript

### Password Handling

* Hashed using Argon2id with secure parameters:

  * 64MB memory
  * 3 iterations
* Resistant to brute-force and rainbow table attacks

### Additional Security

* **Rate Limiting** – Per-endpoint limits with Redis to prevent abuse
* **Account Lockout** – Lock account after repeated failed logins
* **Helmet Middleware** – Sets security headers (XSS, clickjacking, etc.)
* **SQL Injection Protection** – Sequelize ORM with parameterized queries
* **Input Sanitization** – Using `express-validator` on all routes

## Public Endpoints

| Method | Endpoint             | Description          |
| ------ | -------------------- | -------------------- |
| POST   | `/api/auth/register` | Register a new user  |
| POST   | `/api/auth/login`    | Authenticate a user  |
| POST   | `/api/auth/refresh`  | Refresh access token |
| GET    | `/api/auth/health`   | Check server health  |

## Protected Endpoints

| Method | Endpoint                 | Description                    |
| ------ | ------------------------ | ------------------------------ |
| POST   | `/api/auth/logout`       | Logout from current session    |
| POST   | `/api/auth/logout-all`   | Logout from all active devices |
| GET    | `/api/auth/profile`      | Get authenticated user profile |
| GET    | `/api/auth/sessions`     | List all active sessions       |
| DELETE | `/api/auth/sessions/:id` | Revoke specific session        |

## Getting Started

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment Variables

Create a `.env` file and fill in the following values:

```env
# PostgreSQL
DB_NAME=auth_db
DB_USER=your_username
DB_PASSWORD=your_password
DB_HOST=localhost
DB_PORT=5432

# JWT
JWT_ACCESS_SECRET=access_secret
JWT_REFRESH_SECRET=refresh_secret
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d

# Redis
REDIS_URL=redis://localhost:6379
REDIS_PASSWORD=your_redis_password

# Server
PORT=5000
NODE_ENV=development
FRONTEND_URL=http://localhost:3000
```

### 3. Setup Database

```bash
npm run db:create
npm run db:migrate
```

### 4. Ensure Redis Is Running

Make sure Redis is installed and running on your machine.

### 5. Start Development Server

```bash
npm run dev
```

## Example Request

### Login

```http
POST /api/auth/login
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "SecurePass123!"
}
```

**Response**

```json
{
  "message": "Login successful",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "fullName": "John Doe"
  },
  "accessToken": "jwt_token_here"
}
```

## Error Handling

* **400 Bad Request** – Input validation errors
* **401 Unauthorized** – Invalid or expired token
* **423 Locked** – Account temporarily locked
* **429 Too Many Requests** – Rate limit exceeded

## Libraries Used & Rationale

| Library                 | Purpose                                                 |
| ----------------------- | ------------------------------------------------------- |
| `express`               | Lightweight and flexible backend framework              |
| `sequelize`             | ORM for PostgreSQL, prevents raw SQL injection risks    |
| `argon2`                | Modern password hashing algorithm, stronger than bcrypt |
| `jsonwebtoken`          | Manages access and refresh token signing/verification   |
| `redis`                 | Token storage and rate limiting cache                   |
| `express-validator`     | Input validation and sanitization                       |
| `helmet`                | Security headers for XSS and clickjacking protection    |
| `rate-limiter-flexible` | Redis-based rate limiting and brute-force mitigation    |