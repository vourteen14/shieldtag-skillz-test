# Secure Authentication System - Backend Skillz Test Shieldtag

## Live Demo & Screenshots

See `screenshots/` folder for complete preview including:
- Registration and login pages
- Real-time form validation
- Brute force protection

## Project Architecture

```
.
├── backend/          # Express.js REST API
├── frontend/         # Next.js Application  
├── screenshots/      # Application demo
├── docker-compose.yml
└── README.md
```

## Quick Start

### Prerequisites
- Node.js 18+
- PostgreSQL 14+
- Docker & Docker Compose (optional)

### Docker (Recommended)
```bash
# Clone repository
git clone <your-repo-url>
cd secure-auth-system

# Run with Docker Compose
docker-compose up -d

# Access application
Frontend: http://localhost:3000
Backend API: http://localhost:5000
```

### Manual Setup
```bash
# Setup Backend
cd backend
npm install
cp .env.example .env  # Configure your environment
npm run migrate
npm run seed
npm run dev

# Setup Frontend (new terminal)
cd frontend
npm install
cp .env.local.example .env.local
npm run dev
```

## Security Features

### Authentication & Authorization
- **Password Hashing** => Argon2id (more secure than bcrypt)
- **JWT Tokens** => Access token (15m) + Refresh token (7d)
- **Token Storage** => Access token in memory, refresh token in HttpOnly cookie
- **Protected Routes** => Authentication middleware for dashboard

### Attack Prevention
- **SQL Injection** => Sequelize ORM with parameterized queries
- **XSS Protection** => Input sanitization & CSP headers
- **Brute Force** => Rate limiting (5 attempts per 5 minutes)
- **CSRF** => HttpOnly cookies with SameSite attribute

### Input Validation
- **Backend** => express-validator with custom rules
- **Frontend** => Client-side validation with real-time feedback
- **Sanitization** => HTML encoding for all user input

## Test Account

For testing purposes, use the seeded account:
```
Email: admin@example.com
Password: Admin123!
```

## Technology Stack

### Backend
- **Framework** => Express.js
- **Database** => PostgreSQL + Sequelize ORM
- **Authentication** => JWT + Argon2
- **Security** => Helmet, CORS, Rate Limiting
- **Validation** => express-validator

### Frontend
- **Framework** => Next.js 14 (App Router)
- **Styling** => Tailwind CSS
- **HTTP Client** => Axios with interceptors
- **State Management** => Built-in React state
- **Form Handling** => Native with validation

## Security Implementation

### 1. Password Security
```javascript
// Argon2id with optimal parameters
const hashedPassword = await argon2.hash(password, {
  type: argon2.argon2id,
  timeCost: 3,
  memoryCost: 65536, // 64MB
});
```

### 2. JWT Strategy
- **Access Token**: Short-lived (15 minutes), stored in memory
- **Refresh Token**: Long-lived (7 days), HttpOnly cookie + database
- **Auto-refresh**: Automatic refresh before token expiration

### 3. Rate Limiting
```javascript
// Login endpoint protection
const loginLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 5, // maximum 5 attempts
  message: 'Too many login attempts'
});
```

### 4. Database Security
- Sequelize ORM prevents SQL injection
- Environment variables for credentials
- Connection pooling for performance

## API Endpoints

| Method | Endpoint             | Description          | Rate Limit |
| ------ | -------------------- | -------------------- | ---------- |
| POST   | `/api/auth/register` | User registration    | 5/5min     |
| POST   | `/api/auth/login`    | User login           | 5/5min     |
| POST   | `/api/auth/refresh`  | Refresh access token | 10/5min    |
| POST   | `/api/auth/logout`   | User logout          | 10/5min    |
| GET    | `/api/auth/profile`  | Get user profile     | 100/5min   |

## Screenshots Preview

| Feature                | Screenshot                                      |
| ---------------------- | ----------------------------------------------- |
| Register Page          | `screenshots/user-register-page.png`            |
| Login Page             | `screenshots/user-login-page.png`               |
| Dashboard              | `screenshots/user-dashboard.png`                |
| Validation Errors      | `screenshots/user-email-format-validation.png`  |
| Brute Force Protection | `screenshots/user-login-prevent-bruteforce.png` |

## Deployment

### Production Ready
- Docker multi-stage builds for size optimization
- Environment-based configuration
- Health checks for monitoring
- Graceful shutdown handling

### Environment Variables
```bash
# Backend (.env)
DATABASE_URL=postgresql://user:pass@localhost:5432/authdb
JWT_ACCESS_SECRET=your-super-secret-key
JWT_REFRESH_SECRET=your-refresh-secret-key
NODE_ENV=production

# Frontend (.env.local)
NEXT_PUBLIC_API_URL=http://localhost:5000
```

## Testing

```bash
# Backend tests
cd backend
npm run test

# Frontend tests  
cd frontend
npm run test
```

## Development Notes

### Technology Rationale

- **Argon2** => Winner of Password Hashing Competition, more secure than bcrypt
- **JWT** => Stateless, suitable for microservices and horizontal scaling
- **Next.js** => SSR/SSG support, built-in optimizations, excellent DX
- **PostgreSQL** => ACID compliance, robust for production
- **Sequelize** => Type-safe ORM with migration support

### Security Best Practices Applied

1. **Defense in Depth** => Multiple layers of security
2. **Principle of Least Privilege** => Minimal permissions required
3. **Input Validation** => Never trust user input
4. **Secure by Default** => Security-first configuration
5. **Error Handling** => Don't leak sensitive information