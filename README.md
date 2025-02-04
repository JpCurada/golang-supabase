# Golang Supabase Template

A secure backend template using Go and Supabase with authentication features.

## Features
- JWT Authentication
- Email Verification
- Password Reset
- CSRF Protection
- Input Validation
- Secure Password Hashing
- User Management

## Setup
1. Copy .env.example to .env and fill in values
2. Run migrations
3. Start server

## Project Structure
```
├── cmd/
│   └── api/              # Application entrypoint
├── internal/
│   ├── auth/            # Authentication utilities
│   ├── config/          # Configuration
│   ├── database/        # Database connection
│   ├── email/           # Email service
│   ├── handlers/        # HTTP handlers
│   ├── middleware/      # HTTP middleware
│   └── models/          # Data models
└── migrations/          # Database migrations
```

## API Endpoints
- POST /api/v1/auth/register
- POST /api/v1/auth/login
- POST /api/v1/auth/verify-email
- POST /api/v1/auth/forgot-password
- POST /api/v1/auth/reset-password