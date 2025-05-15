# JWT Authentication & User Management

This document provides an overview of the authentication and user management system in the application.

## Overview

The authentication system uses a combination of:

1. Session-based authentication for web access
2. JSON Web Tokens (JWT) for API access
3. Secure password hashing with Argon2

## User Authentication Flow

1. **Login**:
   - User logs in with username and password
   - Server verifies credentials using Argon2 password verification
   - Upon successful authentication:
     - A session is created for web access
     - JWT tokens (access token and refresh token) are issued for API access

2. **API Access**:
   - Client includes access token in Authorization header: `Bearer <token>`
   - Server validates the token signature and expiration
   - If valid, the request is processed

3. **Token Refresh**:
   - Access tokens expire after a short period (default: 15 minutes)
   - Refresh tokens have a longer lifetime (default: 24 hours)
   - Client can use refresh token to obtain a new access token without re-authentication

4. **Logout**:
   - Web session is terminated
   - API tokens are revoked in the database

## JWT Token Structure

The JWT tokens contain:

- `sub`: Subject (username)
- `exp`: Expiration time
- `iat`: Issued at time
- `tenant_id`: Optional tenant identifier for multi-tenancy
- `jti`: JWT ID (unique identifier to prevent replay attacks)

## Security Features

- **Password Hashing**: Uses Argon2, a modern password hashing algorithm
- **Token Expiration**: Short-lived access tokens reduce the risk of token theft
- **Token Refresh**: Allows for extended sessions without re-authentication
- **Token Revocation**: Tokens can be revoked before they expire

## User Management

The application provides endpoints for:

- Creating new users
- Retrieving user information
- Updating user details
- Assigning users to tenants

## Setup

1. Run the initialization script to set up security:
   ```
   cargo run --bin initialize_security
   ```

2. This will:
   - Generate a secure JWT secret and update configuration
   - Create an admin user with default credentials (admin/admin123)

3. Update production configuration with secure secret keys before deployment.

## API Endpoints

- `POST /auth/login` - Authenticate and obtain tokens
- `GET /auth/logout` - End session and revoke tokens
- `POST /auth/token/refresh` - Refresh access token
- `POST /auth/token/revoke` - Manually revoke a token
- `POST /users` - Create a new user
- `GET /users/:id` - Get user details
- `PATCH /users/:id` - Update user details
