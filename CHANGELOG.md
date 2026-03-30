# Changelog

All notable changes to this project will be documented in this file.

## [1.0.0] - 2026-03-30

### Added
- Core `EasyAuth` class with strategy-based authentication
- `LocalStrategy` — username/password authentication
- `JwtStrategy` — JSON Web Token authentication (header, cookie, query)
- `GoogleStrategy` — Google OAuth 2.0 authentication
- `protect()` middleware — route guard for logged-in users
- `authorize(...roles)` middleware — role-based access control
- Utility helpers: `hashPassword`, `comparePassword`, `generateToken`, `verifyToken`
- TypeScript type definitions
- Full documentation and examples
