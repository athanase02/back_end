# Security Logs Directory

This directory contains security event logs and rate limiting data.

## Files:
- `security.log` - Comprehensive security event logging (OWASP #9)
- `rate_limit.json` - Rate limiting data for brute force protection (OWASP #4, #7)

## Security Features Implemented:

### OWASP Top 10 Coverage:
1. ✅ **Broken Access Control** - Session-based authentication with IP tracking
2. ✅ **Cryptographic Failures** - Bcrypt password hashing, secure session cookies
3. ✅ **Injection Prevention** - Prepared statements, input sanitization, XSS protection
4. ✅ **Insecure Design** - Rate limiting, account lockout, password strength requirements
5. ✅ **Security Misconfiguration** - Security headers (CSP, X-Frame-Options, etc.)
6. ⚠️ **Vulnerable Components** - Manual dependency management (consider adding automated scanning)
7. ✅ **Authentication Failures** - Enhanced password validation, rate limiting, session hijacking detection
8. ✅ **Data Integrity** - Image validation, file type checking, integrity verification
9. ✅ **Logging & Monitoring** - Comprehensive security event logging system
10. ⚠️ **SSRF** - Not applicable (no external URL fetching)

## Log Entries Include:
- Timestamp
- Event type (login, logout, failed_login, etc.)
- User ID
- IP address
- User agent
- Contextual data
- Error messages

## Rate Limiting:
- Maximum 5 login attempts per 15 minutes
- Account locks for 15 minutes after exceeding limit
- Automatic reset on successful login

## Important Notes:
- Log files are automatically created by the application
- **DO NOT** commit log files to version control (included in .gitignore)
- Regularly monitor logs for suspicious activity
- Consider log rotation for production environments
- Ensure proper file permissions (logs directory should be writable by web server)

## Authors:
- Olivier Kwizera - Security logging and rate limiting implementation
- Athanase Abayo - Event tracking and session management integration
