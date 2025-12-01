# SwapHub Backend API

Complete PHP backend for the SwapHub peer-to-peer item borrowing platform.

## 🚀 API Endpoints

### Authentication (`/api/auth.php`)
- **POST** `?action=signup` - Register new user
  - Body: `email`, `password`, `full_name`
- **POST** `?action=login` - User login
  - Body: `email`, `password`
- **GET** `?action=check_auth` - Check authentication status
- **POST** `?action=logout` - User logout
- **POST** `?action=reset_password` - Request password reset
  - Body: `email`

### Profile Management (`/api/profile.php`)
- **GET** `?action=get_profile` - Get user profile
- **POST** `?action=update_profile` - Update profile
  - Body: `full_name`, `phone`, `bio`, `location`, `student_id`, `graduation_year`
  - Files: `avatar` (optional)
- **GET** `?action=get_user_stats` - Get user statistics
- **POST** `?action=delete_account` - Delete account (soft delete)
  - Body: `password`

### Listings Management (`/api/listings.php`)
- **GET** `?action=get_all` - Get all listings
  - Query params: `category`, `location`, `status`, `search`, `limit`, `offset`
- **GET** `?action=get_by_id&id={id}` - Get single listing
- **POST** `?action=create` - Create new listing (requires auth)
  - Body: `title`, `description`, `category_id`, `condition_status`, `price`, `rental_period`, `location`
  - Files: `images[]` (optional, multiple)
- **POST** `?action=update` - Update listing (requires auth)
  - Body: `id`, any fields to update
- **POST/DELETE** `?action=delete&id={id}` - Delete listing (requires auth)
- **GET** `?action=get_my_listings` - Get current user's listings (requires auth)
- **GET** `?action=get_categories` - Get all categories

### Google OAuth
- **GET** `/api/google-oauth.php` - Get Google OAuth URL
- **GET** `/api/google-callback.php` - OAuth callback handler

## 🔒 Security Features

1. **Rate Limiting** - Prevents brute force attacks (5 attempts, 15-minute lockout)
2. **Password Hashing** - BCrypt hashing for all passwords
3. **Session Management** - Secure HTTP-only cookies
4. **Input Sanitization** - All inputs sanitized and validated
5. **CORS Protection** - Whitelist-based origin checking
6. **SQL Injection Protection** - Prepared statements for all queries

## 📁 File Structure

```
back_end/
├── api/
│   ├── auth.php              # Authentication endpoints
│   ├── profile.php           # Profile management
│   ├── listings.php          # Item listings CRUD
│   ├── google-oauth.php      # Google OAuth initiation
│   └── google-callback.php   # Google OAuth callback
├── config/
│   ├── db.php                # Database connection
│   ├── db_production.php     # Production DB config
│   ├── db_infinityfree.php   # InfinityFree config
│   └── db_with_fallback.php  # Multi-environment config
├── db/
│   ├── SI2025.sql            # Database schema
│   └── migrate_avatar.php    # Migration scripts
└── logs/
    ├── rate_limit.json       # Rate limiting data
    └── security.log          # Security events
```

## 🛠 Setup Instructions

### 1. Database Setup
```sql
-- Import the database schema
mysql -u your_user -p < db/SI2025.sql

-- Or manually create database
CREATE DATABASE SI2025;
USE SI2025;
SOURCE db/SI2025.sql;
```

### 2. Configuration
Update `config/db.php` with your database credentials:
```php
$host = 'localhost';
$database = 'SI2025';
$username = 'your_username';
$password = 'your_password';
```

### 3. CORS Configuration
Update allowed origins in each API file:
```php
$allowed_origins = [
    'https://your-frontend-domain.vercel.app'
];
```

### 4. Google OAuth (Optional)
Update in `api/google-oauth.php` and `api/google-callback.php`:
```php
$googleClientId = 'YOUR_GOOGLE_CLIENT_ID';
$googleClientSecret = 'YOUR_GOOGLE_CLIENT_SECRET';
```

### 5. File Permissions
```bash
chmod 755 api/
chmod 755 uploads/
chmod 644 logs/rate_limit.json
```

## 🚀 Deployment

### Railway / Render / Heroku
1. Add buildpack: `heroku/php`
2. Set environment variables:
   - `DB_HOST`
   - `DB_NAME`
   - `DB_USER`
   - `DB_PASS`
3. Deploy from GitHub repository

### InfinityFree / cPanel
1. Upload files to `htdocs/` or `public_html/`
2. Import database via phpMyAdmin
3. Update `config/db.php` with hosting credentials

## 📝 API Response Format

All endpoints return JSON:

### Success Response
```json
{
  "success": true,
  "message": "Operation successful",
  "data": {}
}
```

### Error Response
```json
{
  "success": false,
  "message": "Error description"
}
```

## 🧪 Testing

Test authentication:
```bash
curl -X POST http://localhost/api/auth.php \
  -d "action=login&email=test@example.com&password=password123"
```

Test listings:
```bash
curl http://localhost/api/listings.php?action=get_all
```

## 📄 License

Created by SwapHub Team for Ashesi University CS project.

## 👥 Authors

- **Athanase Abayo** - Core architecture & authentication
- **Mabinty Mambu** - API integration & session management
- **Olivier Kwizera** - Security & rate limiting
- **Victoria Ama Nyonato** - Profile management
