<?php
/**
 * SwapIt Authentication API
 * Handles user authentication, registration, session management, and password reset
 * 
 * @author Athanase Abayo - Core authentication architecture
 * @author Mabinty Mambu - Session management
 * @author Olivier Kwizera - Security enhancements and rate limiting
 * @version 2.0
 */

// Security headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// CORS configuration - Update with your frontend URL
$allowed_origins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://swaphub-frontend.vercel.app',
    'https://your-vercel-domain.vercel.app'
];

$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
}
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Start session with secure settings
ini_set('session.cookie_httponly', 1);
ini_set('session.cookie_secure', isset($_SERVER['HTTPS']) ? 1 : 0);
ini_set('session.cookie_samesite', 'Lax');
session_start();

// Include database connection
require_once __DIR__ . '/../config/db.php';

/**
 * Rate limiting implementation - prevents brute force attacks
 * OWASP #7: Identification and Authentication Failures
 */
class RateLimiter {
    private $logFile;
    private $maxAttempts = 5;
    private $lockoutTime = 900; // 15 minutes

    public function __construct() {
        $this->logFile = __DIR__ . '/../logs/rate_limit.json';
        if (!file_exists($this->logFile)) {
            file_put_contents($this->logFile, json_encode([]));
        }
    }

    public function isRateLimited($identifier) {
        $data = json_decode(file_get_contents($this->logFile), true) ?: [];
        
        if (!isset($data[$identifier])) {
            return ['limited' => false, 'attempts' => 0];
        }

        $record = $data[$identifier];
        $currentTime = time();

        // Reset if lockout time has passed
        if (isset($record['locked_until']) && $currentTime > $record['locked_until']) {
            unset($data[$identifier]);
            file_put_contents($this->logFile, json_encode($data));
            return ['limited' => false, 'attempts' => 0];
        }

        // Check if account is locked
        if (isset($record['locked_until']) && $currentTime < $record['locked_until']) {
            return [
                'limited' => true,
                'retry_after' => $record['locked_until'],
                'message' => 'Too many failed attempts. Account temporarily locked.'
            ];
        }

        return ['limited' => false, 'attempts' => $record['attempts'] ?? 0];
    }

    public function recordAttempt($identifier, $success = false) {
        $data = json_decode(file_get_contents($this->logFile), true) ?: [];
        $currentTime = time();

        if ($success) {
            // Clear on successful login
            unset($data[$identifier]);
        } else {
            // Increment failed attempts
            if (!isset($data[$identifier])) {
                $data[$identifier] = ['attempts' => 0, 'first_attempt' => $currentTime];
            }
            
            $data[$identifier]['attempts']++;
            $data[$identifier]['last_attempt'] = $currentTime;

            // Lock account after max attempts
            if ($data[$identifier]['attempts'] >= $this->maxAttempts) {
                $data[$identifier]['locked_until'] = $currentTime + $this->lockoutTime;
            }
        }

        file_put_contents($this->logFile, json_encode($data));
        
        return [
            'attempts' => $data[$identifier]['attempts'] ?? 0,
            'remaining' => max(0, $this->maxAttempts - ($data[$identifier]['attempts'] ?? 0))
        ];
    }
}

/**
 * Send JSON response
 */
function sendResponse($success, $message, $data = []) {
    echo json_encode(array_merge(['success' => $success, 'message' => $message], $data));
    exit();
}

/**
 * Validate email format
 */
function validateEmail($email) {
    return filter_var($email, FILTER_VALIDATE_EMAIL) !== false;
}

/**
 * Sanitize user input
 */
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

// Get action from request
$action = $_GET['action'] ?? $_POST['action'] ?? '';

// Database connection
$db = getDBConnection();
if (!$db) {
    sendResponse(false, 'Database connection failed');
}

$rateLimiter = new RateLimiter();

switch ($action) {
    case 'signup':
        // User registration
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';
        $fullName = sanitizeInput($_POST['full_name'] ?? '');

        // Validation
        if (empty($email) || empty($password) || empty($fullName)) {
            sendResponse(false, 'All fields are required');
        }

        if (!validateEmail($email)) {
            sendResponse(false, 'Invalid email format');
        }

        if (strlen($password) < 6) {
            sendResponse(false, 'Password must be at least 6 characters');
        }

        // Check if email already exists
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows > 0) {
            sendResponse(false, 'Email already registered');
        }

        // Hash password
        $passwordHash = password_hash($password, PASSWORD_BCRYPT);

        // Insert user
        $stmt = $db->prepare("INSERT INTO users (email, password_hash, full_name) VALUES (?, ?, ?)");
        $stmt->bind_param("sss", $email, $passwordHash, $fullName);
        
        if ($stmt->execute()) {
            $userId = $stmt->insert_id;

            // Create profile
            $stmt = $db->prepare("INSERT INTO profiles (user_id, full_name, email) VALUES (?, ?, ?)");
            $stmt->bind_param("iss", $userId, $fullName, $email);
            $stmt->execute();

            // Get user data
            $stmt = $db->prepare("SELECT id, email, full_name, avatar_url, created_at FROM users WHERE id = ?");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $user = $stmt->get_result()->fetch_assoc();

            // Set session
            $_SESSION['user_id'] = $userId;
            $_SESSION['user_email'] = $email;
            $_SESSION['user_name'] = $fullName;

            sendResponse(true, 'Account created successfully', ['user' => $user]);
        } else {
            sendResponse(false, 'Failed to create account');
        }
        break;

    case 'login':
        // User login
        $email = sanitizeInput($_POST['email'] ?? '');
        $password = $_POST['password'] ?? '';

        // Validation
        if (empty($email) || empty($password)) {
            sendResponse(false, 'Email and password are required');
        }

        // Rate limiting check
        $rateCheck = $rateLimiter->isRateLimited($email);
        if ($rateCheck['limited']) {
            sendResponse(false, $rateCheck['message'], [
                'locked' => true,
                'retry_after' => $rateCheck['retry_after']
            ]);
        }

        // Get user
        $stmt = $db->prepare("SELECT id, email, password_hash, full_name, avatar_url, is_active FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            $rateLimiter->recordAttempt($email, false);
            sendResponse(false, 'Invalid email or password');
        }

        $user = $result->fetch_assoc();

        // Check if account is active
        if (!$user['is_active']) {
            sendResponse(false, 'Account is deactivated. Please contact support.');
        }

        // Verify password
        if (!password_verify($password, $user['password_hash'])) {
            $attemptInfo = $rateLimiter->recordAttempt($email, false);
            sendResponse(false, 'Invalid email or password', [
                'remaining_attempts' => $attemptInfo['remaining']
            ]);
        }

        // Successful login - clear rate limit
        $rateLimiter->recordAttempt($email, true);

        // Update last login
        $stmt = $db->prepare("UPDATE users SET last_login_at = NOW() WHERE id = ?");
        $stmt->bind_param("i", $user['id']);
        $stmt->execute();

        // Set session
        $_SESSION['user_id'] = $user['id'];
        $_SESSION['user_email'] = $user['email'];
        $_SESSION['user_name'] = $user['full_name'];
        $_SESSION['last_activity'] = time();

        unset($user['password_hash']);
        sendResponse(true, 'Login successful', ['user' => $user]);
        break;

    case 'check_auth':
        // Check if user is authenticated
        if (isset($_SESSION['user_id'])) {
            $userId = $_SESSION['user_id'];
            
            $stmt = $db->prepare("SELECT id, email, full_name, avatar_url FROM users WHERE id = ? AND is_active = 1");
            $stmt->bind_param("i", $userId);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();
                sendResponse(true, 'Authenticated', ['user' => $user]);
            }
        }
        sendResponse(false, 'Not authenticated', ['user' => null]);
        break;

    case 'logout':
        // User logout
        session_unset();
        session_destroy();
        sendResponse(true, 'Logged out successfully');
        break;

    case 'reset_password':
        // Password reset (send email with token)
        $email = sanitizeInput($_POST['email'] ?? '');

        if (empty($email) || !validateEmail($email)) {
            sendResponse(false, 'Valid email is required');
        }

        // Check if user exists
        $stmt = $db->prepare("SELECT id FROM users WHERE email = ?");
        $stmt->bind_param("s", $email);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            // Don't reveal if email exists or not (security)
            sendResponse(true, 'If the email exists, a reset link has been sent');
        }

        $user = $result->fetch_assoc();
        
        // Generate reset token
        $token = bin2hex(random_bytes(32));
        $expiresAt = date('Y-m-d H:i:s', strtotime('+1 hour'));

        // Store token
        $stmt = $db->prepare("INSERT INTO verification_tokens (user_id, token, token_type, expires_at) VALUES (?, ?, 'password_reset', ?)");
        $stmt->bind_param("iss", $user['id'], $token, $expiresAt);
        $stmt->execute();

        // In production, send email with reset link
        // For now, just return success
        sendResponse(true, 'If the email exists, a reset link has been sent', [
            'dev_token' => $token // Remove in production
        ]);
        break;

    default:
        sendResponse(false, 'Invalid action');
}
