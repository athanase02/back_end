<?php
/**
 * SwapIt Profile Management API
 * Handles user profile updates, avatar uploads, and profile data retrieval
 * 
 * @author Victoria Ama Nyonato - Profile management
 * @author Athanase Abayo - Avatar upload and data persistence
 * @version 2.0
 */

// Security headers
header('Content-Type: application/json');
header('X-Content-Type-Options: nosniff');
header('X-Frame-Options: DENY');
header('X-XSS-Protection: 1; mode=block');

// CORS configuration
$allowed_origins = [
    'http://localhost',
    'http://127.0.0.1',
    'https://swaphub-frontend.vercel.app',
    'https://swaphub-frontend-git-main-athanase02s-projects.vercel.app',
    'https://swaphub-frontend-athanase02s-projects.vercel.app'
];

$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : '';
if (in_array($origin, $allowed_origins)) {
    header("Access-Control-Allow-Origin: $origin");
}
header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');
header('Access-Control-Allow-Credentials: true');

if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit();
}

// Start session
session_start();

// Include database connection
require_once __DIR__ . '/../config/db.php';

/**
 * Send JSON response
 */
function sendResponse($success, $message, $data = []) {
    echo json_encode(array_merge(['success' => $success, 'message' => $message], $data));
    exit();
}

/**
 * Sanitize user input
 */
function sanitizeInput($input) {
    return htmlspecialchars(strip_tags(trim($input)), ENT_QUOTES, 'UTF-8');
}

/**
 * Check if user is authenticated
 */
function requireAuth() {
    if (!isset($_SESSION['user_id'])) {
        sendResponse(false, 'Authentication required');
    }
    return $_SESSION['user_id'];
}

// Get action from request
$action = $_POST['action'] ?? $_GET['action'] ?? '';

// Database connection
$db = getDBConnection();
if (!$db) {
    sendResponse(false, 'Database connection failed');
}

switch ($action) {
    case 'get_profile':
        // Get user profile
        $userId = requireAuth();

        $stmt = $db->prepare("
            SELECT u.id, u.email, u.full_name, u.avatar_url, u.phone, u.created_at,
                   p.bio, p.location, p.university, p.student_id, p.graduation_year,
                   p.rating_average, p.total_reviews, p.total_items_listed, 
                   p.total_items_borrowed, p.total_items_lent, p.trust_score
            FROM users u
            LEFT JOIN profiles p ON u.id = p.user_id
            WHERE u.id = ?
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            $profile = $result->fetch_assoc();
            sendResponse(true, 'Profile retrieved', ['profile' => $profile]);
        } else {
            sendResponse(false, 'Profile not found');
        }
        break;

    case 'update_profile':
        // Update user profile
        $userId = requireAuth();

        // Handle avatar upload
        $avatarUrl = null;
        if (isset($_FILES['avatar']) && $_FILES['avatar']['error'] === UPLOAD_ERR_OK) {
            $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
            $filename = $_FILES['avatar']['name'];
            $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

            if (!in_array($ext, $allowed)) {
                sendResponse(false, 'Invalid file type. Allowed: jpg, jpeg, png, gif, webp');
            }

            // Check file size (max 5MB)
            if ($_FILES['avatar']['size'] > 5 * 1024 * 1024) {
                sendResponse(false, 'File too large. Maximum size: 5MB');
            }

            // Create uploads directory if it doesn't exist
            $uploadDir = __DIR__ . '/../uploads/avatars/';
            if (!file_exists($uploadDir)) {
                mkdir($uploadDir, 0755, true);
            }

            // Generate unique filename
            $newFilename = $userId . '_' . time() . '.' . $ext;
            $uploadPath = $uploadDir . $newFilename;

            if (move_uploaded_file($_FILES['avatar']['tmp_name'], $uploadPath)) {
                $avatarUrl = '/uploads/avatars/' . $newFilename;
            } else {
                sendResponse(false, 'Failed to upload avatar');
            }
        } elseif (isset($_POST['avatar_url'])) {
            // Allow setting avatar from URL (for Google OAuth, etc.)
            $avatarUrl = sanitizeInput($_POST['avatar_url']);
        }

        // Collect profile updates
        $updates = [];
        $types = '';
        $values = [];

        if (isset($_POST['full_name'])) {
            $fullName = sanitizeInput($_POST['full_name']);
            $updates[] = "full_name = ?";
            $types .= 's';
            $values[] = $fullName;
        }

        if (isset($_POST['phone'])) {
            $phone = sanitizeInput($_POST['phone']);
            $updates[] = "phone = ?";
            $types .= 's';
            $values[] = $phone;
        }

        if ($avatarUrl !== null) {
            $updates[] = "avatar_url = ?";
            $types .= 's';
            $values[] = $avatarUrl;
        }

        // Update users table
        if (!empty($updates)) {
            $values[] = $userId;
            $types .= 'i';
            
            $sql = "UPDATE users SET " . implode(', ', $updates) . " WHERE id = ?";
            $stmt = $db->prepare($sql);
            $stmt->bind_param($types, ...$values);
            $stmt->execute();
        }

        // Update profiles table
        $profileUpdates = [];
        $profileTypes = '';
        $profileValues = [];

        if (isset($_POST['bio'])) {
            $bio = sanitizeInput($_POST['bio']);
            $profileUpdates[] = "bio = ?";
            $profileTypes .= 's';
            $profileValues[] = $bio;
        }

        if (isset($_POST['location'])) {
            $location = sanitizeInput($_POST['location']);
            $profileUpdates[] = "location = ?";
            $profileTypes .= 's';
            $profileValues[] = $location;
        }

        if (isset($_POST['student_id'])) {
            $studentId = sanitizeInput($_POST['student_id']);
            $profileUpdates[] = "student_id = ?";
            $profileTypes .= 's';
            $profileValues[] = $studentId;
        }

        if (isset($_POST['graduation_year'])) {
            $gradYear = (int)$_POST['graduation_year'];
            $profileUpdates[] = "graduation_year = ?";
            $profileTypes .= 'i';
            $profileValues[] = $gradYear;
        }

        if (!empty($profileUpdates)) {
            $profileValues[] = $userId;
            $profileTypes .= 'i';
            
            $sql = "UPDATE profiles SET " . implode(', ', $profileUpdates) . " WHERE user_id = ?";
            $stmt = $db->prepare($sql);
            $stmt->bind_param($profileTypes, ...$profileValues);
            $stmt->execute();
        }

        // Get updated user data
        $stmt = $db->prepare("SELECT id, email, full_name, avatar_url, phone FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $user = $stmt->get_result()->fetch_assoc();

        // Update session
        $_SESSION['user_name'] = $user['full_name'];

        sendResponse(true, 'Profile updated successfully', ['user' => $user]);
        break;

    case 'get_user_stats':
        // Get user statistics
        $userId = requireAuth();

        $stmt = $db->prepare("
            SELECT 
                COUNT(DISTINCT i.id) as total_listings,
                COUNT(DISTINCT CASE WHEN i.status = 'available' THEN i.id END) as available_items,
                COUNT(DISTINCT CASE WHEN i.status = 'borrowed' THEN i.id END) as borrowed_items,
                COALESCE(SUM(i.views), 0) as total_views,
                COALESCE(SUM(i.saves_count), 0) as total_saves
            FROM items i
            WHERE i.owner_id = ? AND i.status != 'deleted'
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $stats = $stmt->get_result()->fetch_assoc();

        sendResponse(true, 'Stats retrieved', ['stats' => $stats]);
        break;

    case 'delete_account':
        // Delete user account (soft delete)
        $userId = requireAuth();

        $password = $_POST['password'] ?? '';
        if (empty($password)) {
            sendResponse(false, 'Password required to delete account');
        }

        // Verify password
        $stmt = $db->prepare("SELECT password_hash FROM users WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();
        $user = $result->fetch_assoc();

        if (!password_verify($password, $user['password_hash'])) {
            sendResponse(false, 'Invalid password');
        }

        // Soft delete - deactivate account
        $stmt = $db->prepare("UPDATE users SET is_active = 0 WHERE id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();

        // Clear session
        session_unset();
        session_destroy();

        sendResponse(true, 'Account deleted successfully');
        break;

    default:
        sendResponse(false, 'Invalid action');
}
