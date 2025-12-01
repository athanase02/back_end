<?php
/**
 * SwapIt Listings API
 * Handles item listings CRUD operations, search, filtering, and image uploads
 * 
 * @author Athanase Abayo - Core listing architecture
 * @author Mabinty Mambu - Search and filtering
 * @author Olivier Kwizera - Image uploads
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
header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, OPTIONS');
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

/**
 * Handle image uploads
 */
function handleImageUpload($file, $itemId) {
    $allowed = ['jpg', 'jpeg', 'png', 'gif', 'webp'];
    $filename = $file['name'];
    $ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));

    if (!in_array($ext, $allowed)) {
        return ['success' => false, 'message' => 'Invalid file type'];
    }

    if ($file['size'] > 5 * 1024 * 1024) {
        return ['success' => false, 'message' => 'File too large (max 5MB)'];
    }

    $uploadDir = __DIR__ . '/../uploads/items/';
    if (!file_exists($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    $newFilename = $itemId . '_' . time() . '_' . uniqid() . '.' . $ext;
    $uploadPath = $uploadDir . $newFilename;

    if (move_uploaded_file($file['tmp_name'], $uploadPath)) {
        return ['success' => true, 'url' => '/uploads/items/' . $newFilename];
    }

    return ['success' => false, 'message' => 'Upload failed'];
}

// Get action from request
$action = $_POST['action'] ?? $_GET['action'] ?? '';

// Database connection
$db = getDBConnection();
if (!$db) {
    sendResponse(false, 'Database connection failed');
}

switch ($action) {
    case 'get_all':
        // Get all listings with filtering
        $category = isset($_GET['category']) ? sanitizeInput($_GET['category']) : null;
        $location = isset($_GET['location']) ? sanitizeInput($_GET['location']) : null;
        $status = isset($_GET['status']) ? sanitizeInput($_GET['status']) : 'available';
        $search = isset($_GET['search']) ? sanitizeInput($_GET['search']) : null;
        $limit = isset($_GET['limit']) ? (int)$_GET['limit'] : 50;
        $offset = isset($_GET['offset']) ? (int)$_GET['offset'] : 0;

        $sql = "
            SELECT i.*, 
                   c.name as category_name,
                   u.full_name as owner_name,
                   u.avatar_url as owner_avatar
            FROM items i
            LEFT JOIN categories c ON i.category_id = c.id
            LEFT JOIN users u ON i.owner_id = u.id
            WHERE i.status != 'deleted'
        ";

        $params = [];
        $types = '';

        if ($status) {
            $sql .= " AND i.status = ?";
            $types .= 's';
            $params[] = $status;
        }

        if ($category) {
            $sql .= " AND c.slug = ?";
            $types .= 's';
            $params[] = $category;
        }

        if ($location) {
            $sql .= " AND i.location LIKE ?";
            $types .= 's';
            $params[] = "%$location%";
        }

        if ($search) {
            $sql .= " AND (i.title LIKE ? OR i.description LIKE ?)";
            $types .= 'ss';
            $params[] = "%$search%";
            $params[] = "%$search%";
        }

        $sql .= " ORDER BY i.created_at DESC LIMIT ? OFFSET ?";
        $types .= 'ii';
        $params[] = $limit;
        $params[] = $offset;

        $stmt = $db->prepare($sql);
        if (!empty($params)) {
            $stmt->bind_param($types, ...$params);
        }
        $stmt->execute();
        $result = $stmt->get_result();

        $items = [];
        while ($row = $result->fetch_assoc()) {
            // Decode JSON fields
            $row['image_urls'] = json_decode($row['image_urls'] ?? '[]', true);
            $row['tags'] = json_decode($row['tags'] ?? '[]', true);
            $items[] = $row;
        }

        sendResponse(true, 'Listings retrieved', ['items' => $items, 'count' => count($items)]);
        break;

    case 'get_by_id':
        // Get single listing by ID
        $itemId = (int)($_GET['id'] ?? 0);
        if ($itemId <= 0) {
            sendResponse(false, 'Invalid item ID');
        }

        $stmt = $db->prepare("
            SELECT i.*, 
                   c.name as category_name,
                   u.full_name as owner_name,
                   u.avatar_url as owner_avatar,
                   u.email as owner_email
            FROM items i
            LEFT JOIN categories c ON i.category_id = c.id
            LEFT JOIN users u ON i.owner_id = u.id
            WHERE i.id = ? AND i.status != 'deleted'
        ");
        $stmt->bind_param("i", $itemId);
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows === 0) {
            sendResponse(false, 'Item not found');
        }

        $item = $result->fetch_assoc();
        $item['image_urls'] = json_decode($item['image_urls'] ?? '[]', true);
        $item['tags'] = json_decode($item['tags'] ?? '[]', true);

        // Increment views
        $updateStmt = $db->prepare("UPDATE items SET views = views + 1 WHERE id = ?");
        $updateStmt->bind_param("i", $itemId);
        $updateStmt->execute();

        sendResponse(true, 'Item retrieved', ['item' => $item]);
        break;

    case 'create':
        // Create new listing
        $userId = requireAuth();

        $title = sanitizeInput($_POST['title'] ?? '');
        $description = sanitizeInput($_POST['description'] ?? '');
        $categoryId = (int)($_POST['category_id'] ?? 0);
        $condition = sanitizeInput($_POST['condition_status'] ?? 'Good');
        $price = (float)($_POST['price'] ?? 0);
        $rentalPeriod = sanitizeInput($_POST['rental_period'] ?? 'daily');
        $location = sanitizeInput($_POST['location'] ?? '');

        // Validation
        if (empty($title) || empty($description) || $categoryId <= 0 || empty($location)) {
            sendResponse(false, 'All required fields must be filled');
        }

        if ($price < 0) {
            sendResponse(false, 'Price must be a positive number');
        }

        // Insert item
        $stmt = $db->prepare("
            INSERT INTO items (title, description, category_id, condition_status, price, 
                             rental_period, location, owner_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'available')
        ");
        $stmt->bind_param("ssissssi", $title, $description, $categoryId, $condition, 
                         $price, $rentalPeriod, $location, $userId);
        
        if (!$stmt->execute()) {
            sendResponse(false, 'Failed to create listing');
        }

        $itemId = $stmt->insert_id;

        // Handle image uploads
        $imageUrls = [];
        if (isset($_FILES['images'])) {
            $files = $_FILES['images'];
            
            // Handle multiple files
            if (is_array($files['name'])) {
                for ($i = 0; $i < count($files['name']); $i++) {
                    if ($files['error'][$i] === UPLOAD_ERR_OK) {
                        $file = [
                            'name' => $files['name'][$i],
                            'type' => $files['type'][$i],
                            'tmp_name' => $files['tmp_name'][$i],
                            'error' => $files['error'][$i],
                            'size' => $files['size'][$i]
                        ];
                        $upload = handleImageUpload($file, $itemId);
                        if ($upload['success']) {
                            $imageUrls[] = $upload['url'];
                        }
                    }
                }
            } else {
                $upload = handleImageUpload($files, $itemId);
                if ($upload['success']) {
                    $imageUrls[] = $upload['url'];
                }
            }
        }

        // Update item with image URLs
        if (!empty($imageUrls)) {
            $imageUrlsJson = json_encode($imageUrls);
            $stmt = $db->prepare("UPDATE items SET image_urls = ? WHERE id = ?");
            $stmt->bind_param("si", $imageUrlsJson, $itemId);
            $stmt->execute();
        }

        // Update user's total listings count
        $stmt = $db->prepare("UPDATE profiles SET total_items_listed = total_items_listed + 1 WHERE user_id = ?");
        $stmt->bind_param("i", $userId);
        $stmt->execute();

        sendResponse(true, 'Listing created successfully', ['item_id' => $itemId, 'images' => $imageUrls]);
        break;

    case 'update':
        // Update existing listing
        $userId = requireAuth();
        $itemId = (int)($_POST['id'] ?? 0);

        if ($itemId <= 0) {
            sendResponse(false, 'Invalid item ID');
        }

        // Check ownership
        $stmt = $db->prepare("SELECT owner_id FROM items WHERE id = ?");
        $stmt->bind_param("i", $itemId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            sendResponse(false, 'Item not found');
        }

        $item = $result->fetch_assoc();
        if ($item['owner_id'] != $userId) {
            sendResponse(false, 'You do not have permission to edit this item');
        }

        // Build update query
        $updates = [];
        $types = '';
        $values = [];

        if (isset($_POST['title'])) {
            $updates[] = "title = ?";
            $types .= 's';
            $values[] = sanitizeInput($_POST['title']);
        }

        if (isset($_POST['description'])) {
            $updates[] = "description = ?";
            $types .= 's';
            $values[] = sanitizeInput($_POST['description']);
        }

        if (isset($_POST['price'])) {
            $updates[] = "price = ?";
            $types .= 'd';
            $values[] = (float)$_POST['price'];
        }

        if (isset($_POST['condition_status'])) {
            $updates[] = "condition_status = ?";
            $types .= 's';
            $values[] = sanitizeInput($_POST['condition_status']);
        }

        if (isset($_POST['location'])) {
            $updates[] = "location = ?";
            $types .= 's';
            $values[] = sanitizeInput($_POST['location']);
        }

        if (isset($_POST['status'])) {
            $updates[] = "status = ?";
            $types .= 's';
            $values[] = sanitizeInput($_POST['status']);
        }

        if (empty($updates)) {
            sendResponse(false, 'No fields to update');
        }

        $values[] = $itemId;
        $types .= 'i';

        $sql = "UPDATE items SET " . implode(', ', $updates) . " WHERE id = ?";
        $stmt = $db->prepare($sql);
        $stmt->bind_param($types, ...$values);
        $stmt->execute();

        sendResponse(true, 'Listing updated successfully');
        break;

    case 'delete':
        // Delete listing (soft delete)
        $userId = requireAuth();
        $itemId = (int)($_POST['id'] ?? $_GET['id'] ?? 0);

        if ($itemId <= 0) {
            sendResponse(false, 'Invalid item ID');
        }

        // Check ownership
        $stmt = $db->prepare("SELECT owner_id FROM items WHERE id = ?");
        $stmt->bind_param("i", $itemId);
        $stmt->execute();
        $result = $stmt->get_result();
        
        if ($result->num_rows === 0) {
            sendResponse(false, 'Item not found');
        }

        $item = $result->fetch_assoc();
        if ($item['owner_id'] != $userId) {
            sendResponse(false, 'You do not have permission to delete this item');
        }

        // Soft delete
        $stmt = $db->prepare("UPDATE items SET status = 'deleted' WHERE id = ?");
        $stmt->bind_param("i", $itemId);
        $stmt->execute();

        sendResponse(true, 'Listing deleted successfully');
        break;

    case 'get_my_listings':
        // Get current user's listings
        $userId = requireAuth();
        
        $stmt = $db->prepare("
            SELECT i.*, c.name as category_name
            FROM items i
            LEFT JOIN categories c ON i.category_id = c.id
            WHERE i.owner_id = ? AND i.status != 'deleted'
            ORDER BY i.created_at DESC
        ");
        $stmt->bind_param("i", $userId);
        $stmt->execute();
        $result = $stmt->get_result();

        $items = [];
        while ($row = $result->fetch_assoc()) {
            $row['image_urls'] = json_decode($row['image_urls'] ?? '[]', true);
            $row['tags'] = json_decode($row['tags'] ?? '[]', true);
            $items[] = $row;
        }

        sendResponse(true, 'Your listings retrieved', ['items' => $items, 'count' => count($items)]);
        break;

    case 'get_categories':
        // Get all categories
        $stmt = $db->prepare("SELECT * FROM categories WHERE is_active = 1 ORDER BY display_order, name");
        $stmt->execute();
        $result = $stmt->get_result();

        $categories = [];
        while ($row = $result->fetch_assoc()) {
            $categories[] = $row;
        }

        sendResponse(true, 'Categories retrieved', ['categories' => $categories]);
        break;

    default:
        sendResponse(false, 'Invalid action');
}
