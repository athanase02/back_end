<?php
// Public entry point for Railway
// This file should be accessible at the root of the application

// Set error reporting
error_reporting(E_ALL);
ini_set('display_errors', 0);
ini_set('log_errors', 1);

// Get the requested URI
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$uri = rtrim($uri, '/');

// Health check endpoint
if ($uri === '/health' || $uri === '/health.php') {
    require __DIR__ . '/../health.php';
    exit;
}

// Root endpoint - API info
if ($uri === '' || $uri === '/') {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'message' => 'SwapHub Backend API - Running on Railway',
        'version' => '1.0',
        'timestamp' => date('Y-m-d H:i:s'),
        'php_version' => PHP_VERSION,
        'server_software' => $_SERVER['SERVER_SOFTWARE'] ?? 'Unknown',
        'endpoints' => [
            'GET /health' => 'Health check',
            'GET /api/auth.php?action=check_auth' => 'Check authentication status',
            'POST /api/auth.php?action=login' => 'User login',
            'POST /api/auth.php?action=signup' => 'User registration',
            'POST /api/auth.php?action=logout' => 'User logout',
            'GET /api/listings.php?action=get_all' => 'Get all listings',
            'GET /api/listings.php?action=get_categories' => 'Get categories',
            'GET /api/profile.php?action=get_profile' => 'Get user profile'
        ]
    ], JSON_PRETTY_PRINT);
    exit;
}

// Route API requests
if (strpos($uri, '/api/') === 0) {
    $file = __DIR__ . '/..' . $uri;
    if (file_exists($file) && is_file($file)) {
        require $file;
        exit;
    }
    
    // API file not found
    http_response_code(404);
    header('Content-Type: application/json');
    echo json_encode([
        'success' => false,
        'message' => 'API endpoint not found',
        'requested' => $uri,
        'file_checked' => $file
    ]);
    exit;
}

// 404 for everything else
http_response_code(404);
header('Content-Type: application/json');
echo json_encode([
    'success' => false,
    'message' => 'Resource not found',
    'requested' => $uri
]);
exit;
