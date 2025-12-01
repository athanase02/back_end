<?php
// Router for Railway PHP built-in server
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Serve static files directly
if ($uri !== '/' && file_exists(__DIR__ . $uri)) {
    return false; // Let PHP's built-in server handle it
}

// Route /api/* requests
if (strpos($uri, '/api/') === 0) {
    $file = __DIR__ . $uri;
    if (file_exists($file) && is_file($file)) {
        require $file;
        exit;
    }
}

// Root endpoint - show API info
if ($uri === '/' || $uri === '') {
    header('Content-Type: application/json');
    echo json_encode([
        'success' => true,
        'message' => 'SwapHub Backend API - Running on Railway',
        'version' => '1.0',
        'timestamp' => date('Y-m-d H:i:s'),
        'endpoints' => [
            'GET /api/auth.php?action=check_auth' => 'Check authentication status',
            'POST /api/auth.php?action=login' => 'User login',
            'POST /api/auth.php?action=signup' => 'User registration',
            'POST /api/auth.php?action=logout' => 'User logout',
            'GET /api/listings.php?action=get_all' => 'Get all listings',
            'GET /api/listings.php?action=get_categories' => 'Get categories',
            'GET /api/profile.php?action=get_profile' => 'Get user profile'
        ]
    ]);
    exit;
}

// 404 for everything else
http_response_code(404);
header('Content-Type: application/json');
echo json_encode([
    'success' => false,
    'message' => 'Endpoint not found',
    'requested' => $uri
]);
exit;

