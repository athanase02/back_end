<?php
// Simple router for Railway deployment
$uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

// Route /api/* to api/ directory
if (strpos($uri, '/api/') === 0) {
    $file = __DIR__ . $uri;
    if (file_exists($file)) {
        require $file;
        exit;
    }
}

// Default response
header('Content-Type: application/json');
echo json_encode([
    'success' => true,
    'message' => 'SwapHub Backend API',
    'version' => '1.0',
    'endpoints' => [
        '/api/auth.php' => 'Authentication',
        '/api/profile.php' => 'Profile Management',
        '/api/listings.php' => 'Listings Management'
    ]
]);
