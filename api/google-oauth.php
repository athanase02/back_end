<?php
/**
 * SwapIt Google OAuth Integration
 * Handles Google Sign-In authentication
 * 
 * @author Athanase Abayo
 * @version 1.0
 */

// Security headers
header('Content-Type: application/json');

// CORS configuration
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
header('Access-Control-Allow-Credentials: true');

// Start session
session_start();

// Include database connection
require_once __DIR__ . '/../config/db.php';

// Google OAuth configuration
// TODO: Replace with your actual Google OAuth credentials
$googleClientId = 'YOUR_GOOGLE_CLIENT_ID';
$googleClientSecret = 'YOUR_GOOGLE_CLIENT_SECRET';
$redirectUri = 'http://localhost/activity_04_Final_Project/back_end/api/google-callback.php';

// For production, update redirect URI
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    $redirectUri = 'https://your-backend-url/api/google-callback.php';
}

/**
 * Send JSON response
 */
function sendResponse($success, $message, $data = []) {
    echo json_encode(array_merge(['success' => $success, 'message' => $message], $data));
    exit();
}

// Build Google OAuth URL
$authUrl = 'https://accounts.google.com/o/oauth2/v2/auth?' . http_build_query([
    'client_id' => $googleClientId,
    'redirect_uri' => $redirectUri,
    'response_type' => 'code',
    'scope' => 'email profile',
    'access_type' => 'online',
    'prompt' => 'select_account'
]);

sendResponse(true, 'Google OAuth URL generated', [
    'auth_url' => $authUrl,
    'redirect_uri' => $redirectUri
]);
