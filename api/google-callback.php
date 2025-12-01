<?php
/**
 * SwapIt Google OAuth Callback Handler
 * Processes Google authentication callback and creates/logs in user
 * 
 * @author Athanase Abayo
 * @version 1.0
 */

session_start();

// Include database connection
require_once __DIR__ . '/../config/db.php';

// Google OAuth configuration
$googleClientId = 'YOUR_GOOGLE_CLIENT_ID';
$googleClientSecret = 'YOUR_GOOGLE_CLIENT_SECRET';
$redirectUri = 'http://localhost/activity_04_Final_Project/back_end/api/google-callback.php';

// For production
if (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') {
    $redirectUri = 'https://your-backend-url/api/google-callback.php';
}

// Get authorization code
$code = $_GET['code'] ?? '';
if (empty($code)) {
    header('Location: /pages/login.html?error=no_code');
    exit();
}

// Exchange code for access token
$tokenUrl = 'https://oauth2.googleapis.com/token';
$tokenData = [
    'code' => $code,
    'client_id' => $googleClientId,
    'client_secret' => $googleClientSecret,
    'redirect_uri' => $redirectUri,
    'grant_type' => 'authorization_code'
];

$ch = curl_init($tokenUrl);
curl_setopt($ch, CURLOPT_POST, true);
curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($tokenData));
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$tokenResponse = curl_exec($ch);
curl_close($ch);

$tokenResult = json_decode($tokenResponse, true);

if (!isset($tokenResult['access_token'])) {
    header('Location: /pages/login.html?error=token_failed');
    exit();
}

// Get user info from Google
$accessToken = $tokenResult['access_token'];
$userInfoUrl = 'https://www.googleapis.com/oauth2/v2/userinfo?access_token=' . $accessToken;

$ch = curl_init($userInfoUrl);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
$userInfoResponse = curl_exec($ch);
curl_close($ch);

$userInfo = json_decode($userInfoResponse, true);

if (!isset($userInfo['email'])) {
    header('Location: /pages/login.html?error=userinfo_failed');
    exit();
}

// Connect to database
$db = getDBConnection();
if (!$db) {
    header('Location: /pages/login.html?error=db_failed');
    exit();
}

$email = $userInfo['email'];
$fullName = $userInfo['name'] ?? $userInfo['email'];
$avatarUrl = $userInfo['picture'] ?? null;

// Check if user exists
$stmt = $db->prepare("SELECT id, email, full_name, avatar_url, is_active FROM users WHERE email = ?");
$stmt->bind_param("s", $email);
$stmt->execute();
$result = $stmt->get_result();

if ($result->num_rows > 0) {
    // User exists - log them in
    $user = $result->fetch_assoc();
    
    if (!$user['is_active']) {
        header('Location: /pages/login.html?error=account_inactive');
        exit();
    }

    // Update avatar if changed
    if ($avatarUrl && $avatarUrl !== $user['avatar_url']) {
        $updateStmt = $db->prepare("UPDATE users SET avatar_url = ?, last_login_at = NOW() WHERE id = ?");
        $updateStmt->bind_param("si", $avatarUrl, $user['id']);
        $updateStmt->execute();
    } else {
        $updateStmt = $db->prepare("UPDATE users SET last_login_at = NOW() WHERE id = ?");
        $updateStmt->bind_param("i", $user['id']);
        $updateStmt->execute();
    }

    // Set session
    $_SESSION['user_id'] = $user['id'];
    $_SESSION['user_email'] = $user['email'];
    $_SESSION['user_name'] = $user['full_name'];
} else {
    // Create new user
    $passwordHash = password_hash(bin2hex(random_bytes(16)), PASSWORD_BCRYPT);
    
    $stmt = $db->prepare("INSERT INTO users (email, password_hash, full_name, avatar_url, is_verified) VALUES (?, ?, ?, ?, 1)");
    $stmt->bind_param("ssss", $email, $passwordHash, $fullName, $avatarUrl);
    
    if ($stmt->execute()) {
        $userId = $stmt->insert_id();

        // Create profile
        $stmt = $db->prepare("INSERT INTO profiles (user_id, full_name, email, avatar_url) VALUES (?, ?, ?, ?)");
        $stmt->bind_param("isss", $userId, $fullName, $email, $avatarUrl);
        $stmt->execute();

        // Set session
        $_SESSION['user_id'] = $userId;
        $_SESSION['user_email'] = $email;
        $_SESSION['user_name'] = $fullName;
    } else {
        header('Location: /pages/login.html?error=create_failed');
        exit();
    }
}

// Redirect to dashboard
header('Location: /pages/dashboard.html');
exit();
