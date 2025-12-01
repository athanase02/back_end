<?php
/**
 * Database Configuration for InfinityFree
 * Update these values with your InfinityFree credentials
 */

// InfinityFree Database Credentials
// Get these from your InfinityFree Control Panel > MySQL Databases
$host = "sql###.infinityfree.net"; // Replace ### with your server number
$username = "epiz_XXXXXXXX"; // Your MySQL username from InfinityFree
$password = "YOUR_MYSQL_PASSWORD"; // Your MySQL password
$database = "epiz_XXXXXXXX_swapit"; // Your database name (usually epiz_XXXXXXXX_swapit)

// Create connection
$conn = new mysqli($host, $username, $password, $database);

// Check connection
if ($conn->connect_error) {
    // For API requests, return JSON error
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false) {
        header('Content-Type: application/json');
        http_response_code(500);
        echo json_encode([
            'success' => false,
            'error' => 'Database connection failed',
            'message' => 'Please check database credentials in config/db.php'
        ]);
        exit;
    } else {
        die("Connection failed: " . $conn->connect_error);
    }
}

// Set charset to ensure proper handling of special characters
$conn->set_charset("utf8mb4");

// Optional: Set timezone
date_default_timezone_set('UTC');

?>
