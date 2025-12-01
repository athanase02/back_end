<?php
/**
 * Database Configuration for Production
 * Supports environment variables for cloud deployment
 * 
 * @author Athanase Abayo
 * @version 1.0
 */

// Load database credentials from environment variables or use defaults
// Support multiple env var names (Railway: MYSQL_*, Generic: DB_*)
$db_host = getenv('MYSQL_HOST') ?: getenv('DB_HOST') ?: 'localhost';
$db_username = getenv('MYSQL_USER') ?: getenv('DB_USERNAME') ?: getenv('DB_USER') ?: 'root';
$db_password = getenv('MYSQL_PASSWORD') ?: getenv('DB_PASSWORD') ?: '';
$db_name = getenv('MYSQL_DATABASE') ?: getenv('DB_NAME') ?: 'SI2025';
$db_port = getenv('MYSQL_PORT') ?: getenv('DB_PORT') ?: '3306';

try {
    // Attempt to connect to MySQL database
    $conn = new mysqli($db_host, $db_username, $db_password, $db_name, $db_port);
    
    // Handle database not found (Error 1049) by creating it
    if ($conn->connect_error) {
        if (strpos($conn->connect_error, 'Unknown database') !== false || $conn->connect_errno === 1049) {
            error_log("SwapIt: Database '{$db_name}' not found. Attempting to create...");
            
            // Connect without database to create it
            $tmpConn = new mysqli($db_host, $db_username, $db_password, '', $db_port);
            if ($tmpConn->connect_error) {
                throw new Exception("Cannot connect to MySQL server: " . $tmpConn->connect_error);
            }
            
            // Create database
            $escapedDbName = $tmpConn->real_escape_string($db_name);
            if (!$tmpConn->query("CREATE DATABASE IF NOT EXISTS `{$escapedDbName}` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci")) {
                throw new Exception("Failed to create database '{$db_name}': " . $tmpConn->error);
            }
            
            error_log("SwapIt: Database '{$db_name}' created successfully");
            $tmpConn->close();
            
            // Reconnect to the new database
            $conn = new mysqli($db_host, $db_username, $db_password, $db_name, $db_port);
            if ($conn->connect_error) {
                throw new Exception("Connection failed after creating database: " . $conn->connect_error);
            }
        } else {
            throw new Exception("Database connection failed: " . $conn->connect_error);
        }
    }
    
    // Set charset
    $conn->set_charset("utf8mb4");
    
    // Log successful connection
    error_log("SwapIt: Database connected successfully");
    
} catch (Exception $e) {
    // Log error
    error_log("SwapIt Database Error: " . $e->getMessage());
    
    // In production, show generic error
    if (getenv('ENVIRONMENT') === 'production') {
        http_response_code(503);
        echo json_encode([
            'success' => false,
            'error' => 'Database service temporarily unavailable'
        ]);
        exit;
    }
    
    // In development, show detailed error
    http_response_code(503);
    echo json_encode([
        'success' => false,
        'error' => 'Database connection failed',
        'details' => $e->getMessage()
    ]);
    exit;
}
?>
