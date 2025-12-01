<?php
// Database configuration
// Database name: SI2025 (SwapIt 2025)
$host = "localhost";
$username = "root"; // your MySQL username
$password = ""; // your MySQL password - try empty first
$database = "SI2025";

// Create connection
$conn = new mysqli($host, $username, $password);

// Check connection
if ($conn->connect_error) {
    // For API requests, return JSON error instead of dying
    if (strpos($_SERVER['REQUEST_URI'] ?? '', '/api/') !== false) {
        header('Content-Type: application/json');
        echo json_encode([
            'success' => false, 
            'error' => 'Database connection failed',
            'details' => 'Please ensure MySQL is running and credentials are correct'
        ]);
        exit;
    } else {
        die("Connection failed: " . $conn->connect_error);
    }
}

// Try to create database if it doesn't exist
$conn->query("CREATE DATABASE IF NOT EXISTS $database");
$conn->select_db($database);

// Set charset to ensure proper handling of special characters
$conn->set_charset("utf8mb4");
?>
