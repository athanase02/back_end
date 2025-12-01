<?php
/**
 * Railway Production Database Configuration
 * Uses environment variables automatically provided by Railway
 */

function getDBConnection() {
    // Railway MySQL environment variables
    $host = getenv('MYSQLHOST') ?: 'localhost';
    $port = getenv('MYSQLPORT') ?: '3306';
    $database = getenv('MYSQLDATABASE') ?: 'SI2025';
    $username = getenv('MYSQLUSER') ?: 'root';
    $password = getenv('MYSQLPASSWORD') ?: '';

    try {
        $db = new mysqli($host, $username, $password, $database, $port);
        
        if ($db->connect_error) {
            error_log("Database connection failed: " . $db->connect_error);
            return null;
        }
        
        $db->set_charset('utf8mb4');
        
        // Auto-create database and tables if they don't exist
        createTablesIfNotExist($db);
        
        return $db;
    } catch (Exception $e) {
        error_log("Database error: " . $e->getMessage());
        return null;
    }
}

function createTablesIfNotExist($db) {
    // Check if users table exists
    $result = $db->query("SHOW TABLES LIKE 'users'");
    
    if ($result->num_rows == 0) {
        // Import schema from SQL file
        $sqlFile = __DIR__ . '/../db/SI2025.sql';
        
        if (file_exists($sqlFile)) {
            $sql = file_get_contents($sqlFile);
            
            // Remove CREATE DATABASE and USE statements
            $sql = preg_replace('/DROP DATABASE IF EXISTS .*;/', '', $sql);
            $sql = preg_replace('/CREATE DATABASE .*;/', '', $sql);
            $sql = preg_replace('/USE .*;/', '', $sql);
            
            // Execute SQL statements
            $db->multi_query($sql);
            
            // Clear results
            while ($db->next_result()) {
                if ($result = $db->store_result()) {
                    $result->free();
                }
            }
        }
    }
}

// Test connection
$testConnection = getDBConnection();
if ($testConnection) {
    error_log("Database connection successful");
} else {
    error_log("Database connection failed");
}
