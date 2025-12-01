<?php
/**
 * Database Configuration - Auto-detects Railway vs Local
 * @author Team SwapHub
 */

function getDBConnection() {
    // Check if running on Railway (production)
    if (getenv('MYSQLHOST')) {
        $host = getenv('MYSQLHOST');
        $port = getenv('MYSQLPORT') ?: '3306';
        $database = getenv('MYSQLDATABASE') ?: 'railway';
        $username = getenv('MYSQLUSER');
        $password = getenv('MYSQLPASSWORD');
    } else {
        // Local development
        $host = 'localhost';
        $port = '3306';
        $database = 'SI2025';
        $username = 'root';
        $password = '';
    }
    
    try {
        $db = new mysqli($host, $username, $password, $database, $port);
        
        if ($db->connect_error) {
            error_log("Connection failed: " . $db->connect_error);
            return null;
        }
        
        $db->set_charset('utf8mb4');
        
        // Auto-create tables on first run
        createTablesIfNotExist($db);
        
        return $db;
    } catch (Exception $e) {
        error_log("Database error: " . $e->getMessage());
        return null;
    }
}

function createTablesIfNotExist($db) {
    $result = $db->query("SHOW TABLES LIKE 'users'");
    
    if ($result && $result->num_rows == 0) {
        $sqlFile = __DIR__ . '/../db/SI2025.sql';
        
        if (file_exists($sqlFile)) {
            $sql = file_get_contents($sqlFile);
            $sql = preg_replace('/DROP DATABASE IF EXISTS .*;/', '', $sql);
            $sql = preg_replace('/CREATE DATABASE .*;/', '', $sql);
            $sql = preg_replace('/USE .*;/', '', $sql);
            
            if ($db->multi_query($sql)) {
                while ($db->next_result()) {
                    if ($res = $db->store_result()) {
                        $res->free();
                    }
                }
            }
        }
    }
}

// Legacy support - create $conn variable for backward compatibility
$conn = getDBConnection();
?>
