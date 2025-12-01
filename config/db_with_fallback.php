<?php
/**
 * Database Configuration with Mock Fallback
 * Provides a fallback when MySQL is not available for development
 * 
 * @author Athanase Abayo - Core database connection and fallback logic
 * @author Victoria Ama Nyonato - Mock database implementation
 * @author Olivier Kwizera - Connection error handling
 * @version 2.0
 */

/**
 * Mock Database Implementation
 * Provides in-memory database for development when MySQL is unavailable
 * 
 * @author Victoria Ama Nyonato - Mock database structure
 */
class MockDatabase {
    private $users = [];
    private $sessionFile;
    
    /**
     * Initialize mock database with test data
     * @author Victoria Ama Nyonato
     */
    public function __construct() {
        $this->sessionFile = __DIR__ . '/mock_sessions.json';
        
        // Initialize with some test data
        $this->users = [
            [
                'id' => 1,
                'email' => 'test@ashesi.edu.gh',
                'password_hash' => password_hash('password123', PASSWORD_DEFAULT),
                'full_name' => 'Test User',
                'avatar_url' => null,
                'is_verified' => true
            ],
            [
                'id' => 2,
                'email' => 'admin@swapit.com',
                'password_hash' => password_hash('admin123', PASSWORD_DEFAULT),
                'full_name' => 'SwapIt Admin',
                'avatar_url' => null,
                'is_verified' => true
            ]
        ];
    }
    
    /**
     * Prepare a mock SQL statement
     * @param string $sql - SQL query
     * @return MockStatement - Mock statement object
     * @author Victoria Ama Nyonato
     */
    public function prepare($sql) {
        return new MockStatement($sql, $this->users);
    }
    
    /**
     * Check for connection errors (always returns false for mock)
     * @return bool - Always false for mock database
     * @author Olivier Kwizera
     */
    public function connect_error() {
        return false; // No connection error for mock
    }
    
    /**
     * Set character set (no-op for mock)
     * @param string $charset - Character set name
     * @return bool - Always true for mock
     * @author Olivier Kwizera
     */
    public function set_charset($charset) {
        return true;
    }
    
    /**
     * Execute a query (no-op for mock)
     * @param string $sql - SQL query
     * @return MockResult - Mock result object
     * @author Victoria Ama Nyonato
     */
    public function query($sql) {
        return new MockResult();
    }
    
    /**
     * Select database (no-op for mock)
     * @param string $db - Database name
     * @return bool - Always true for mock
     * @author Olivier Kwizera
     */
    public function select_db($db) {
        return true;
    }
}

/**
 * Mock Statement Implementation
 * Simulates prepared statements for mock database
 * 
 * @author Victoria Ama Nyonato - Statement execution logic
 */
class MockStatement {
    private $sql;
    private $users;
    private $params = [];
    
    /**
     * Initialize mock statement
     * @param string $sql - SQL query
     * @param array $users - User data array
     * @author Victoria Ama Nyonato
     */
    public function __construct($sql, $users) {
        $this->sql = $sql;
        $this->users = $users;
    }
    
    /**
     * Bind parameters to statement
     * @param string $types - Parameter types
     * @param mixed ...$params - Parameters to bind
     * @author Victoria Ama Nyonato
     */
    public function bind_param($types, ...$params) {
        $this->params = $params;
    }
    
    /**
     * Execute the statement
     * @return bool - Always true for mock
     * @author Victoria Ama Nyonato
     */
    public function execute() {
        return true;
    }
    
    /**
     * Get result set from executed statement
     * @return MockResult - Mock result object
     * @author Victoria Ama Nyonato - Result simulation logic
     */
    public function get_result() {
        // Simulate user login query
        if (strpos($this->sql, 'SELECT') !== false && strpos($this->sql, 'users') !== false && strpos($this->sql, 'email') !== false) {
            $email = $this->params[0] ?? '';
            
            foreach ($this->users as $user) {
                if ($user['email'] === $email) {
                    return new MockResult([$user]);
                }
            }
            return new MockResult([]);
        }
        
        return new MockResult();
    }
    
    /**
     * Close the statement
     * @return bool - Always true for mock
     * @author Victoria Ama Nyonato
     */
    public function close() {
        return true;
    }
}

/**
 * Mock Result Set Implementation
 * Simulates result sets for mock database queries
 * 
 * @author Victoria Ama Nyonato - Result set simulation
 */
class MockResult {
    private $data;
    private $index = 0;
    
    /**
     * Initialize mock result set
     * @param array $data - Result data
     * @author Victoria Ama Nyonato
     */
    public function __construct($data = []) {
        $this->data = $data;
    }
    
    /**
     * Fetch next row as associative array
     * @return array|null - Row data or null if no more rows
     * @author Victoria Ama Nyonato
     */
    public function fetch_assoc() {
        if ($this->index < count($this->data)) {
            return $this->data[$this->index++];
        }
        return null;
    }
    
    /**
     * Get number of rows in result set
     * @return int - Number of rows
     * @author Victoria Ama Nyonato
     */
    public function num_rows() {
        return count($this->data);
    }
}

/**
 * Database Connection with Automatic Fallback
 * Tries to connect to MySQL first, falls back to mock database if unavailable
 * 
 * @author Athanase Abayo - Connection logic and fallback handling
 * @author Olivier Kwizera - Error handling and logging
 */
// Try to create real MySQL connection first, fallback to mock
try {
    $host = "localhost";
    $username = "root";
    $password = "";
    $database = "SI2025";
    
    $conn = new mysqli($host, $username, $password);
    
    if ($conn->connect_error) {
        throw new Exception("MySQL connection failed");
    }
    
    // Try to create database if it doesn't exist
    $conn->query("CREATE DATABASE IF NOT EXISTS $database");
    $conn->select_db($database);
    $conn->set_charset("utf8mb4");
    
    // Test if we can actually use the database
    $test_query = $conn->query("SHOW TABLES");
    if (!$test_query) {
        throw new Exception("Database not accessible");
    }
    
} catch (Exception $e) {
    // Use mock database as fallback
    $conn = new MockDatabase();
    
    // Log that we're using mock database
    error_log("SwapIt: Using mock database - " . $e->getMessage());
}
?>