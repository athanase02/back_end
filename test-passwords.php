<?php
// Test different MySQL password combinations
$host = "localhost";
$username = "root";
$database = "SI2025";

$passwords = [
    "",
    "root",
    "Otto@2023!!!",
    "password",
    "admin",
    "mysql"
];

echo "Testing MySQL Connection with different passwords...\n\n";

foreach ($passwords as $password) {
    echo "Trying password: " . ($password === "" ? "(empty)" : $password) . "...\n";
    
    $conn = @new mysqli($host, $username, $password, $database);
    
    if (!$conn->connect_error) {
        echo "✓ SUCCESS! Connected with password: " . ($password === "" ? "(empty)" : $password) . "\n";
        echo "Database: " . $database . "\n\n";
        
        // Show tables
        $result = $conn->query("SHOW TABLES");
        if ($result) {
            echo "Tables found:\n";
            while ($row = $result->fetch_row()) {
                echo "  - " . $row[0] . "\n";
            }
        }
        
        $conn->close();
        echo "\n=== Use this password in your config/db.php file ===\n";
        exit(0);
    } else {
        echo "✗ Failed: " . $conn->connect_error . "\n\n";
    }
}

echo "None of the common passwords worked. Please check your MySQL configuration.\n";
?>
