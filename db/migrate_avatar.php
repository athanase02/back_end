<?php
/**
 * Migration Script: Add avatar_url column to users table
 */

require_once '../config/db.php';

echo "Running migration: Add avatar_url to users table\n";

try {
    // Check if column already exists
    $result = $conn->query("SHOW COLUMNS FROM users LIKE 'avatar_url'");
    
    if ($result->num_rows > 0) {
        echo "Column 'avatar_url' already exists in users table.\n";
    } else {
        // Add the column
        $sql = "ALTER TABLE users ADD COLUMN avatar_url TEXT AFTER full_name";
        
        if ($conn->query($sql) === TRUE) {
            echo "Successfully added 'avatar_url' column to users table.\n";
        } else {
            echo "Error adding column: " . $conn->error . "\n";
        }
    }
    
    // Verify the change
    $result = $conn->query("DESCRIBE users");
    echo "\nCurrent users table structure:\n";
    echo str_repeat("-", 80) . "\n";
    printf("%-20s %-20s %-10s %-10s %-20s\n", "Field", "Type", "Null", "Key", "Extra");
    echo str_repeat("-", 80) . "\n";
    
    while ($row = $result->fetch_assoc()) {
        printf("%-20s %-20s %-10s %-10s %-20s\n",
            $row['Field'],
            $row['Type'],
            $row['Null'],
            $row['Key'],
            $row['Extra']
        );
    }
    
} catch (Exception $e) {
    echo "Migration failed: " . $e->getMessage() . "\n";
}

$conn->close();
?>
