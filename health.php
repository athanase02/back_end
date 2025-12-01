<?php
// Health check endpoint
header('Content-Type: application/json');

$health = [
    'status' => 'ok',
    'timestamp' => date('Y-m-d H:i:s'),
    'php_version' => PHP_VERSION,
    'extensions' => [
        'mysqli' => extension_loaded('mysqli'),
        'json' => extension_loaded('json'),
        'mbstring' => extension_loaded('mbstring')
    ],
    'environment' => [
        'MYSQLHOST' => getenv('MYSQLHOST') ? 'set' : 'not set',
        'MYSQLPORT' => getenv('MYSQLPORT') ?: 'not set',
        'MYSQLDATABASE' => getenv('MYSQLDATABASE') ?: 'not set'
    ]
];

echo json_encode($health, JSON_PRETTY_PRINT);
