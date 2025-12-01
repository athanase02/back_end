#!/bin/sh
# SwapHub Backend Start Script for Railway

echo "=== SwapHub Backend Starting ==="
echo "PHP Version:"
php -v | head -1

echo ""
echo "Current Directory:"
pwd

echo ""
echo "Directory Contents:"
ls -la | head -20

echo ""
echo "=== Environment Variables ==="
echo "PORT: $PORT"
echo "MYSQLHOST: ${MYSQLHOST:-not set}"
echo "MYSQLPORT: ${MYSQLPORT:-not set}"
echo "MYSQLDATABASE: ${MYSQLDATABASE:-not set}"

echo ""
echo "=== PHP Extensions ==="
php -m | grep -E "(mysqli|json|mbstring)" || echo "Extensions check failed"

echo ""
echo "=== Starting PHP Development Server ==="
echo "Command: php -S 0.0.0.0:$PORT -t ."
php -S 0.0.0.0:$PORT -t .
