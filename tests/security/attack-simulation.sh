#!/bin/bash
# ==============================================================================
# Attack Simulation Script
# Test WAF and security systems
# ==============================================================================

set -e

TARGET="${1:-http://localhost}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║         Security Attack Simulation                   ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "Target: $TARGET"
echo ""
echo "⚠️  This script simulates attacks for TESTING ONLY"
echo ""

# SQL Injection Tests
echo "[1/5] Testing SQL Injection protection..."
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/api/users?id=1' OR '1'='1"

curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/api/users?id=1 UNION SELECT * FROM users--"

# XSS Tests
echo "[2/5] Testing XSS protection..."
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/?q=<script>alert('XSS')</script>"

curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/?q=<img src=x onerror=alert('XSS')>"

# Path Traversal Tests
echo "[3/5] Testing Path Traversal protection..."
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/../../etc/passwd"

curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/api/file?path=../../../etc/passwd"

# Command Injection Tests
echo "[4/5] Testing Command Injection protection..."
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    "$TARGET/api/ping?host=127.0.0.1;cat /etc/passwd"

# Scanner Detection
echo "[5/5] Testing Scanner Detection..."
curl -s -o /dev/null -w "Status: %{http_code}\n" \
    -H "User-Agent: sqlmap/1.0" \
    "$TARGET/"

echo ""
echo "✓ Attack simulation complete"
echo "All attacks should return 403 Forbidden or similar"
