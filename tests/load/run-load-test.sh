#!/bin/bash
# ==============================================================================
# Load Testing Script
# Comprehensive performance testing
# ==============================================================================

set -e

TARGET_URL="${1:-https://localhost}"
DURATION="${2:-30s}"
CONNECTIONS="${3:-400}"
THREADS="${4:-12}"

echo "╔══════════════════════════════════════════════════════╗"
echo "║           Load Testing Configuration                 ║"
echo "╚══════════════════════════════════════════════════════╝"
echo "Target URL:    $TARGET_URL"
echo "Duration:      $DURATION"
echo "Connections:   $CONNECTIONS"
echo "Threads:       $THREADS"
echo ""

# Check if wrk is installed
if ! command -v wrk &> /dev/null; then
    echo "Error: wrk is not installed"
    echo "Install with: apt-get install wrk (Debian/Ubuntu)"
    exit 1
fi

echo "Starting load test..."
echo ""

# Run wrk test
wrk -t$THREADS -c$CONNECTIONS -d$DURATION "$TARGET_URL" \
    -H "User-Agent: LoadTest/1.0" \
    -H "Accept: text/html,application/json" \
    --latency

echo ""
echo "╔══════════════════════════════════════════════════════╗"
echo "║              Load Test Completed                     ║"
echo "╚══════════════════════════════════════════════════════╝"
