#!/bin/bash
# ==============================================================================
# System Limits Configuration
# ==============================================================================

set -e

echo "Configuring system limits..."

cat > /etc/security/limits.d/99-nginx.conf << 'EOF'
# Nginx limits
nginx soft nofile 1000000
nginx hard nofile 1000000
nginx soft nproc 65535
nginx hard nproc 65535

# Redis limits
redis soft nofile 100000
redis hard nofile 100000

# All users default
* soft nofile 100000
* hard nofile 100000
EOF

echo "✓ System limits configured"
