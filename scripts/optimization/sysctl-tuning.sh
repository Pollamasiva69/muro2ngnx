#!/bin/bash
# ==============================================================================
# System Kernel Tuning for High-Performance Nginx
# ==============================================================================

set -e

echo "Applying sysctl optimizations..."

cat > /etc/sysctl.d/99-nginx-performance.conf << 'EOF'
# Network Performance Tuning
net.core.somaxconn = 65535
net.core.netdev_max_backlog = 65535
net.ipv4.tcp_max_syn_backlog = 65535
net.ipv4.ip_local_port_range = 1024 65535

# TCP Tuning
net.ipv4.tcp_fin_timeout = 10
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 60
net.ipv4.tcp_keepalive_probes = 3

# TCP Buffer Sizes
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_rmem = 4096 87380 16777216
net.ipv4.tcp_wmem = 4096 65536 16777216

# TCP Congestion Control - BBR
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# Connection Tracking
net.netfilter.nf_conntrack_max = 1000000
net.netfilter.nf_conntrack_tcp_timeout_established = 600
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# File System
fs.file-max = 2097152
fs.inotify.max_user_watches = 524288

# Memory Management
vm.swappiness = 10
vm.dirty_ratio = 15
vm.dirty_background_ratio = 5

# Security (SYN flood protection)
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
EOF

# Apply settings
sysctl -p /etc/sysctl.d/99-nginx-performance.conf

echo "✓ Sysctl tuning applied"
