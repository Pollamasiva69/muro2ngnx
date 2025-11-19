#!/bin/bash
# ==============================================================================
# Installation Script - Enterprise Nginx Protection System
# Automated deployment for production environments
# ==============================================================================

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REQUIRED_RAM_GB=8
REQUIRED_DISK_GB=50

echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Enterprise Nginx Protection System - Installation         ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ==============================================================================
# Pre-flight checks
# ==============================================================================
echo -e "${YELLOW}[1/10] Running pre-flight checks...${NC}"

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo -e "${RED}Error: This script must be run as root${NC}"
   exit 1
fi

# Check system resources
TOTAL_RAM=$(free -g | awk '/^Mem:/{print $2}')
if [ "$TOTAL_RAM" -lt "$REQUIRED_RAM_GB" ]; then
    echo -e "${RED}Error: Insufficient RAM. Required: ${REQUIRED_RAM_GB}GB, Available: ${TOTAL_RAM}GB${NC}"
    exit 1
fi

AVAILABLE_DISK=$(df -BG / | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_DISK" -lt "$REQUIRED_DISK_GB" ]; then
    echo -e "${RED}Error: Insufficient disk space. Required: ${REQUIRED_DISK_GB}GB, Available: ${AVAILABLE_DISK}GB${NC}"
    exit 1
fi

echo -e "${GREEN}✓ Pre-flight checks passed${NC}"

# ==============================================================================
# Install system dependencies
# ==============================================================================
echo -e "\n${YELLOW}[2/10] Installing system dependencies...${NC}"

if command -v apt-get &> /dev/null; then
    # Debian/Ubuntu
    apt-get update
    apt-get install -y \
        docker.io \
        docker-compose \
        curl \
        git \
        htop \
        iotop \
        iftop \
        nload \
        vim
elif command -v yum &> /dev/null; then
    # RHEL/CentOS
    yum install -y \
        docker \
        docker-compose \
        curl \
        git \
        htop \
        iotop \
        iftop \
        vim
fi

# Start and enable Docker
systemctl start docker
systemctl enable docker

echo -e "${GREEN}✓ Dependencies installed${NC}"

# ==============================================================================
# Apply system optimizations
# ==============================================================================
echo -e "\n${YELLOW}[3/10] Applying system optimizations...${NC}"

bash "${PROJECT_ROOT}/scripts/optimization/sysctl-tuning.sh"
bash "${PROJECT_ROOT}/scripts/optimization/limits-config.sh"

echo -e "${GREEN}✓ System optimized${NC}"

# ==============================================================================
# Configure firewall
# ==============================================================================
echo -e "\n${YELLOW}[4/10] Configuring firewall...${NC}"

bash "${PROJECT_ROOT}/scripts/optimization/firewall-setup.sh"

echo -e "${GREEN}✓ Firewall configured${NC}"

# ==============================================================================
# Setup environment variables
# ==============================================================================
echo -e "\n${YELLOW}[5/10] Setting up environment...${NC}"

if [ ! -f "${PROJECT_ROOT}/.env" ]; then
    cat > "${PROJECT_ROOT}/.env" << 'EOF'
# Domain configuration
DOMAIN=yourdomain.com

# Redis configuration
REDIS_PASSWORD=changeme_redis_password

# SSL/TLS
CERTBOT_EMAIL=admin@yourdomain.com

# Security
JWT_SECRET=changeme_jwt_secret

# ClickHouse
CLICKHOUSE_PASSWORD=changeme_clickhouse_password

# Grafana
GRAFANA_PASSWORD=changeme_grafana_password
EOF

    echo -e "${YELLOW}⚠ Default .env file created. Please edit it with your configuration!${NC}"
fi

echo -e "${GREEN}✓ Environment configured${NC}"

# ==============================================================================
# Generate SSL certificates
# ==============================================================================
echo -e "\n${YELLOW}[6/10] Generating SSL certificates...${NC}"

mkdir -p "${PROJECT_ROOT}/ssl"

# Generate self-signed cert for testing
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout "${PROJECT_ROOT}/ssl/key.pem" \
    -out "${PROJECT_ROOT}/ssl/cert.pem" \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=localhost" \
    2>/dev/null

# Generate DH parameters
if [ ! -f "${PROJECT_ROOT}/ssl/dhparam.pem" ]; then
    echo "Generating DH parameters (this may take a few minutes)..."
    openssl dhparam -out "${PROJECT_ROOT}/ssl/dhparam.pem" 2048
fi

echo -e "${GREEN}✓ SSL certificates generated${NC}"

# ==============================================================================
# Initialize Redis cluster
# ==============================================================================
echo -e "\n${YELLOW}[7/10] Initializing Redis cluster...${NC}"

# Note: Full cluster initialization requires running containers
echo "Redis cluster will be initialized after containers start"

echo -e "${GREEN}✓ Redis configuration ready${NC}"

# ==============================================================================
# Build Docker images
# ==============================================================================
echo -e "\n${YELLOW}[8/10] Building Docker images...${NC}"

cd "${PROJECT_ROOT}/deployment/docker"
docker-compose build --no-cache ml-service

echo -e "${GREEN}✓ Docker images built${NC}"

# ==============================================================================
# Start services
# ==============================================================================
echo -e "\n${YELLOW}[9/10] Starting services...${NC}"

docker-compose up -d

# Wait for services to be healthy
echo "Waiting for services to be healthy..."
sleep 10

# Check health
docker-compose ps

echo -e "${GREEN}✓ Services started${NC}"

# ==============================================================================
# Final checks
# ==============================================================================
echo -e "\n${YELLOW}[10/10] Running final checks...${NC}"

# Test Nginx
if curl -f -k https://localhost/health &> /dev/null; then
    echo -e "${GREEN}✓ Nginx is responding${NC}"
else
    echo -e "${RED}⚠ Nginx health check failed${NC}"
fi

# Test ML service
if curl -f http://localhost:9000/health &> /dev/null; then
    echo -e "${GREEN}✓ ML service is responding${NC}"
else
    echo -e "${RED}⚠ ML service health check failed${NC}"
fi

# ==============================================================================
# Installation complete
# ==============================================================================
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Installation completed successfully!                 ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "Services:"
echo -e "  • Nginx (HTTP):        http://localhost"
echo -e "  • Nginx (HTTPS):       https://localhost"
echo -e "  • Dashboard:           https://localhost:8443"
echo -e "  • Grafana:             http://localhost:3000"
echo -e "  • Prometheus:          http://localhost:9090"
echo -e "  • ML Service:          http://localhost:9000"
echo ""
echo -e "Next steps:"
echo -e "  1. Edit .env file with your configuration"
echo -e "  2. Update nginx/conf/sites-available/default.conf with your domain"
echo -e "  3. Run: docker-compose restart"
echo -e "  4. Setup Let's Encrypt: bash scripts/management/generate-ssl.sh yourdomain.com"
echo ""
echo -e "Documentation: ./docs/"
echo -e "Log files: /var/log/nginx/"
echo ""
