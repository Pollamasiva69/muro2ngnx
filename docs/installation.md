# Installation Guide

## Prerequisites

### System Requirements
- **OS**: Ubuntu 22.04 LTS / Debian 12 / RHEL 8+ / CentOS 8+
- **RAM**: 8GB minimum, 16GB recommended
- **CPU**: 4 cores minimum, 8 cores recommended
- **Disk**: 50GB minimum, 100GB recommended (SSD preferred)
- **Network**: 1Gbps network interface

### Software Requirements
- Docker 24.0+
- Docker Compose 2.0+
- Root access

## Quick Start

### 1. Clone Repository

```bash
git clone https://github.com/yourusername/nginx-enterprise-protection.git
cd nginx-enterprise-protection
```

### 2. Run Installation Script

```bash
sudo ./deployment/scripts/install.sh
```

This automated script will:
- Check system requirements
- Install dependencies
- Apply system optimizations
- Configure firewall
- Generate SSL certificates
- Start all services

### 3. Configure Environment

Edit `.env` file with your settings:

```bash
nano .env
```

Update the following:
- `DOMAIN`: Your domain name
- `CERTBOT_EMAIL`: Your email for Let's Encrypt
- All passwords (change from defaults!)

### 4. Update Nginx Configuration

Edit domain in Nginx site configuration:

```bash
nano nginx/conf/sites-available/default.conf
```

Replace `yourdomain.com` with your actual domain.

### 5. Restart Services

```bash
cd deployment/docker
docker-compose restart
```

## Manual Installation

### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
apt-get update
apt-get install -y docker.io docker-compose
systemctl start docker
systemctl enable docker
```

**RHEL/CentOS:**
```bash
yum install -y docker docker-compose
systemctl start docker
systemctl enable docker
```

### Step 2: Apply System Optimizations

```bash
bash scripts/optimization/sysctl-tuning.sh
bash scripts/optimization/limits-config.sh
bash scripts/optimization/firewall-setup.sh
```

### Step 3: Generate SSL Certificates

**Self-signed (for testing):**
```bash
mkdir -p ssl
openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
    -keyout ssl/key.pem \
    -out ssl/cert.pem \
    -subj "/C=US/ST=State/L=City/O=Organization/CN=yourdomain.com"
```

**Let's Encrypt (production):**
```bash
docker-compose run --rm certbot certonly --webroot \
    --webroot-path=/var/www/certbot \
    --email admin@yourdomain.com \
    --agree-tos \
    --no-eff-email \
    -d yourdomain.com -d www.yourdomain.com
```

### Step 4: Start Services

```bash
cd deployment/docker
docker-compose up -d
```

### Step 5: Verify Installation

```bash
# Check services
docker-compose ps

# Test Nginx
curl -k https://localhost/health

# Test ML service
curl http://localhost:9000/health

# View logs
docker-compose logs -f nginx-proxy
```

## Post-Installation

### Initialize Redis Cluster

```bash
docker exec -it redis-master-1 redis-cli --cluster create \
    redis-master-1:6379 \
    redis-master-2:6379 \
    redis-master-3:6379 \
    --cluster-replicas 0 \
    --cluster-yes
```

### Access Dashboards

- **Grafana**: http://your-ip:3000 (admin/changeme)
- **Prometheus**: http://your-ip:9090
- **Security Dashboard**: https://your-domain:8443

### Setup Monitoring

1. Import Grafana dashboards from `monitoring/grafana/dashboards/`
2. Configure Prometheus targets
3. Setup alerting rules

## Troubleshooting

### Services won't start
```bash
# Check logs
docker-compose logs

# Check disk space
df -h

# Check ports
netstat -tlnp | grep -E '(80|443|6379|9000)'
```

### Permission denied errors
```bash
# Fix ownership
chown -R www-data:www-data /var/cache/nginx
chown -R redis:redis /data
```

### High memory usage
```bash
# Check container resources
docker stats

# Adjust memory limits in docker-compose.yml
```

## Next Steps

- [Configuration Guide](configuration.md)
- [Tuning Guide](tuning.md)
- [Security Hardening](hardening.md)
