# Configuration Guide

## Nginx Configuration

### Main Configuration

Edit `nginx/conf/nginx.conf`:

**Worker Processes:**
```nginx
worker_processes auto;  # Auto-detect CPU cores
worker_cpu_affinity auto;  # Pin to cores
```

**Connection Settings:**
```nginx
events {
    worker_connections 65535;  # Max connections per worker
    multi_accept on;  # Accept multiple connections at once
}
```

### Rate Limiting

Adjust rate limits in `nginx/conf/nginx.conf`:

```nginx
# Global: 1000 req/s per IP
limit_req_zone $binary_remote_addr zone=global_limit:50m rate=1000r/s;

# API: 100 req/s per IP
limit_req_zone $binary_remote_addr zone=api_limit:30m rate=100r/s;

# Login: 5 req/s per IP
limit_req_zone $binary_remote_addr zone=login_limit:10m rate=5r/s;
```

Usage in site config:
```nginx
location /api/ {
    limit_req zone=api_limit burst=200 nodelay;
}
```

### SSL/TLS Configuration

**Strong Ciphers:**
```nginx
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';
ssl_prefer_server_ciphers off;
```

**OCSP Stapling:**
```nginx
ssl_stapling on;
ssl_stapling_verify on;
ssl_trusted_certificate /etc/nginx/ssl/ca-bundle.crt;
```

### Caching

**Proxy Cache:**
```nginx
proxy_cache_path /var/cache/nginx/proxy
    levels=1:2
    keys_zone=proxy_cache:100m
    max_size=10g
    inactive=60m;
```

**Microcache:**
```nginx
location / {
    proxy_cache microcache;
    proxy_cache_valid 200 5s;  # Cache for 5 seconds
}
```

## ModSecurity WAF

### Paranoia Level

Edit `nginx/modsecurity/modsecurity.conf`:

```
# 1 = basic protection
# 2 = moderate (recommended)
# 3 = strict
# 4 = very strict (high false positive rate)
setvar:tx.paranoia_level=2
```

### Anomaly Score Threshold

Lower = stricter:

```
# Block threshold
setvar:tx.inbound_anomaly_score_threshold=5

# 5 = strict
# 10 = moderate
# 20 = permissive
```

### Whitelisting

Add IP to whitelist:
```lua
-- In nginx/lua/access_control.lua
-- Or via Redis:
redis-cli SADD "WHITELIST:ips" "192.168.1.100"
```

### Custom Rules

Add custom rules in `nginx/modsecurity/rules/custom-rules.conf`:

```
SecRule ARGS "@rx malicious-pattern" \
"id:100500,\
phase:2,\
deny,\
status:403,\
msg:'Custom attack detected'"
```

## ML Service Configuration

### Threat Score Thresholds

Edit in `ml-service/src/ml_classifier.rs`:

```rust
// Adjust scoring weights
weights.insert("request_rate".to_string(), 2.5);
weights.insert("has_suspicious_chars".to_string(), 25.0);
```

### Action Thresholds

Edit in `nginx/conf/sites-available/default.conf`:

- 0-30: Allow
- 31-60: Rate limit
- 61-80: Challenge
- 81-100: Block

## Redis Configuration

### Memory Settings

Edit `redis/redis.conf`:

```
maxmemory 2gb
maxmemory-policy allkeys-lru
```

### Persistence

```
# RDB snapshots
save 900 1
save 300 10
save 60 10000

# AOF
appendonly yes
appendfsync everysec
```

### Cluster Settings

```
cluster-enabled yes
cluster-node-timeout 15000
cluster-require-full-coverage yes
```

## ClickHouse Configuration

### Data Retention

Edit `database/schemas/init.sql`:

```sql
TTL timestamp + INTERVAL 90 DAY  -- Keep logs for 90 days
```

### Partitioning

```sql
PARTITION BY toYYYYMMDD(timestamp)  -- Daily partitions
```

## Monitoring Configuration

### Prometheus Targets

Edit `monitoring/prometheus/prometheus.yml`:

```yaml
scrape_configs:
  - job_name: 'nginx'
    static_configs:
      - targets: ['nginx-proxy:9090']

  - job_name: 'ml-service'
    static_configs:
      - targets: ['ml-service:9000']
```

### Grafana Data Sources

Add ClickHouse datasource:

```
URL: http://clickhouse:8123
Database: security
```

## Environment Variables

### .env File

```bash
# Domain
DOMAIN=yourdomain.com

# Redis
REDIS_PASSWORD=your-strong-password-here

# SSL
CERTBOT_EMAIL=admin@yourdomain.com

# Security
JWT_SECRET=generate-random-secret-here

# Passwords
CLICKHOUSE_PASSWORD=strong-password
GRAFANA_PASSWORD=strong-password
```

## Advanced Configuration

### GeoIP Blocking

In `nginx/conf/sites-available/default.conf`:

```nginx
# Block specific countries
if ($geoip2_data_country_code ~ (CN|RU|KP)) {
    return 403 "Access denied from your country";
}
```

### Custom Logging

Add custom log format:

```nginx
log_format custom '$remote_addr - $request - $status - $threat_score';
access_log /var/log/nginx/custom.log custom;
```

### Load Balancing

Configure upstream servers:

```nginx
upstream backend {
    least_conn;
    server backend1.example.com:8080 weight=5;
    server backend2.example.com:8080 weight=3;
    server backend3.example.com:8080 backup;
}
```

## Configuration Testing

```bash
# Test Nginx config
docker-compose exec nginx-proxy nginx -t

# Reload config (zero downtime)
docker-compose exec nginx-proxy nginx -s reload

# Validate ModSecurity rules
docker-compose exec nginx-proxy modsec-rules-check

# Test rate limiting
ab -n 1000 -c 100 https://yourdomain.com/
```

## Best Practices

1. **Always test in staging first**
2. **Monitor false positives**
3. **Tune slowly and incrementally**
4. **Keep logs of all changes**
5. **Document custom rules**
6. **Regular backups of configuration**

## Next Steps

- [Tuning Guide](tuning.md)
- [Troubleshooting](troubleshooting.md)
- [API Documentation](api.md)
