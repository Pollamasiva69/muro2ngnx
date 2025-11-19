-- ==============================================================================
-- ClickHouse Database Schema
-- High-performance analytics for HTTP logs and security events
-- ==============================================================================

-- Create database
CREATE DATABASE IF NOT EXISTS security;

-- HTTP Logs Table
CREATE TABLE IF NOT EXISTS security.http_logs
(
    timestamp DateTime64(3) CODEC(DoubleDelta, LZ4),
    client_ip IPv4 CODEC(LZ4),
    request_id UUID CODEC(LZ4),
    method LowCardinality(String) CODEC(LZ4),
    uri String CODEC(LZ4),
    query_string String CODEC(LZ4),
    status UInt16 CODEC(LZ4),
    response_time Float32 CODEC(LZ4),
    upstream_response_time Float32 CODEC(LZ4),
    body_bytes_sent UInt64 CODEC(LZ4),
    user_agent String CODEC(LZ4),
    referer String CODEC(LZ4),
    country FixedString(2) CODEC(LZ4),
    city String CODEC(LZ4),
    threat_score UInt8 CODEC(LZ4),
    blocked Bool CODEC(LZ4),
    block_reason String CODEC(LZ4),
    cache_status LowCardinality(String) CODEC(LZ4),

    -- Indexes for fast queries
    INDEX idx_ip client_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_time timestamp TYPE minmax GRANULARITY 1,
    INDEX idx_status status TYPE set(100) GRANULARITY 4,
    INDEX idx_uri uri TYPE tokenbf_v1(32768, 3, 0) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, client_ip)
TTL timestamp + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- Security Events Table
CREATE TABLE IF NOT EXISTS security.security_events
(
    timestamp DateTime64(3),
    event_type LowCardinality(String),
    client_ip IPv4,
    severity LowCardinality(String),
    threat_score UInt8,
    classification LowCardinality(String),
    description String,
    user_agent String,
    request_uri String,
    action LowCardinality(String),

    INDEX idx_ip client_ip TYPE bloom_filter GRANULARITY 4,
    INDEX idx_type event_type TYPE set(100) GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp)
ORDER BY (timestamp, event_type, client_ip)
TTL timestamp + INTERVAL 30 DAY
SETTINGS index_granularity = 8192;

-- Aggregated Statistics (Materialized View)
CREATE MATERIALIZED VIEW IF NOT EXISTS security.hourly_stats
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (hour, client_ip)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    client_ip,
    count() AS request_count,
    countIf(blocked = 1) AS blocked_count,
    avg(threat_score) AS avg_threat_score,
    quantile(0.95)(response_time) AS p95_response_time,
    sum(body_bytes_sent) AS total_bytes
FROM security.http_logs
GROUP BY hour, client_ip;

-- Top Attackers View
CREATE MATERIALIZED VIEW IF NOT EXISTS security.top_attackers
ENGINE = AggregatingMergeTree()
PARTITION BY toYYYYMMDD(hour)
ORDER BY (hour, client_ip)
AS SELECT
    toStartOfHour(timestamp) AS hour,
    client_ip,
    country,
    countState() AS request_count,
    sumState(toUInt64(blocked)) AS blocked_count,
    avgState(threat_score) AS avg_threat_score
FROM security.http_logs
WHERE threat_score > 50
GROUP BY hour, client_ip, country;
