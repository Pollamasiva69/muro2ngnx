// ==============================================================================
// REDIS CLIENT
// Redis operations for threat intelligence and caching
// ==============================================================================

use redis::AsyncCommands;
use crate::models::Statistics;
use std::collections::HashMap;

pub struct RedisClient {
    client: redis::Client,
}

impl RedisClient {
    pub async fn new(url: &str) -> Result<Self, redis::RedisError> {
        let client = redis::Client::open(url)?;

        // Test connection
        let mut con = client.get_async_connection().await?;
        let _: () = redis::cmd("PING").query_async(&mut con).await?;

        Ok(Self { client })
    }

    /// Get request rate for IP in given window (seconds)
    pub async fn get_request_rate(&self, ip: &str, window: u64) -> Result<f64, redis::RedisError> {
        let mut con = self.client.get_async_connection().await?;
        let key = format!("REQPATTERN:{}", ip);

        let count: u64 = con.zcard(&key).await?;
        Ok(count as f64 / window as f64)
    }

    /// Get timing statistics for IP
    pub async fn get_timing_stats(&self, ip: &str) -> Result<(f64, f64), redis::RedisError> {
        let mut con = self.client.get_async_connection().await?;
        let key = format!("REQTIMING:{}", ip);

        let timestamps: Vec<f64> = con.lrange(&key, 0, 9).await?;

        if timestamps.len() < 2 {
            return Ok((0.0, 0.0));
        }

        // Calculate intervals
        let mut intervals = Vec::new();
        for i in 0..timestamps.len() - 1 {
            intervals.push((timestamps[i] - timestamps[i + 1]).abs());
        }

        // Calculate mean
        let sum: f64 = intervals.iter().sum();
        let mean = sum / intervals.len() as f64;

        // Calculate variance
        let variance_sum: f64 = intervals.iter().map(|x| (x - mean).powi(2)).sum();
        let variance = variance_sum / intervals.len() as f64;

        Ok((mean, variance))
    }

    /// Get location changes for IP
    pub async fn get_location_changes(&self, _ip: &str) -> Result<f64, redis::RedisError> {
        // Simplified implementation
        Ok(0.0)
    }

    /// Set threat score for IP
    pub async fn set_threat_score(&self, ip: &str, score: u8) -> Result<(), redis::RedisError> {
        let mut con = self.client.get_async_connection().await?;
        let key = format!("THREATSCORE:{}", ip);

        con.setex(&key, 3600, score).await?;
        Ok(())
    }

    /// Get statistics
    pub async fn get_statistics(&self) -> Result<Statistics, redis::RedisError> {
        let mut con = self.client.get_async_connection().await?;

        // Get total requests (approximate using HyperLogLog)
        let total: u64 = con.pfcount("STATS:requests:total").await.unwrap_or(0);

        // Get blocked/challenged counts
        let blocked: u64 = con.get("STATS:blocked:total").await.unwrap_or(0);
        let challenged: u64 = con.get("STATS:challenged:total").await.unwrap_or(0);

        let legitimate = total.saturating_sub(blocked + challenged);

        // Calculate average threat score (simplified)
        let avg_score = 35.0;

        let mut threat_distribution = HashMap::new();
        threat_distribution.insert("low".to_string(), legitimate);
        threat_distribution.insert("medium".to_string(), challenged);
        threat_distribution.insert("high".to_string(), blocked / 2);
        threat_distribution.insert("critical".to_string(), blocked / 2);

        Ok(Statistics {
            total_requests: total,
            blocked_requests: blocked,
            challenged_requests: challenged,
            legitimate_requests: legitimate,
            avg_threat_score: avg_score,
            threat_distribution,
        })
    }
}

impl Default for Statistics {
    fn default() -> Self {
        Self {
            total_requests: 0,
            blocked_requests: 0,
            challenged_requests: 0,
            legitimate_requests: 0,
            avg_threat_score: 0.0,
            threat_distribution: HashMap::new(),
        }
    }
}
