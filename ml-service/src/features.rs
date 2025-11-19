// ==============================================================================
// FEATURE EXTRACTION
// Extract features from HTTP requests for ML classification
// ==============================================================================

use crate::models::{RequestFeatures, ThreatScoreRequest, VerifyRequest};
use crate::redis_client::RedisClient;
use std::collections::HashMap;

/// Feature extractor
pub struct FeatureExtractor {
    suspicious_countries: Vec<String>,
}

impl FeatureExtractor {
    pub fn new() -> Self {
        Self {
            // Countries with higher bot/attack traffic (configurable)
            suspicious_countries: vec![
                "CN".to_string(),
                "RU".to_string(),
                "KP".to_string(),
                "IR".to_string(),
            ],
        }
    }

    /// Extract features from verification request
    pub async fn extract_from_verify(
        &self,
        req: &VerifyRequest,
        redis: &RedisClient,
    ) -> RequestFeatures {
        let headers = req.headers.as_ref();

        // Request characteristics
        let uri_length = req.request_uri.len() as f64;
        let query_length = req.request_uri
            .split('?')
            .nth(1)
            .map(|q| q.len() as f64)
            .unwrap_or(0.0);

        let has_suspicious_chars = self.check_suspicious_chars(&req.request_uri);

        let method_is_get = if req.request_method == "GET" { 1.0 } else { 0.0 };
        let method_is_post = if req.request_method == "POST" { 1.0 } else { 0.0 };

        // Header analysis
        let header_count = headers.map(|h| h.len() as f64).unwrap_or(0.0);
        let has_user_agent = if req.user_agent.is_some() { 1.0 } else { 0.0 };
        let has_referer = headers
            .and_then(|h| h.get("referer"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept = headers
            .and_then(|h| h.get("accept"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept_language = headers
            .and_then(|h| h.get("accept-language"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept_encoding = headers
            .and_then(|h| h.get("accept-encoding"))
            .map(|_| 1.0)
            .unwrap_or(0.0);

        // TLS analysis
        let tls_version_score = self.parse_tls_version(req.ssl_protocol.as_deref());
        let has_strong_cipher = self.check_strong_cipher(req.ssl_cipher.as_deref());

        // Timing patterns (get from Redis)
        let (avg_interval, variance_interval) = redis
            .get_timing_stats(&req.client_ip)
            .await
            .unwrap_or((0.0, 0.0));

        // Request rate (from Redis)
        let request_rate = redis
            .get_request_rate(&req.client_ip, 60)
            .await
            .unwrap_or(0.0);

        // Geographic analysis
        let is_suspicious_country = req
            .country
            .as_ref()
            .map(|c| if self.suspicious_countries.contains(c) { 1.0 } else { 0.0 })
            .unwrap_or(0.0);

        let location_changes = redis
            .get_location_changes(&req.client_ip)
            .await
            .unwrap_or(0.0);

        // Behavioral analysis (simplified - would be more complex in production)
        let session_depth = 0.0; // Would track actual page depth
        let session_breadth = 0.0; // Would track unique paths
        let abnormal_sequence = 0.0; // Would detect unusual navigation patterns

        RequestFeatures {
            request_rate,
            uri_length,
            query_length,
            has_suspicious_chars,
            method_is_get,
            method_is_post,
            header_count,
            has_user_agent,
            has_referer,
            has_accept,
            has_accept_language,
            has_accept_encoding,
            tls_version_score,
            has_strong_cipher,
            avg_interval,
            variance_interval,
            is_suspicious_country,
            location_changes,
            session_depth,
            session_breadth,
            abnormal_sequence,
        }
    }

    /// Extract features from threat score request
    pub async fn extract_from_threat_request(
        &self,
        req: &ThreatScoreRequest,
        redis: &RedisClient,
    ) -> RequestFeatures {
        let headers = req.headers.as_ref();

        let uri_length = req.request_uri.len() as f64;
        let query_length = req.request_uri
            .split('?')
            .nth(1)
            .map(|q| q.len() as f64)
            .unwrap_or(0.0);

        let has_suspicious_chars = self.check_suspicious_chars(&req.request_uri);

        let method_is_get = if req.request_method == "GET" { 1.0 } else { 0.0 };
        let method_is_post = if req.request_method == "POST" { 1.0 } else { 0.0 };

        let header_count = headers.map(|h| h.len() as f64).unwrap_or(0.0);
        let has_user_agent = if req.user_agent.is_some() { 1.0 } else { 0.0 };
        let has_referer = headers
            .and_then(|h| h.get("referer"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept = headers
            .and_then(|h| h.get("accept"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept_language = headers
            .and_then(|h| h.get("accept-language"))
            .map(|_| 1.0)
            .unwrap_or(0.0);
        let has_accept_encoding = headers
            .and_then(|h| h.get("accept-encoding"))
            .map(|_| 1.0)
            .unwrap_or(0.0);

        // Get timing and rate data from Redis
        let (avg_interval, variance_interval) = redis
            .get_timing_stats(&req.client_ip)
            .await
            .unwrap_or((0.0, 0.0));

        let request_rate = redis
            .get_request_rate(&req.client_ip, 60)
            .await
            .unwrap_or(0.0);

        // Geographic
        let is_suspicious_country = req
            .geo_data
            .as_ref()
            .map(|g| if self.suspicious_countries.contains(&g.country) { 1.0 } else { 0.0 })
            .unwrap_or(0.0);

        let location_changes = redis
            .get_location_changes(&req.client_ip)
            .await
            .unwrap_or(0.0);

        // Session data
        let (session_depth, session_breadth, abnormal_sequence) = req
            .session_data
            .as_ref()
            .map(|s| {
                let depth = s.pages_visited.len() as f64;
                let breadth = s.pages_visited.iter().collect::<std::collections::HashSet<_>>().len() as f64;
                let abnormal = if depth > 0.0 && breadth / depth < 0.5 { 1.0 } else { 0.0 };
                (depth, breadth, abnormal)
            })
            .unwrap_or((0.0, 0.0, 0.0));

        RequestFeatures {
            request_rate,
            uri_length,
            query_length,
            has_suspicious_chars,
            method_is_get,
            method_is_post,
            header_count,
            has_user_agent,
            has_referer,
            has_accept,
            has_accept_language,
            has_accept_encoding,
            tls_version_score: 0.0,
            has_strong_cipher: 0.0,
            avg_interval,
            variance_interval,
            is_suspicious_country,
            location_changes,
            session_depth,
            session_breadth,
            abnormal_sequence,
        }
    }

    /// Check for suspicious characters in URI
    fn check_suspicious_chars(&self, uri: &str) -> f64 {
        let suspicious_patterns = vec![
            "../", "..\\", "%2e%2e", "union", "select", "script", "javascript:",
            "onerror=", "onclick=", "eval(", "base64", "system(", "exec(", "<?php",
        ];

        let uri_lower = uri.to_lowercase();
        for pattern in suspicious_patterns {
            if uri_lower.contains(pattern) {
                return 1.0;
            }
        }

        0.0
    }

    /// Parse TLS version to score
    fn parse_tls_version(&self, protocol: Option<&str>) -> f64 {
        match protocol {
            Some("TLSv1.3") => 4.0,
            Some("TLSv1.2") => 3.0,
            Some("TLSv1.1") => 2.0,
            Some("TLSv1.0") | Some("TLSv1") => 1.0,
            _ => 0.0,
        }
    }

    /// Check if cipher is strong
    fn check_strong_cipher(&self, cipher: Option<&str>) -> f64 {
        if let Some(c) = cipher {
            let c_upper = c.to_uppercase();
            // Strong ciphers: ECDHE, AES-GCM, CHACHA20
            if c_upper.contains("ECDHE") && (c_upper.contains("AES") || c_upper.contains("CHACHA20")) {
                return 1.0;
            }
        }
        0.0
    }
}

impl Default for FeatureExtractor {
    fn default() -> Self {
        Self::new()
    }
}
