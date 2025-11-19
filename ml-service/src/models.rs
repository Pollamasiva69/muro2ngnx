// ==============================================================================
// DATA MODELS
// Request models, features, and responses
// ==============================================================================

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Request verification data from Nginx
#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub request_uri: String,
    pub request_method: String,
    pub ssl_protocol: Option<String>,
    pub ssl_cipher: Option<String>,
    pub country: Option<String>,
    pub headers: Option<HashMap<String, String>>,
}

/// Threat score calculation request
#[derive(Debug, Deserialize)]
pub struct ThreatScoreRequest {
    pub client_ip: String,
    pub user_agent: Option<String>,
    pub request_uri: String,
    pub request_method: String,
    pub request_body: Option<String>,
    pub headers: Option<HashMap<String, String>>,
    pub geo_data: Option<GeoData>,
    pub session_data: Option<SessionData>,
}

/// Geographic data
#[derive(Debug, Deserialize, Serialize)]
pub struct GeoData {
    pub country: String,
    pub city: Option<String>,
    pub latitude: Option<f64>,
    pub longitude: Option<f64>,
    pub asn: Option<u32>,
}

/// Session data for behavioral analysis
#[derive(Debug, Deserialize, Serialize)]
pub struct SessionData {
    pub session_id: String,
    pub request_count: u32,
    pub last_request_time: i64,
    pub pages_visited: Vec<String>,
}

/// Extracted features for ML model
#[derive(Debug, Serialize, Deserialize)]
pub struct RequestFeatures {
    // Request characteristics
    pub request_rate: f64,          // Requests per second from IP
    pub uri_length: f64,
    pub query_length: f64,
    pub has_suspicious_chars: f64,  // Binary: 0 or 1
    pub method_is_get: f64,
    pub method_is_post: f64,

    // Header analysis
    pub header_count: f64,
    pub has_user_agent: f64,
    pub has_referer: f64,
    pub has_accept: f64,
    pub has_accept_language: f64,
    pub has_accept_encoding: f64,

    // TLS fingerprinting
    pub tls_version_score: f64,     // 0=none, 1=TLSv1.0, 2=TLSv1.1, 3=TLSv1.2, 4=TLSv1.3
    pub has_strong_cipher: f64,

    // Timing patterns
    pub avg_interval: f64,          // Average time between requests (ms)
    pub variance_interval: f64,     // Variance in timing

    // Geographic
    pub is_suspicious_country: f64, // Based on threat intelligence
    pub location_changes: f64,      // Number of location changes

    // Behavioral
    pub session_depth: f64,         // Number of pages visited
    pub session_breadth: f64,       // Unique paths visited
    pub abnormal_sequence: f64,     // Unusual page flow
}

/// Threat score response
#[derive(Debug, Serialize)]
pub struct ThreatScoreResponse {
    pub threat_score: u8,           // 0-100
    pub classification: String,     // "legitimate", "suspicious", "bot", "attack"
    pub confidence: f64,            // 0.0-1.0
    pub details: HashMap<String, f64>,
}

/// Verification response for Nginx
#[derive(Debug, Serialize)]
pub struct VerifyResponse {
    pub allowed: bool,
    pub threat_score: u8,
    pub action: String,             // "allow", "rate_limit", "challenge", "block"
}

/// Training data point
#[derive(Debug, Deserialize, Serialize)]
pub struct TrainingDataPoint {
    pub features: RequestFeatures,
    pub label: u8,                  // 0=legit, 1=suspicious, 2=bot, 3=scraper, 4=attack
}

/// Model training request
#[derive(Debug, Deserialize)]
pub struct TrainRequest {
    pub data: Vec<TrainingDataPoint>,
    pub model_type: Option<String>, // "random_forest", "gradient_boosting", etc.
}

/// Statistics response
#[derive(Debug, Serialize)]
pub struct Statistics {
    pub total_requests: u64,
    pub blocked_requests: u64,
    pub challenged_requests: u64,
    pub legitimate_requests: u64,
    pub avg_threat_score: f64,
    pub threat_distribution: HashMap<String, u64>,
}

impl RequestFeatures {
    /// Convert features to vector for ML model
    pub fn to_vec(&self) -> Vec<f64> {
        vec![
            self.request_rate,
            self.uri_length,
            self.query_length,
            self.has_suspicious_chars,
            self.method_is_get,
            self.method_is_post,
            self.header_count,
            self.has_user_agent,
            self.has_referer,
            self.has_accept,
            self.has_accept_language,
            self.has_accept_encoding,
            self.tls_version_score,
            self.has_strong_cipher,
            self.avg_interval,
            self.variance_interval,
            self.is_suspicious_country,
            self.location_changes,
            self.session_depth,
            self.session_breadth,
            self.abnormal_sequence,
        ]
    }

    /// Feature names (for model interpretation)
    pub fn feature_names() -> Vec<&'static str> {
        vec![
            "request_rate",
            "uri_length",
            "query_length",
            "has_suspicious_chars",
            "method_is_get",
            "method_is_post",
            "header_count",
            "has_user_agent",
            "has_referer",
            "has_accept",
            "has_accept_language",
            "has_accept_encoding",
            "tls_version_score",
            "has_strong_cipher",
            "avg_interval",
            "variance_interval",
            "is_suspicious_country",
            "location_changes",
            "session_depth",
            "session_breadth",
            "abnormal_sequence",
        ]
    }
}
