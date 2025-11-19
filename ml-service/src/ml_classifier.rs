// ==============================================================================
// ML CLASSIFIER
// Machine learning based threat classification
// ==============================================================================

use crate::models::{RequestFeatures, ThreatScoreResponse};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize)]
pub struct MLClassifier {
    model_type: String,
    /// Weights for heuristic-based classification (fallback)
    weights: HashMap<String, f64>,
}

impl MLClassifier {
    /// Create new heuristic-based classifier (used when ML model not available)
    pub fn new_heuristic() -> Self {
        let mut weights = HashMap::new();

        // Feature weights for threat scoring
        weights.insert("request_rate".to_string(), 2.5);
        weights.insert("has_suspicious_chars".to_string(), 25.0);
        weights.insert("has_user_agent".to_string(), -5.0);  // Negative = good
        weights.insert("has_referer".to_string(), -2.0);
        weights.insert("has_accept".to_string(), -2.0);
        weights.insert("has_accept_language".to_string(), -2.0);
        weights.insert("has_accept_encoding".to_string(), -2.0);
        weights.insert("tls_version_score".to_string(), -3.0);
        weights.insert("has_strong_cipher".to_string(), -3.0);
        weights.insert("is_suspicious_country".to_string(), 10.0);
        weights.insert("variance_interval".to_string(), -0.5);  // Low variance = bot
        weights.insert("uri_length".to_string(), 0.05);
        weights.insert("query_length".to_string(), 0.1);

        Self {
            model_type: "heuristic".to_string(),
            weights,
        }
    }

    /// Load ML model from file
    pub fn load(_path: &str) -> Result<Self, anyhow::Error> {
        // In production, this would load a trained model (XGBoost, RandomForest, etc.)
        // For now, return heuristic model
        log::warn!("ML model loading not implemented, using heuristic classifier");
        Ok(Self::new_heuristic())
    }

    /// Predict threat score for given features
    pub fn predict(&self, features: &RequestFeatures) -> ThreatScoreResponse {
        match self.model_type.as_str() {
            "heuristic" => self.predict_heuristic(features),
            _ => self.predict_heuristic(features),  // Fallback
        }
    }

    /// Heuristic-based prediction
    fn predict_heuristic(&self, features: &RequestFeatures) -> ThreatScoreResponse {
        let mut score = 30.0;  // Base score
        let mut details = HashMap::new();

        // Request rate scoring
        let rate_score = (features.request_rate * self.weights.get("request_rate").unwrap_or(&1.0)).min(30.0);
        score += rate_score;
        details.insert("rate_score".to_string(), rate_score);

        // Suspicious characters
        if features.has_suspicious_chars > 0.5 {
            let sus_score = *self.weights.get("has_suspicious_chars").unwrap_or(&20.0);
            score += sus_score;
            details.insert("suspicious_chars".to_string(), sus_score);
        }

        // Header analysis (missing headers = suspicious)
        let header_penalty = (6.0 - (
            features.has_user_agent +
            features.has_referer +
            features.has_accept +
            features.has_accept_language +
            features.has_accept_encoding
        )) * 3.0;
        score += header_penalty;
        details.insert("header_penalty".to_string(), header_penalty);

        // TLS scoring (good TLS reduces score)
        let tls_bonus = features.tls_version_score * -2.0 + features.has_strong_cipher * -3.0;
        score += tls_bonus;
        details.insert("tls_bonus".to_string(), tls_bonus);

        // Geographic scoring
        if features.is_suspicious_country > 0.5 {
            let geo_score = *self.weights.get("is_suspicious_country").unwrap_or(&10.0);
            score += geo_score;
            details.insert("geo_score".to_string(), geo_score);
        }

        // Timing variance (bots have low variance)
        if features.variance_interval < 100.0 && features.request_rate > 5.0 {
            let timing_score = 15.0;
            score += timing_score;
            details.insert("timing_score".to_string(), timing_score);
        }

        // URI length (very long URIs can be attacks)
        if features.uri_length > 200.0 {
            let uri_score = ((features.uri_length - 200.0) * 0.1).min(10.0);
            score += uri_score;
            details.insert("uri_length_score".to_string(), uri_score);
        }

        // Clamp score to 0-100
        score = score.max(0.0).min(100.0);

        // Determine classification
        let (classification, confidence) = if score < 30.0 {
            ("legitimate", 0.9)
        } else if score < 50.0 {
            ("suspicious", 0.7)
        } else if score < 70.0 {
            ("bot", 0.8)
        } else if score < 85.0 {
            ("scraper", 0.85)
        } else {
            ("attack", 0.95)
        };

        ThreatScoreResponse {
            threat_score: score as u8,
            classification: classification.to_string(),
            confidence,
            details,
        }
    }

    /// Train model with new data
    pub fn train(&mut self, _data: &[crate::models::TrainingDataPoint]) -> Result<(), anyhow::Error> {
        // In production, this would retrain the model
        // For heuristic model, we could update weights based on feedback
        log::info!("Training not implemented for heuristic model");
        Ok(())
    }

    /// Save model to file
    pub fn save(&self, _path: &str) -> Result<(), anyhow::Error> {
        // In production, serialize and save the model
        log::info!("Model saving not implemented");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_heuristic_classifier() {
        let classifier = MLClassifier::new_heuristic();

        // Test legitimate request
        let legit_features = RequestFeatures {
            request_rate: 1.0,
            uri_length: 50.0,
            query_length: 10.0,
            has_suspicious_chars: 0.0,
            method_is_get: 1.0,
            method_is_post: 0.0,
            header_count: 10.0,
            has_user_agent: 1.0,
            has_referer: 1.0,
            has_accept: 1.0,
            has_accept_language: 1.0,
            has_accept_encoding: 1.0,
            tls_version_score: 4.0,
            has_strong_cipher: 1.0,
            avg_interval: 5000.0,
            variance_interval: 2000.0,
            is_suspicious_country: 0.0,
            location_changes: 0.0,
            session_depth: 5.0,
            session_breadth: 4.0,
            abnormal_sequence: 0.0,
        };

        let result = classifier.predict(&legit_features);
        assert!(result.threat_score < 40, "Legitimate request should have low score");

        // Test attack request
        let attack_features = RequestFeatures {
            request_rate: 50.0,
            uri_length: 300.0,
            query_length: 150.0,
            has_suspicious_chars: 1.0,
            method_is_get: 0.0,
            method_is_post: 1.0,
            header_count: 3.0,
            has_user_agent: 0.0,
            has_referer: 0.0,
            has_accept: 0.0,
            has_accept_language: 0.0,
            has_accept_encoding: 0.0,
            tls_version_score: 0.0,
            has_strong_cipher: 0.0,
            avg_interval: 50.0,
            variance_interval: 5.0,
            is_suspicious_country: 1.0,
            location_changes: 5.0,
            session_depth: 1.0,
            session_breadth: 1.0,
            abnormal_sequence: 1.0,
        };

        let result = classifier.predict(&attack_features);
        assert!(result.threat_score > 70, "Attack request should have high score");
    }
}
