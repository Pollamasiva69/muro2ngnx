// ==============================================================================
// HTTP HANDLERS
// API endpoints for threat detection service
// ==============================================================================

use actix_web::{web, HttpRequest, HttpResponse, Result};
use crate::{AppState, models::*, features::FeatureExtractor};
use std::time::Instant;

/// Health check endpoint
pub async fn health_check() -> HttpResponse {
    HttpResponse::Ok().json(serde_json::json!({
        "status": "healthy",
        "service": "ml-threat-detection",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

/// Verify request (called by Nginx auth_request)
pub async fn verify_request(
    req: HttpRequest,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let start = Instant::now();

    // Extract headers from Nginx
    let client_ip = req.headers()
        .get("x-client-ip")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("0.0.0.0")
        .to_string();

    let user_agent = req.headers()
        .get("x-user-agent")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let request_uri = req.headers()
        .get("x-request-uri")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("/")
        .to_string();

    let request_method = req.headers()
        .get("x-request-method")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("GET")
        .to_string();

    let ssl_protocol = req.headers()
        .get("x-ssl-protocol")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let ssl_cipher = req.headers()
        .get("x-ssl-cipher")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let country = req.headers()
        .get("x-country")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_string());

    let verify_req = VerifyRequest {
        client_ip: client_ip.clone(),
        user_agent,
        request_uri,
        request_method,
        ssl_protocol,
        ssl_cipher,
        country,
        headers: None,
    };

    // Extract features
    let extractor = FeatureExtractor::new();
    let features = extractor.extract_from_verify(&verify_req, &state.redis).await;

    // Classify
    let result = state.classifier.predict(&features);

    // Determine action
    let (allowed, action) = if result.threat_score >= 81 {
        (false, "block")
    } else if result.threat_score >= 61 {
        (true, "challenge")
    } else if result.threat_score >= 31 {
        (true, "rate_limit")
    } else {
        (true, "allow")
    };

    // Store threat score in Redis
    let _ = state.redis.set_threat_score(&verify_req.client_ip, result.threat_score).await;

    // Log processing time
    let duration = start.elapsed();
    log::debug!("Verification for {} took {:?}", verify_req.client_ip, duration);

    // Return response with custom header
    let response = VerifyResponse {
        allowed,
        threat_score: result.threat_score,
        action: action.to_string(),
    };

    let mut http_resp = if allowed {
        HttpResponse::Ok()
    } else {
        HttpResponse::Forbidden()
    };

    Ok(http_resp
        .insert_header(("X-Threat-Score", result.threat_score.to_string()))
        .insert_header(("X-Action", action))
        .json(response))
}

/// Calculate threat score (detailed endpoint)
pub async fn calculate_threat_score(
    req: web::Json<ThreatScoreRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    let extractor = FeatureExtractor::new();
    let features = extractor.extract_from_threat_request(&req, &state.redis).await;

    let result = state.classifier.predict(&features);

    // Store in Redis
    let _ = state.redis.set_threat_score(&req.client_ip, result.threat_score).await;

    Ok(HttpResponse::Ok().json(result))
}

/// Get metrics (Prometheus format)
pub async fn get_metrics(state: web::Data<AppState>) -> Result<HttpResponse> {
    let stats = state.redis.get_statistics().await.unwrap_or_default();

    let metrics = format!(
        r#"# HELP ml_service_total_requests Total requests processed
# TYPE ml_service_total_requests counter
ml_service_total_requests {}

# HELP ml_service_blocked_requests Total requests blocked
# TYPE ml_service_blocked_requests counter
ml_service_blocked_requests {}

# HELP ml_service_challenged_requests Total requests challenged
# TYPE ml_service_challenged_requests counter
ml_service_challenged_requests {}

# HELP ml_service_avg_threat_score Average threat score
# TYPE ml_service_avg_threat_score gauge
ml_service_avg_threat_score {}
"#,
        stats.total_requests,
        stats.blocked_requests,
        stats.challenged_requests,
        stats.avg_threat_score
    );

    Ok(HttpResponse::Ok()
        .content_type("text/plain; version=0.0.4")
        .body(metrics))
}

/// Train model with new data
pub async fn train_model(
    req: web::Json<TrainRequest>,
    state: web::Data<AppState>,
) -> Result<HttpResponse> {
    // In production, this would trigger model retraining
    log::info!("Received training request with {} data points", req.data.len());

    // For now, just acknowledge
    Ok(HttpResponse::Ok().json(serde_json::json!({
        "status": "accepted",
        "message": "Training queued",
        "data_points": req.data.len(),
    })))
}

/// Get statistics
pub async fn get_statistics(state: web::Data<AppState>) -> Result<HttpResponse> {
    let stats = state.redis.get_statistics().await.unwrap_or_default();
    Ok(HttpResponse::Ok().json(stats))
}
