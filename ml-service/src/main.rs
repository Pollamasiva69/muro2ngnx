// ==============================================================================
// ML THREAT DETECTION SERVICE
// High-performance threat scoring service for Nginx
// ==============================================================================

use actix_web::{web, App, HttpServer, middleware};
use dotenv::dotenv;
use env_logger::Env;
use std::sync::Arc;

mod models;
mod ml_classifier;
mod features;
mod handlers;
mod redis_client;
mod metrics;

use ml_classifier::MLClassifier;
use redis_client::RedisClient;

/// Application state shared across requests
pub struct AppState {
    classifier: Arc<MLClassifier>,
    redis: Arc<RedisClient>,
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Load environment variables
    dotenv().ok();

    // Initialize logger
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    log::info!("Starting ML Threat Detection Service...");

    // Configuration
    let bind_addr = std::env::var("BIND_ADDR").unwrap_or_else(|_| "0.0.0.0:9000".to_string());
    let redis_url = std::env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".to_string());
    let model_path = std::env::var("MODEL_PATH").unwrap_or_else(|_| "./models/classifier.bin".to_string());

    // Initialize Redis client
    log::info!("Connecting to Redis at {}...", redis_url);
    let redis_client = match RedisClient::new(&redis_url).await {
        Ok(client) => {
            log::info!("Redis connection established");
            Arc::new(client)
        },
        Err(e) => {
            log::error!("Failed to connect to Redis: {}", e);
            return Err(std::io::Error::new(std::io::ErrorKind::Other, e));
        }
    };

    // Initialize ML classifier
    log::info!("Loading ML model from {}...", model_path);
    let classifier = match MLClassifier::load(&model_path) {
        Ok(clf) => {
            log::info!("ML model loaded successfully");
            Arc::new(clf)
        },
        Err(e) => {
            log::warn!("Failed to load ML model, using heuristic-based classifier: {}", e);
            Arc::new(MLClassifier::new_heuristic())
        }
    };

    // Create app state
    let app_state = web::Data::new(AppState {
        classifier,
        redis: redis_client,
    });

    log::info!("Starting HTTP server on {}...", bind_addr);

    // Start HTTP server
    HttpServer::new(move || {
        App::new()
            .app_data(app_state.clone())
            // Middlewares
            .wrap(middleware::Logger::default())
            .wrap(middleware::Compress::default())
            // Health check endpoint
            .service(
                web::resource("/health")
                    .route(web::get().to(handlers::health_check))
            )
            // Verification endpoint (called by Nginx)
            .service(
                web::resource("/verify")
                    .route(web::get().to(handlers::verify_request))
                    .route(web::post().to(handlers::verify_request))
            )
            // Threat score endpoint
            .service(
                web::resource("/score")
                    .route(web::post().to(handlers::calculate_threat_score))
            )
            // Metrics endpoint (Prometheus format)
            .service(
                web::resource("/metrics")
                    .route(web::get().to(handlers::get_metrics))
            )
            // Training endpoint (for model updates)
            .service(
                web::resource("/train")
                    .route(web::post().to(handlers::train_model))
            )
            // Statistics endpoint
            .service(
                web::resource("/stats")
                    .route(web::get().to(handlers::get_statistics))
            )
    })
    .bind(&bind_addr)?
    .workers(num_cpus::get())
    .run()
    .await
}
