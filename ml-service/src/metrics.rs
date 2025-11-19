// ==============================================================================
// METRICS
// Prometheus metrics collection
// ==============================================================================

use lazy_static::lazy_static;
use prometheus::{IntCounter, IntGauge, Histogram, Registry};

lazy_static! {
    pub static ref REGISTRY: Registry = Registry::new();

    pub static ref REQUESTS_TOTAL: IntCounter =
        IntCounter::new("ml_service_requests_total", "Total requests processed")
            .expect("metric can be created");

    pub static ref PREDICTIONS_TOTAL: IntCounter =
        IntCounter::new("ml_service_predictions_total", "Total predictions made")
            .expect("metric can be created");

    pub static ref BLOCKED_TOTAL: IntCounter =
        IntCounter::new("ml_service_blocked_total", "Total requests blocked")
            .expect("metric can be created");

    pub static ref CHALLENGED_TOTAL: IntCounter =
        IntCounter::new("ml_service_challenged_total", "Total requests challenged")
            .expect("metric can be created");

    pub static ref ACTIVE_CONNECTIONS: IntGauge =
        IntGauge::new("ml_service_active_connections", "Active connections")
            .expect("metric can be created");

    pub static ref PREDICTION_DURATION: Histogram =
        Histogram::new("ml_service_prediction_duration_seconds", "Prediction duration")
            .expect("metric can be created");
}

pub fn init() {
    REGISTRY.register(Box::new(REQUESTS_TOTAL.clone())).expect("collector can be registered");
    REGISTRY.register(Box::new(PREDICTIONS_TOTAL.clone())).expect("collector can be registered");
    REGISTRY.register(Box::new(BLOCKED_TOTAL.clone())).expect("collector can be registered");
    REGISTRY.register(Box::new(CHALLENGED_TOTAL.clone())).expect("collector can be registered");
    REGISTRY.register(Box::new(ACTIVE_CONNECTIONS.clone())).expect("collector can be registered");
    REGISTRY.register(Box::new(PREDICTION_DURATION.clone())).expect("collector can be registered");
}
