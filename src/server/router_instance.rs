use axum::{extract::WebSocketUpgrade, routing::get, Router};
use http::Method;
use std::sync::{Arc, Mutex};
use std::time::Instant;
type Request = axum::http::Request<axum::body::Body>;
use tower_http::cors::CorsLayer;
use super::proxy_request_handler::ProxyRequestHandler;
use super::handle_websocket;

pub fn get_router_instance(allowed_origins: Vec<&str>, proxy_host: String) -> (Router, Arc<std::sync::Mutex<std::time::Instant>>) {
    let last_request_time = Arc::new(Mutex::new(Instant::now()));
    let cors_layer = CorsLayer::new()
        .allow_methods([Method::GET, Method::POST])
        .allow_origin(
            allowed_origins
                .iter()
                .map(|x| x.parse().unwrap())
                .collect::<Vec<_>>(),
        )
        .allow_private_network(true);
    let proxy_request_handler = Arc::new(ProxyRequestHandler::new(proxy_host));

    let update_last_request_time = {
        let last_request_time = Arc::clone(&last_request_time);
        move |req: Request, next: axum::middleware::Next| {
            let last_request_time = Arc::clone(&last_request_time);
            async move {
                *last_request_time.lock().unwrap() = Instant::now();
                next.run(req).await
            }
        }
    };

    let router = Router::new()
    .nest(
        "/bridge",
        Router::new()
            .route("/ping", get(|| async { "OK" }))
            .route("/", get(|ws: WebSocketUpgrade| async { ws.on_upgrade(handle_websocket) }))
            .layer(cors_layer),
    )
    .fallback(move |req: Request| {
        let proxy_request_handler = Arc::clone(&proxy_request_handler);
        async move { proxy_request_handler.handler(req).await }
    })
    .layer(axum::middleware::from_fn(update_last_request_time));

    (router, last_request_time)
}
