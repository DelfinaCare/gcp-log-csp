use axum::{
    body::Bytes,
    extract::{ConnectInfo, DefaultBodyLimit},
    http::{HeaderMap, Method, StatusCode, Uri},
    routing::{get, post},
    Router,
};
use std::net::SocketAddr;

/// Maximum request body size: 16 KiB
const MAX_BODY_SIZE: usize = 16_384;

/// Build the application router.
pub fn app(csp_endpoint: &str) -> Router {
    Router::new()
        .route(csp_endpoint, post(handle_csp_report))
        .route("/health", get(health))
        .layer(DefaultBodyLimit::max(MAX_BODY_SIZE))
}

/// Health check endpoint.
async fn health() -> StatusCode {
    StatusCode::OK
}

/// Handle incoming CSP violation reports.
///
/// Accepts both the legacy `report-uri` format (`application/csp-report`)
/// and the newer Reporting API format (`application/reports+json`).
/// The report is logged as a GCP structured log entry to stdout.
async fn handle_csp_report(
    ConnectInfo(peer_addr): ConnectInfo<SocketAddr>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> StatusCode {
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    // Only accept JSON-like content types used by CSP reporting.
    if !is_accepted_content_type(content_type) {
        return StatusCode::UNSUPPORTED_MEDIA_TYPE;
    }

    let http_request = build_http_request_log(&peer_addr, &method, &uri, &headers, body.len());

    match serde_json::from_slice::<serde_json::Value>(&body) {
        Ok(parsed) => {
            let log_entry = serde_json::json!({
                "severity": "WARNING",
                "message": "CSP violation report received",
                "httpRequest": http_request,
                "csp-report": parsed
            });
            println!("{log_entry}");
        }
        Err(_) => {
            let log_entry = serde_json::json!({
                "severity": "WARNING",
                "message": "CSP report received with invalid JSON body",
                "httpRequest": http_request,
                "raw-body": String::from_utf8_lossy(&body)
            });
            println!("{log_entry}");
            return StatusCode::BAD_REQUEST;
        }
    }

    StatusCode::NO_CONTENT
}

/// Build the GCP structured logging `httpRequest` object from the incoming request.
///
/// Populates all fields that can be derived from the request at this layer:
/// - `requestMethod`, `requestUrl`, `requestSize`, `protocol`
/// - `userAgent`, `referer` from headers
/// - `remoteIp` from the direct peer address; `X-Forwarded-For` / `X-Real-IP`
///   are included separately when present so callers can apply their own trust policy.
fn build_http_request_log(
    peer_addr: &SocketAddr,
    method: &Method,
    uri: &Uri,
    headers: &HeaderMap,
    body_len: usize,
) -> serde_json::Value {
    let mut obj = serde_json::Map::new();

    obj.insert(
        "requestMethod".into(),
        serde_json::Value::String(method.to_string()),
    );
    obj.insert(
        "requestUrl".into(),
        serde_json::Value::String(uri.to_string()),
    );
    // GCP expects requestSize as a string (int64 formatted as string).
    obj.insert(
        "requestSize".into(),
        serde_json::Value::String(body_len.to_string()),
    );
    obj.insert(
        "remoteIp".into(),
        serde_json::Value::String(peer_addr.to_string()),
    );

    if let Some(ua) = headers.get("user-agent").and_then(|v| v.to_str().ok()) {
        obj.insert(
            "userAgent".into(),
            serde_json::Value::String(ua.to_string()),
        );
    }
    if let Some(referer) = headers.get("referer").and_then(|v| v.to_str().ok()) {
        obj.insert(
            "referer".into(),
            serde_json::Value::String(referer.to_string()),
        );
    }
    // X-Forwarded-For / X-Real-IP: include as informational fields so that operators
    // running behind a trusted proxy can identify the originating client.
    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        obj.insert(
            "xForwardedFor".into(),
            serde_json::Value::String(xff.to_string()),
        );
    }
    if let Some(xri) = headers.get("x-real-ip").and_then(|v| v.to_str().ok()) {
        obj.insert("xRealIp".into(), serde_json::Value::String(xri.to_string()));
    }
    if let Some(origin) = headers.get("origin").and_then(|v| v.to_str().ok()) {
        obj.insert(
            "origin".into(),
            serde_json::Value::String(origin.to_string()),
        );
    }
    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        obj.insert(
            "protocol".into(),
            serde_json::Value::String(proto.to_string()),
        );
    }

    serde_json::Value::Object(obj)
}

/// Check whether the content type is one used by CSP reporting mechanisms.
fn is_accepted_content_type(ct: &str) -> bool {
    let ct_lower = ct.to_ascii_lowercase();
    ct_lower.starts_with("application/csp-report")
        || ct_lower.starts_with("application/json")
        || ct_lower.starts_with("application/reports+json")
}

#[tokio::main]
async fn main() {
    let port: u16 = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(8080);

    let csp_endpoint = std::env::var("CSP_ENDPOINT").unwrap_or_else(|_| "/csp-report".to_string());

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind to address");

    eprintln!("Listening on {addr}");
    axum::serve(
        listener,
        app(&csp_endpoint).into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await
    .expect("server error");
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use http_body_util::BodyExt;
    use tower::util::ServiceExt;

    /// Fake peer address used in tests that exercise the CSP handler.
    fn fake_peer() -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], 12345))
    }

    /// Build a POST request to the CSP handler, injecting a fake ConnectInfo extension.
    fn csp_post(uri: &str, content_type: &str, body: Vec<u8>) -> Request<Body> {
        Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", content_type)
            .extension(ConnectInfo(fake_peer()))
            .body(Body::from(body))
            .unwrap()
    }

    #[tokio::test]
    async fn health_returns_ok() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn csp_report_uri_format() {
        let body = serde_json::json!({
            "csp-report": {
                "document-uri": "https://example.com",
                "violated-directive": "script-src 'self'",
                "blocked-uri": "https://evil.com/script.js",
                "original-policy": "script-src 'self'; report-uri /csp-report"
            }
        });

        let response = app("/csp-report")
            .oneshot(csp_post(
                "/csp-report",
                "application/csp-report",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_to_format() {
        let body = serde_json::json!([{
            "type": "csp-violation",
            "age": 10,
            "url": "https://example.com/page",
            "user_agent": "Mozilla/5.0",
            "body": {
                "documentURL": "https://example.com/page",
                "blockedURL": "https://evil.com/script.js",
                "effectiveDirective": "script-src-elem",
                "originalPolicy": "script-src 'self'; report-to csp-endpoint"
            }
        }]);

        let response = app("/csp-report")
            .oneshot(csp_post(
                "/csp-report",
                "application/reports+json",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_with_application_json() {
        let body = serde_json::json!({"test": true});

        let response = app("/csp-report")
            .oneshot(csp_post(
                "/csp-report",
                "application/json",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn csp_report_rejects_wrong_content_type() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "text/plain")
                    .extension(ConnectInfo(fake_peer()))
                    .body(Body::from("not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn csp_report_rejects_invalid_json() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/csp-report")
                    .extension(ConnectInfo(fake_peer()))
                    .body(Body::from("this is not json"))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn csp_report_rejects_get_method() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .method("GET")
                    .uri("/csp-report")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
    }

    #[tokio::test]
    async fn csp_report_rejects_oversized_body() {
        // Create a body larger than MAX_BODY_SIZE
        let large_body = vec![b'{'; MAX_BODY_SIZE + 1];

        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/csp-report")
                    .header("content-type", "application/csp-report")
                    .extension(ConnectInfo(fake_peer()))
                    .body(Body::from(large_body))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .uri("/nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn health_returns_empty_body() {
        let response = app("/csp-report")
            .oneshot(
                Request::builder()
                    .uri("/health")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        let body = response.into_body().collect().await.unwrap().to_bytes();
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn custom_csp_endpoint_accepts_reports() {
        let body = serde_json::json!({"test": true});

        let response = app("/custom-csp")
            .oneshot(csp_post(
                "/custom-csp",
                "application/csp-report",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn custom_csp_endpoint_default_path_returns_404() {
        let body = serde_json::json!({"test": true});

        let response = app("/custom-csp")
            .oneshot(csp_post(
                "/csp-report",
                "application/csp-report",
                serde_json::to_vec(&body).unwrap(),
            ))
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    // --- Unit tests for build_http_request_log ---

    #[test]
    fn http_request_log_basic_fields() {
        let peer: SocketAddr = "10.0.0.1:9999".parse().unwrap();
        let method = Method::POST;
        let uri: Uri = "/csp-report".parse().unwrap();
        let headers = HeaderMap::new();
        let log = build_http_request_log(&peer, &method, &uri, &headers, 42);

        assert_eq!(log["requestMethod"], "POST");
        assert_eq!(log["requestUrl"], "/csp-report");
        assert_eq!(log["requestSize"], "42");
        assert_eq!(log["remoteIp"], "10.0.0.1:9999");
    }

    #[test]
    fn http_request_log_optional_headers() {
        use axum::http::HeaderValue;

        let peer: SocketAddr = "10.0.0.2:8888".parse().unwrap();
        let method = Method::POST;
        let uri: Uri = "/csp-report".parse().unwrap();
        let mut headers = HeaderMap::new();
        headers.insert("user-agent", HeaderValue::from_static("TestBrowser/1.0"));
        headers.insert("referer", HeaderValue::from_static("https://example.com/"));
        headers.insert(
            "x-forwarded-for",
            HeaderValue::from_static("1.2.3.4, 5.6.7.8"),
        );
        headers.insert("x-real-ip", HeaderValue::from_static("1.2.3.4"));
        headers.insert("origin", HeaderValue::from_static("https://example.com"));
        headers.insert("x-forwarded-proto", HeaderValue::from_static("https"));

        let log = build_http_request_log(&peer, &method, &uri, &headers, 0);

        assert_eq!(log["userAgent"], "TestBrowser/1.0");
        assert_eq!(log["referer"], "https://example.com/");
        assert_eq!(log["xForwardedFor"], "1.2.3.4, 5.6.7.8");
        assert_eq!(log["xRealIp"], "1.2.3.4");
        assert_eq!(log["origin"], "https://example.com");
        assert_eq!(log["protocol"], "https");
    }

    #[test]
    fn http_request_log_missing_optional_headers_are_absent() {
        let peer: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let method = Method::POST;
        let uri: Uri = "/csp-report".parse().unwrap();
        let headers = HeaderMap::new();
        let log = build_http_request_log(&peer, &method, &uri, &headers, 0);

        assert!(log.get("userAgent").is_none());
        assert!(log.get("referer").is_none());
        assert!(log.get("xForwardedFor").is_none());
        assert!(log.get("xRealIp").is_none());
        assert!(log.get("origin").is_none());
        assert!(log.get("protocol").is_none());
    }
}
