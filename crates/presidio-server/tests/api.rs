use axum::body::{to_bytes, Body};
use axum::http::{Request, StatusCode};
use presidio_server::app;
use tower::ServiceExt;

async fn call(
    method: &str,
    uri: &str,
    body: Option<serde_json::Value>,
) -> (StatusCode, serde_json::Value) {
    let mut req = Request::builder().method(method).uri(uri);
    let body = match body {
        Some(v) => {
            req = req.header("content-type", "application/json");
            Body::from(v.to_string())
        }
        None => Body::empty(),
    };
    let resp = app().oneshot(req.body(body).unwrap()).await.unwrap();
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
    let json = serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
    (status, json)
}

#[tokio::test]
async fn health() {
    let (status, _) = call("GET", "/health", None).await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn supported_entities_lists() {
    let (status, json) = call("GET", "/supportedentities?language=en", None).await;
    assert_eq!(status, StatusCode::OK);
    let ents: Vec<String> = serde_json::from_value(json).unwrap();
    assert!(ents.contains(&"EMAIL_ADDRESS".to_string()));
}

#[tokio::test]
async fn analyze_finds_email() {
    let (status, json) = call(
        "POST",
        "/analyze",
        Some(serde_json::json!({"text": "mail a@b.com"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(json
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["entity_type"] == "EMAIL_ADDRESS"));
}

#[tokio::test]
async fn analyze_respects_allow_list() {
    let (_, json) = call(
        "POST",
        "/analyze",
        Some(serde_json::json!({"text": "mail a@b.com", "allow_list": ["a@b.com"]})),
    )
    .await;
    assert!(json.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn anonymize_with_results() {
    let (status, json) = call(
        "POST",
        "/anonymize",
        Some(serde_json::json!({
            "text": "hi bob",
            "analyzer_results": [{"entity_type": "PERSON", "start": 3, "end": 6, "score": 0.9}],
            "anonymizers": {"DEFAULT": {"type": "redact"}}
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(json["text"], "hi ");
}

#[tokio::test]
async fn anonymize_text_convenience() {
    let (status, json) = call(
        "POST",
        "/anonymize_text",
        Some(serde_json::json!({"text": "mail a@b.com", "operator": "redact"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(!json["text"].as_str().unwrap().contains("a@b.com"));
}
