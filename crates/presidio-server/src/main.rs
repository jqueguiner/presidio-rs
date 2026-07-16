//! `presidio-server` binary — serves the analyze/anonymize HTTP API.
//! Configure the port via the `PORT` env var (default 3000).

#[tokio::main]
async fn main() {
    let app = presidio_server::app();
    let port = std::env::var("PORT")
        .ok()
        .and_then(|p| p.parse::<u16>().ok())
        .unwrap_or(3000);
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .expect("bind address");
    println!("presidio-server listening on http://{addr}");
    axum::serve(listener, app).await.expect("serve");
}
