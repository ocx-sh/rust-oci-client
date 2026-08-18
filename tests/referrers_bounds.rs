//! The referrers index is the one registry response whose length nothing in the
//! protocol bounds: it grows with however many artifacts the peer claims refer
//! to the subject. These tests hold the two ceilings the client applies to it —
//! bytes on the wire, and descriptors after parsing — against a server that
//! ignores both.
use std::net::SocketAddr;

use axum::body::Body;
use axum::response::{IntoResponse, Response};
use axum::{routing::get, Router};
use futures_util::stream;
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::OciDistributionError,
    Client, Reference,
};
use tokio::{net::TcpListener, task::JoinHandle};

const SUBJECT: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const OVER_LIMIT_BYTES: usize = 5 * 1024 * 1024;

/// A well-formed index carrying `count` descriptors.
fn index_with(count: usize) -> String {
    let entries: Vec<String> = (0..count)
        .map(|n| {
            format!(
                r#"{{"mediaType":"application/vnd.oci.image.manifest.v1+json","digest":"sha256:{n:064x}","size":7}}"#
            )
        })
        .collect();
    format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{}]}}"#,
        entries.join(",")
    )
}

/// Declares its length honestly, and the length is over the cap.
async fn declared_oversize() -> Response {
    // Padding inside a JSON string keeps the body parseable, so a failure here
    // can only be the size check — never a parse error standing in for it.
    let padding = "A".repeat(OVER_LIMIT_BYTES);
    let body = format!(
        r#"{{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[],"annotations":{{"pad":"{padding}"}}}}"#
    );
    ([("content-type", "application/json")], body).into_response()
}

/// Declares nothing and streams past the cap — the case a Content-Length check
/// alone would let through.
async fn undeclared_oversize() -> Response {
    let chunks = stream::iter((0..64).map(|_| Ok::<_, std::io::Error>(vec![b'A'; 128 * 1024])));
    Response::builder()
        .header("content-type", "application/json")
        .body(Body::from_stream(chunks))
        .unwrap()
}

/// Small enough to read, too many entries to act on.
async fn too_many_descriptors() -> Response {
    ([("content-type", "application/json")], index_with(4097)).into_response()
}

struct HostileRegistry {
    handle: JoinHandle<()>,
    server: String,
}

impl Drop for HostileRegistry {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

impl HostileRegistry {
    async fn new() -> Self {
        let app = Router::new()
            .route("/v2/declared/referrers/{digest}", get(declared_oversize))
            .route("/v2/undeclared/referrers/{digest}", get(undeclared_oversize))
            .route("/v2/many/referrers/{digest}", get(too_many_descriptors));

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).await.unwrap();
        let server = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { handle, server }
    }

    fn client(&self) -> Client {
        Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        })
    }

    fn reference(&self, repository: &str) -> Reference {
        format!("{}/{repository}@{SUBJECT}", self.server).parse().unwrap()
    }
}

#[tokio::test]
async fn an_over_declared_referrers_body_is_refused_before_it_is_read() {
    let registry = HostileRegistry::new().await;
    let error = registry
        .client()
        .pull_referrers_native(&registry.reference("declared"), None)
        .await
        .expect_err("a 5 MiB referrers index must be refused");
    assert!(
        matches!(error, OciDistributionError::ResponseTooLargeError { .. }),
        "expected a size refusal, got: {error}"
    );
}

#[tokio::test]
async fn an_undeclared_referrers_body_is_refused_while_it_is_read() {
    let registry = HostileRegistry::new().await;
    let error = registry
        .client()
        .pull_referrers_native(&registry.reference("undeclared"), None)
        .await
        .expect_err("a chunked oversize referrers index must be refused");
    assert!(
        matches!(error, OciDistributionError::ResponseTooLargeError { .. }),
        "expected a size refusal, got: {error}"
    );
}

#[tokio::test]
async fn a_referrers_index_past_the_descriptor_cap_is_refused() {
    let registry = HostileRegistry::new().await;
    let error = registry
        .client()
        .pull_referrers_native(&registry.reference("many"), None)
        .await
        .expect_err("an index of 4097 descriptors must be refused");
    assert!(
        matches!(error, OciDistributionError::SpecViolationError(_)),
        "expected a descriptor-count refusal, got: {error}"
    );
}
