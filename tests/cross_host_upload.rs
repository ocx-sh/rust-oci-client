//! A blob upload must stay on the registry that opened the session.
//!
//! The unit tests in `client.rs` cover the guard itself; these cover the
//! *wiring* — that the real push paths call it — by standing up two listeners
//! and having the registry hand out an upload `Location` on the other one.
//! A different port is a different origin, so no second hostname is needed.

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::{header::LOCATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{patch, post},
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::OciDistributionError,
    Client, Reference,
};
use sha2::{Digest, Sha256};
use tokio::{net::TcpListener, task::JoinHandle};

const BLOB: &[u8] = b"a blob that must never leave the registry that asked for it";

/// A listener that aborts its task on drop, like `digest_validation.rs`'s
/// `BadServer`.
struct Server {
    handle: JoinHandle<()>,
    pub authority: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

impl Server {
    async fn spawn(build: impl FnOnce(String) -> Router) -> Self {
        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let authority = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let app = build(authority.clone());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { handle, authority }
    }
}

/// Every request the foreign host saw. Must stay empty.
type Sightings = Arc<Mutex<Vec<String>>>;

async fn record(State(seen): State<Sightings>, headers: HeaderMap) -> StatusCode {
    let authorization = if headers.contains_key("Authorization") {
        "with credentials"
    } else {
        "unauthenticated"
    };
    seen.lock().unwrap().push(authorization.to_string());
    StatusCode::ACCEPTED
}

/// Opens an upload session whose `Location` is whatever the test wired in.
async fn open_session(State(location): State<String>) -> Response {
    (StatusCode::ACCEPTED, [(LOCATION, location)]).into_response()
}

/// Accepts a chunk, echoing the range back as the spec requires.
async fn accept_chunk(headers: HeaderMap) -> Response {
    let range = headers
        .get("Content-Range")
        .and_then(|value| value.to_str().ok())
        .unwrap_or("0-0")
        .to_string();
    (
        StatusCode::ACCEPTED,
        [
            (LOCATION.as_str(), "/v2/testrepo/blobs/uploads/1"),
            ("Range", range.as_str()),
        ],
    )
        .into_response()
}

/// Commits the session.
async fn commit_session() -> Response {
    (
        StatusCode::CREATED,
        [(LOCATION, "/v2/testrepo/blobs/committed")],
    )
        .into_response()
}

fn client(monolithic: bool) -> Client {
    Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        use_monolithic_push: monolithic,
        ..Default::default()
    })
}

fn blob_digest() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(BLOB)))
}

/// Stands up the foreign host plus a registry that redirects uploads onto it,
/// then pushes. Returns the push error and everything the foreign host saw.
async fn push_against_foreign_location(monolithic: bool) -> (OciDistributionError, Vec<String>) {
    let seen: Sightings = Arc::default();
    let foreign = Server::spawn({
        let seen = seen.clone();
        |_| Router::new().fallback(record).with_state(seen)
    })
    .await;

    let elsewhere = format!("http://{}/v2/testrepo/blobs/uploads/1", foreign.authority);
    let registry = Server::spawn(|_| {
        Router::new()
            .route("/v2/testrepo/blobs/uploads/", post(open_session))
            .with_state(elsewhere)
    })
    .await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = client(monolithic)
        .push_blob(&reference, BLOB, &blob_digest())
        .await
        .expect_err("a cross-host upload Location must be refused");

    let sightings = seen.lock().unwrap().clone();
    (error, sightings)
}

#[tokio::test]
async fn chunked_push_refuses_a_cross_host_upload_location() {
    let (error, sightings) = push_against_foreign_location(false).await;

    // Asserted before the error shape: this is the security-relevant half, and
    // it names the leak when it fires.
    assert!(
        sightings.is_empty(),
        "the foreign host was contacted {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::CrossHostRefused { .. }),
        "expected a refusal, got {error:?}"
    );
}

#[tokio::test]
async fn monolithic_push_refuses_a_cross_host_upload_location() {
    let (error, sightings) = push_against_foreign_location(true).await;

    // Asserted before the error shape: this is the security-relevant half, and
    // it names the leak when it fires.
    assert!(
        sightings.is_empty(),
        "the foreign host was contacted {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::CrossHostRefused { .. }),
        "expected a refusal, got {error:?}"
    );
}

/// The green half: a registry keeping the session on its own host still
/// uploads. Without this, a guard that refused every push would pass the two
/// tests above.
#[tokio::test]
async fn same_host_upload_session_still_completes() {
    let registry = Server::spawn(|authority| {
        Router::new()
            .route("/v2/testrepo/blobs/uploads/", post(open_session))
            .route(
                "/v2/testrepo/blobs/uploads/1",
                patch(accept_chunk).put(commit_session),
            )
            // Absolute, on the registry's own host - the shape the guard has to
            // keep working, not merely the relative form.
            .with_state(format!("http://{authority}/v2/testrepo/blobs/uploads/1"))
    })
    .await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    client(false)
        .push_blob(&reference, BLOB, &blob_digest())
        .await
        .expect("a same-host upload session must complete");
}
