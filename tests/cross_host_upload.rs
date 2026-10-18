//! A blob upload must stay on the registry that opened the session.
//!
//! The unit tests in `client.rs` cover the guards themselves; these cover the
//! *wiring* — that the real push paths call them — by standing up two listeners
//! and having the registry try to move the upload onto the other one.
//! A different port is a different origin, so no second hostname is needed.
//!
//! A registry has two ways to attempt the move, and both are covered here for
//! each of the four requests a push addresses to a registry-supplied URL:
//! naming the foreign host in a `Location` (refused by `require_same_registry`)
//! and answering the vetted request with a redirect to it (refused by the
//! no-redirect client those four requests are issued on).

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::{header::LOCATION, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{patch, post, put},
    Router,
};
use bytes::Bytes;
use futures_util::stream;
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

/// Answers with `status` and a `Location` onto the foreign host.
///
/// Which redirect status a case uses is not cosmetic. tower-http retains only a
/// *clone* of the request body across a hop, so a `307` on a body reqwest
/// cannot clone — a streamed upload — is never followed no matter what the
/// policy says, and a test written that way would pass on reqwest's limitation
/// instead of on this crate's guard. `303` is followed for any body (it drops
/// the body and switches to `GET`), so it is the shape that discriminates
/// there. Cases with a cloneable body use `307`, which replays the blob itself
/// and is therefore the worse outcome to prove closed.
fn redirect_to(
    status: StatusCode,
    target: String,
) -> impl Fn() -> std::future::Ready<Response> + Clone {
    move || std::future::ready((status, [(LOCATION, target.clone())]).into_response())
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

/// A same-host session that hands off mid-flight: the `POST` is answered
/// honestly and the `PATCH` names the foreign host in its next-`Location`, so
/// the commit `PUT` is the first request that could cross. That is the
/// realistic registry handoff, and it reaches a different guard than the two
/// tests above — those are refused at the chunk `PATCH`, which never lets the
/// run get this far.
#[tokio::test]
async fn the_commit_put_refuses_a_cross_host_next_location() {
    let seen: Sightings = Arc::default();
    let foreign = Server::spawn({
        let seen = seen.clone();
        |_| Router::new().fallback(record).with_state(seen)
    })
    .await;

    let elsewhere = format!("http://{}/v2/testrepo/blobs/uploads/1", foreign.authority);
    let registry = Server::spawn(move |_| {
        let range_echo = move |headers: HeaderMap| {
            let range = headers
                .get("Content-Range")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("0-0")
                .to_string();
            let elsewhere = elsewhere.clone();
            async move {
                (
                    StatusCode::ACCEPTED,
                    [
                        (LOCATION.as_str(), elsewhere.as_str()),
                        ("Range", range.as_str()),
                    ],
                )
                    .into_response()
            }
        };
        Router::new()
            .route("/v2/testrepo/blobs/uploads/1", patch(range_echo))
            .route("/v2/testrepo/blobs/uploads/", post(open_session))
            .with_state("/v2/testrepo/blobs/uploads/1".to_string())
    })
    .await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = client(false)
        .push_blob(&reference, BLOB, &blob_digest())
        .await
        .expect_err("a cross-host next-Location must be refused");

    let sightings = seen.lock().unwrap().clone();
    assert!(
        sightings.is_empty(),
        "the foreign host was contacted {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::CrossHostRefused { .. }),
        "expected a refusal, got {error:?}"
    );
}

/// `push_blob_stream` with `use_monolithic_push` reaches
/// `push_stream_monolithically`, the one push entry point the buffered
/// `push_blob` above can never take.
#[tokio::test]
async fn streamed_monolithic_push_refuses_a_cross_host_upload_location() {
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
    let body = stream::once(async { Ok(Bytes::from_static(BLOB)) });
    let error = client(true)
        .push_blob_stream(&reference, body, &blob_digest(), Some(BLOB.len()))
        .await
        .expect_err("a cross-host upload Location must be refused on the streamed path too");

    let sightings = seen.lock().unwrap().clone();
    assert!(
        sightings.is_empty(),
        "the foreign host was contacted {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::CrossHostRefused { .. }),
        "expected a refusal, got {error:?}"
    );
}

/// A `Location` no URL parser accepts is an error, never a panic.
///
/// The monolithic path parses the session URL before it vets the origin, so
/// this is the one case `require_same_registry` cannot reach — and it used to
/// be an `.unwrap()` a registry could trip from the wire.
#[tokio::test]
async fn a_malformed_upload_location_is_an_error_not_a_panic() {
    let registry = Server::spawn(|_| {
        Router::new()
            .route("/v2/testrepo/blobs/uploads/", post(open_session))
            .with_state("not a url".to_string())
    })
    .await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = client(true)
        .push_blob(&reference, BLOB, &blob_digest())
        .await
        .expect_err("a malformed upload Location must be reported, not unwrapped");

    assert!(
        matches!(error, OciDistributionError::UrlParseError(_)),
        "expected a parse error, got {error:?}"
    );
}

/// The four upload requests, each answered with a `307` onto the foreign host
/// after the `Location` they were addressed to passed the origin check.
///
/// This is the second hop the string check cannot see. Every case must leave
/// the foreign host untouched and surface the `307` as a status.
async fn push_against_a_redirecting_registry(
    status: StatusCode,
    build: impl FnOnce(StatusCode, String) -> Router + Send + 'static,
    push: impl AsyncFnOnce(Client, Reference) -> OciDistributionError,
    monolithic: bool,
) {
    let seen: Sightings = Arc::default();
    let foreign = Server::spawn({
        let seen = seen.clone();
        |_| Router::new().fallback(record).with_state(seen)
    })
    .await;

    let elsewhere = format!("http://{}/v2/testrepo/blobs/uploads/1", foreign.authority);
    let registry = Server::spawn(move |_| build(status, elsewhere)).await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = push(client(monolithic), reference).await;

    let sightings = seen.lock().unwrap().clone();
    assert!(
        sightings.is_empty(),
        "the redirect was followed onto the foreign host {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::ServerError { code, .. } if code == status.as_u16()),
        "expected the {status} to surface as a status, got {error:?}"
    );
}

/// `push_chunk_body`'s `PATCH`.
#[tokio::test]
async fn a_chunk_patch_does_not_follow_a_redirect_off_the_registry() {
    push_against_a_redirecting_registry(
        StatusCode::TEMPORARY_REDIRECT,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/1",
                    patch(redirect_to(status, elsewhere)),
                )
                .route("/v2/testrepo/blobs/uploads/", post(open_session))
                .with_state("/v2/testrepo/blobs/uploads/1".to_string())
        },
        async |client: Client, reference: Reference| {
            client
                .push_blob(&reference, BLOB, &blob_digest())
                .await
                .expect_err("a redirected chunk PATCH must not be followed")
        },
        false,
    )
    .await;
}

/// `end_push_chunked_session`'s commit `PUT`.
#[tokio::test]
async fn the_commit_put_does_not_follow_a_redirect_off_the_registry() {
    push_against_a_redirecting_registry(
        StatusCode::TEMPORARY_REDIRECT,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/1",
                    patch(accept_chunk).put(redirect_to(status, elsewhere)),
                )
                .route("/v2/testrepo/blobs/uploads/", post(open_session))
                .with_state("/v2/testrepo/blobs/uploads/1".to_string())
        },
        async |client: Client, reference: Reference| {
            client
                .push_blob(&reference, BLOB, &blob_digest())
                .await
                .expect_err("a redirected commit PUT must not be followed")
        },
        false,
    )
    .await;
}

/// `push_monolithically`'s buffered `PUT` — the case that replays the whole
/// blob, since a `Bytes` body is cloneable.
#[tokio::test]
async fn a_monolithic_put_does_not_follow_a_redirect_off_the_registry() {
    push_against_a_redirecting_registry(
        StatusCode::TEMPORARY_REDIRECT,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/1",
                    put(redirect_to(status, elsewhere)),
                )
                .route("/v2/testrepo/blobs/uploads/", post(open_session))
                .with_state("/v2/testrepo/blobs/uploads/1".to_string())
        },
        async |client: Client, reference: Reference| {
            client
                .push_blob(&reference, BLOB, &blob_digest())
                .await
                .expect_err("a redirected monolithic PUT must not be followed")
        },
        true,
    )
    .await;
}

/// `push_stream_monolithically`'s streamed `PUT`.
#[tokio::test]
async fn a_streamed_monolithic_put_does_not_follow_a_redirect_off_the_registry() {
    push_against_a_redirecting_registry(
        StatusCode::SEE_OTHER,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/1",
                    put(redirect_to(status, elsewhere)),
                )
                .route("/v2/testrepo/blobs/uploads/", post(open_session))
                .with_state("/v2/testrepo/blobs/uploads/1".to_string())
        },
        async |client: Client, reference: Reference| {
            let body = stream::once(async { Ok(Bytes::from_static(BLOB)) });
            client
                .push_blob_stream(&reference, body, &blob_digest(), Some(BLOB.len()))
                .await
                .expect_err("a redirected streamed PUT must not be followed")
        },
        true,
    )
    .await;
}

/// A `ServerError` raised on an upload session names a URL the registry chose,
/// so it is redacted like every other registry-supplied URL this crate prints.
///
/// Only the session URL's *origin* was ever vetted; its path and query are the
/// registry's by construction, and `?_state=<token>` is the shape distribution
/// itself uses. `Policy::none()` routes 3xx answers onto this same path, so it
/// is a refusal path now in a way it was not before.
#[tokio::test]
async fn a_server_error_on_an_upload_session_is_redacted() {
    let registry = Server::spawn(|_| {
        Router::new()
            .route(
                "/v2/testrepo/blobs/uploads/1",
                patch(|| async { StatusCode::INTERNAL_SERVER_ERROR }),
            )
            .route("/v2/testrepo/blobs/uploads/", post(open_session))
            // Same host, so the origin check passes — and signed, the way a
            // registry that hands sessions to object storage signs them.
            .with_state("/v2/testrepo/blobs/uploads/1?X-Amz-Signature=deadbeef".to_string())
    })
    .await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = client(false)
        .push_blob(&reference, BLOB, &blob_digest())
        .await
        .expect_err("a 500 on the chunk PATCH must surface");

    let rendered = error.to_string();
    assert!(
        !rendered.contains("deadbeef"),
        "the server error published the session signature: {rendered}"
    );
    assert!(
        rendered.contains("X-Amz-Signature"),
        "the parameter name must survive, or there is nothing to diagnose: {rendered}"
    );
}

/// The `POST` that opens the session must not be relocated either.
///
/// This one has no `Location` to vet — it is the request that *asks* for one —
/// so `require_same_registry` cannot help and the no-redirect client is the
/// only thing standing between a hostile registry and a `POST` to an address
/// the caller never named. The classic target is a link-local metadata
/// endpoint, which is why the foreign listener here must stay untouched.
async fn open_session_against_a_redirecting_registry(
    monolithic: bool,
    build: impl FnOnce(StatusCode, String) -> Router + Send + 'static,
    push: impl AsyncFnOnce(Client, Reference) -> OciDistributionError,
) {
    let seen: Sightings = Arc::default();
    let foreign = Server::spawn({
        let seen = seen.clone();
        |_| Router::new().fallback(record).with_state(seen)
    })
    .await;

    let elsewhere = format!("http://{}/v2/testrepo/blobs/uploads/1", foreign.authority);
    let registry = Server::spawn(move |_| build(StatusCode::TEMPORARY_REDIRECT, elsewhere)).await;

    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    let error = push(client(monolithic), reference).await;

    let sightings = seen.lock().unwrap().clone();
    assert!(
        sightings.is_empty(),
        "the session-opening POST was relocated onto the foreign host {sightings:?}"
    );
    assert!(
        matches!(error, OciDistributionError::ServerError { code: 307, .. }),
        "expected the 307 to surface as a status, got {error:?}"
    );
}

/// `begin_push_chunked_session`.
#[tokio::test]
async fn the_chunked_session_post_does_not_follow_a_redirect_off_the_registry() {
    open_session_against_a_redirecting_registry(
        false,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/",
                    post(redirect_to(status, elsewhere)),
                )
                .with_state(String::new())
        },
        async |client: Client, reference: Reference| {
            client
                .push_blob(&reference, BLOB, &blob_digest())
                .await
                .expect_err("a redirected session POST must not be followed")
        },
    )
    .await;
}

/// `begin_push_monolithical_session`.
#[tokio::test]
async fn the_monolithic_session_post_does_not_follow_a_redirect_off_the_registry() {
    open_session_against_a_redirecting_registry(
        true,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/",
                    post(redirect_to(status, elsewhere)),
                )
                .with_state(String::new())
        },
        async |client: Client, reference: Reference| {
            client
                .push_blob(&reference, BLOB, &blob_digest())
                .await
                .expect_err("a redirected session POST must not be followed")
        },
    )
    .await;
}

/// `mount_blob` — the third `POST` to the same endpoint, and the one the
/// finding did not name.
#[tokio::test]
async fn the_mount_post_does_not_follow_a_redirect_off_the_registry() {
    open_session_against_a_redirecting_registry(
        false,
        |status, elsewhere| {
            Router::new()
                .route(
                    "/v2/testrepo/blobs/uploads/",
                    post(redirect_to(status, elsewhere)),
                )
                .with_state(String::new())
        },
        async |client: Client, reference: Reference| {
            let source = Reference::try_from("other.example.com/sourcerepo:latest").unwrap();
            client
                .mount_blob(&reference, &source, &blob_digest())
                .await
                .expect_err("a redirected mount POST must not be followed")
        },
    )
    .await;
}
