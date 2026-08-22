//! The authentication handshake is the client's most repeated request, and
//! until the token cache was consulted it ran in full — `GET /v2/` plus a
//! token-realm exchange — before *every* registry operation and before every
//! layer of a pull. These tests hold the four properties that make caching it
//! safe: a warm call costs nothing, concurrent cold callers pay once, nothing
//! negative is ever retained, and a cached challenge never suppresses a
//! legitimate later `401`.
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Request, State};
use axum::response::{IntoResponse, Response};
use axum::Router;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use oci_client::token_cache::{RegistryToken, RegistryTokenType};
use oci_client::{Client, Reference, RegistryOperation};
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::task::JoinHandle;

const MANIFEST_MEDIA_TYPE: &str = "application/vnd.oci.image.manifest.v1+json";

/// Everything the stub registry counts and can be told to do.
#[derive(Default)]
struct Registry {
    /// `GET /v2/` — the challenge probe. One per host is the whole point.
    probes: AtomicUsize,
    /// `GET /token` — the token-realm exchange. One per scope, coalesced.
    exchanges: AtomicUsize,
    /// Everything else under `/v2/`.
    resource_requests: AtomicUsize,
    /// `Authorization` header of every request that carried one, in order.
    authorizations: Mutex<Vec<String>>,
    /// `scope` query parameter of every token exchange, in order.
    scopes: Mutex<Vec<String>>,
    /// Status the token endpoint answers with; `200` mints a token.
    token_status: AtomicUsize,
    /// When set, the token endpoint waits for this to flip before it answers,
    /// so no leader can finish before every concurrent caller has arrived.
    hold: Mutex<Option<watch::Receiver<bool>>>,
    /// Repository path prefix -> how many more of its requests answer `401`.
    reject: Mutex<HashMap<String, usize>>,
    /// Whether a rejection's challenge carries an `error` parameter, which is
    /// what tells the client to drop everything cached for the host.
    reject_with_error: AtomicBool,
    /// Whether `GET /v2/` answers with a `WWW-Authenticate` challenge at all.
    challenges: AtomicBool,
    address: Mutex<String>,
}

impl Registry {
    fn realm(&self) -> String {
        format!("http://{}/token", self.address.lock().unwrap())
    }

    /// Number of requests that reached the registry, of any kind.
    fn total(&self) -> usize {
        self.probes.load(Ordering::SeqCst)
            + self.exchanges.load(Ordering::SeqCst)
            + self.resource_requests.load(Ordering::SeqCst)
    }

    fn probes(&self) -> usize {
        self.probes.load(Ordering::SeqCst)
    }

    fn exchanges(&self) -> usize {
        self.exchanges.load(Ordering::SeqCst)
    }

    fn resource_requests(&self) -> usize {
        self.resource_requests.load(Ordering::SeqCst)
    }

    fn authorizations(&self) -> Vec<String> {
        self.authorizations.lock().unwrap().clone()
    }

    fn scopes(&self) -> Vec<String> {
        self.scopes.lock().unwrap().clone()
    }

    /// Answer the next `count` requests for `repository` with `401`.
    fn reject(&self, repository: &str, count: usize) {
        self.reject
            .lock()
            .unwrap()
            .insert(repository.to_string(), count);
    }

    fn take_rejection(&self, path: &str) -> bool {
        let mut reject = self.reject.lock().unwrap();
        for (repository, remaining) in reject.iter_mut() {
            if path.contains(repository.as_str()) && *remaining > 0 {
                *remaining -= 1;
                return true;
            }
        }
        false
    }
}

struct StubRegistry {
    state: Arc<Registry>,
    handle: JoinHandle<()>,
}

impl Drop for StubRegistry {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

impl StubRegistry {
    /// A registry that answers `GET /v2/` with a bearer challenge — the shape
    /// Docker Hub, GHCR, quay.io and ACR all present.
    async fn start() -> Self {
        Self::start_with(true).await
    }

    /// `challenges = false` answers `GET /v2/` with `200` and no
    /// `WWW-Authenticate`: the case a token-cache-only shortcut cannot reach,
    /// because nothing is ever inserted for it.
    async fn start_with(challenges: bool) -> Self {
        let state = Arc::new(Registry {
            token_status: AtomicUsize::new(200),
            challenges: AtomicBool::new(challenges),
            ..Default::default()
        });

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        *state.address.lock().unwrap() =
            format!("127.0.0.1:{}", listener.local_addr().unwrap().port());

        let app = Router::new().fallback(serve).with_state(Arc::clone(&state));
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        StubRegistry { state, handle }
    }

    fn address(&self) -> String {
        self.state.address.lock().unwrap().clone()
    }

    /// Makes the token endpoint hold every answer until the returned sender
    /// releases it. Without a hold the leader can finish before the other
    /// callers reach the miss, and a coalescing assertion passes on serial
    /// execution whether or not anything is coalesced.
    fn hold(&self) -> watch::Sender<bool> {
        let (release, held) = watch::channel(false);
        *self.state.hold.lock().unwrap() = Some(held);
        release
    }

    fn client(&self) -> Client {
        Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        })
    }

    fn reference(&self, repository: &str) -> Reference {
        format!("{}/{repository}:latest", self.address())
            .parse()
            .unwrap()
    }
}

async fn serve(State(state): State<Arc<Registry>>, request: Request) -> Response {
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    if let Some(authorization) = request
        .headers()
        .get("authorization")
        .and_then(|value| value.to_str().ok())
    {
        state
            .authorizations
            .lock()
            .unwrap()
            .push(authorization.to_string());
    }

    if path == "/token" {
        state.exchanges.fetch_add(1, Ordering::SeqCst);
        let scope = query
            .split('&')
            .find_map(|pair| pair.strip_prefix("scope="))
            .unwrap_or_default()
            .to_string();
        state.scopes.lock().unwrap().push(scope);

        // Clone the receiver out before awaiting it: the lock must not be held
        // across the wait, or the callers this hold exists to collect could
        // never arrive.
        let hold = state.hold.lock().unwrap().clone();
        if let Some(mut hold) = hold {
            let _ = hold.wait_for(|released| *released).await;
        }

        let status = state.token_status.load(Ordering::SeqCst) as u16;
        if status != 200 {
            return (
                axum::http::StatusCode::from_u16(status).unwrap(),
                "token endpoint refused",
            )
                .into_response();
        }
        // A distinct token per exchange, so a test can tell which one reached
        // the wire — the difference between "a token was sent" and "the token
        // that was sent is the fresh one".
        let minted = state.exchanges.load(Ordering::SeqCst);
        return (
            [("content-type", "application/json")],
            format!(r#"{{"token":"minted-{minted}"}}"#),
        )
            .into_response();
    }

    if path == "/v2/" || path == "/v2" {
        state.probes.fetch_add(1, Ordering::SeqCst);
        if !state.challenges.load(Ordering::SeqCst) {
            return (axum::http::StatusCode::OK, "{}").into_response();
        }
        return challenge_response(&state, false);
    }

    state.resource_requests.fetch_add(1, Ordering::SeqCst);
    if state.take_rejection(&path) {
        return challenge_response(&state, state.reject_with_error.load(Ordering::SeqCst));
    }

    if path.contains("/tags/list") {
        return (
            [("content-type", "application/json")],
            r#"{"name":"stub","tags":["1.0"]}"#,
        )
            .into_response();
    }
    if path.contains("/manifests/") {
        return (
            [("content-type", MANIFEST_MEDIA_TYPE)],
            format!(r#"{{"schemaVersion":2,"mediaType":"{MANIFEST_MEDIA_TYPE}","config":{{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:{0:064x}","size":2}},"layers":[]}}"#, 0),
        )
            .into_response();
    }
    (axum::http::StatusCode::OK, "blob").into_response()
}

fn challenge_response(state: &Registry, with_error: bool) -> Response {
    let error = if with_error {
        r#",error="invalid_token""#
    } else {
        ""
    };
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(
            "www-authenticate",
            format!(r#"Bearer realm="{}",service="stub"{error}"#, state.realm()),
        )],
        "unauthorized",
    )
        .into_response()
}

fn basic() -> RegistryAuth {
    RegistryAuth::Basic("user".to_string(), "pass".to_string())
}

// ── C-001: a warm `auth()` costs nothing ────────────────────────────────────

/// The first `auth()` pays the probe and the exchange; the second pays nothing.
///
/// Red against the pre-change client, where `auth()` ran the full handshake
/// unconditionally and the second call cost the same two requests as the first.
#[tokio::test]
async fn a_warm_auth_issues_no_requests() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .unwrap();
    let cold = registry.state.total();
    assert!(
        cold <= 2,
        "a cold handshake is a probe plus an exchange, got {cold} requests"
    );

    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .unwrap();
    assert_eq!(
        registry.state.total(),
        cold,
        "a warm auth() must issue no requests at all"
    );
}

/// C-001 edge (a). Bearer costs zero requests either way, so a request count
/// cannot tell whether it short-circuits — but `auth()` is the only route that
/// installs a *rotated* bearer token, so what a shortcut would break is
/// staleness. Assert on the token that reaches the wire.
#[tokio::test]
async fn a_rotated_bearer_token_replaces_the_cached_one() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    for token in ["token-a", "token-b"] {
        client
            .auth(
                &image,
                &RegistryAuth::Bearer(token.to_string()),
                RegistryOperation::Pull,
            )
            .await
            .unwrap();
    }

    client
        .list_tags(&image, &RegistryAuth::Bearer("token-b".into()), None, None)
        .await
        .unwrap();

    let sent = registry.state.authorizations();
    assert_eq!(
        sent.last().map(String::as_str),
        Some("Bearer token-b"),
        "the rotated bearer token must reach the wire, saw {sent:?}"
    );
}

/// C-001 edge (b). A registry that answers `200` with no `WWW-Authenticate`
/// inserts nothing into the token cache, so reaching zero requests on the
/// second call is the host challenge cache's job and nothing else's.
#[tokio::test]
async fn an_unchallenged_registry_is_probed_once() {
    let registry = StubRegistry::start_with(false).await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .unwrap();
    assert_eq!(registry.state.probes(), 1);

    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .unwrap();
    assert_eq!(
        registry.state.probes(),
        1,
        "the probe answer is host-invariant and must be reused"
    );
    assert_eq!(
        registry.state.exchanges(),
        0,
        "an unchallenged registry has nothing to exchange"
    );
}

/// C-001 edges (c) and (d). The cache key is the full scope: another repository
/// or another verb set is a different token, and buildkit's `insufficient_scope`
/// class is what serving one for the other looks like.
#[tokio::test]
async fn a_different_scope_gets_its_own_exchange() {
    let registry = StubRegistry::start().await;
    let client = registry.client();

    client
        .auth(
            &registry.reference("test/one"),
            &basic(),
            RegistryOperation::Pull,
        )
        .await
        .unwrap();
    client
        .auth(
            &registry.reference("test/two"),
            &basic(),
            RegistryOperation::Pull,
        )
        .await
        .unwrap();
    client
        .auth(
            &registry.reference("test/one"),
            &basic(),
            RegistryOperation::Push,
        )
        .await
        .unwrap();

    assert_eq!(
        registry.state.exchanges(),
        3,
        "repository and operation are both part of the key"
    );
    let scopes = registry.state.scopes();
    assert!(
        scopes
            .iter()
            .any(|s| s.contains("test%2Fone") && s.ends_with("pull")),
        "the pull scope for the first repository must have been requested, saw {scopes:?}"
    );
    assert!(
        scopes.iter().any(|s| s.contains("pull%2Cpush")),
        "a push must request the pull,push scope, saw {scopes:?}"
    );
}

// ── C-003: the side effect the shortcut must not skip ───────────────────────

/// `store_auth_if_needed` runs on a cache hit too.
///
/// It is the record `apply_auth` reads to decide a request is authenticated at
/// all, so an early return placed before it makes a cache-resolved pull go out
/// anonymous — the 401-on-default-mode regression. Red-reachable by moving the
/// early return above `store_auth_if_needed`: the blob request below then
/// carries no `Authorization` header.
#[tokio::test]
async fn store_auth_runs_even_when_the_token_cache_answers() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    // Warm the token cache without going near the network, leaving the auth
    // store empty — the one state in which the ordering is observable.
    client
        .tokens
        .insert(
            &image,
            RegistryOperation::Pull,
            RegistryTokenType::Bearer(RegistryToken::Token {
                token: "prewarmed".to_string(),
            }),
        )
        .await;

    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .unwrap();
    assert_eq!(
        registry.state.total(),
        0,
        "a pre-warmed key must not touch the network"
    );

    // `pull_blob_stream` never calls `store_auth_if_needed` itself: it can only
    // authenticate from what `auth()` stored.
    let digest = format!("sha256:{:064x}", 0);
    client
        .pull_blob_stream(&image, digest.as_str())
        .await
        .unwrap();

    assert_eq!(
        registry.state.authorizations(),
        vec!["Bearer prewarmed".to_string()],
        "the blob fetch must carry the token, which it can only do if auth() stored the credentials"
    );
}

// ── C-004: concurrent cold callers pay once ─────────────────────────────────

/// Eight concurrent cold callers for one key produce one token exchange.
///
/// The token endpoint holds until all eight have arrived: without the hold the
/// leader can finish before the others reach the miss, and the test passes on
/// serial execution whether or not anything is coalesced.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_cold_callers_share_one_exchange() {
    const CALLERS: usize = 8;

    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");
    let release = registry.hold();

    let mut handles = Vec::new();
    for _ in 0..CALLERS {
        let client = client.clone();
        let image = image.clone();
        handles.push(tokio::spawn(async move {
            client
                .auth(&image, &basic(), RegistryOperation::Pull)
                .await
                .unwrap()
        }));
    }

    // Release only after every caller has had the chance to enter the miss
    // path: the exchange count is meaningless if the leader could finish first.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release.send(true).unwrap();

    let tokens: Vec<_> = futures_util::future::join_all(handles)
        .await
        .into_iter()
        .map(|joined| joined.unwrap())
        .collect();

    assert_eq!(
        registry.state.exchanges(),
        1,
        "{CALLERS} concurrent cold callers for one scope must share one exchange"
    );
    assert!(
        tokens.iter().all(|token| *token == tokens[0]),
        "every caller must receive the same token, got {tokens:?}"
    );
}

/// C-004 edge (a). A failed exchange is not retained: the next call hits the
/// token endpoint **again**. Asserted as a request count — "the waiters saw an
/// error" is equally true of a permanently cached negative, which is the bug.
#[tokio::test]
async fn a_failed_exchange_is_not_cached() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    registry.state.token_status.store(503, Ordering::SeqCst);
    let failed = client.auth(&image, &basic(), RegistryOperation::Pull).await;
    assert!(
        failed.is_err(),
        "a token endpoint answering 503 must surface as an error"
    );
    assert_eq!(registry.state.exchanges(), 1);

    registry.state.token_status.store(200, Ordering::SeqCst);
    client
        .auth(&image, &basic(), RegistryOperation::Pull)
        .await
        .expect("a later attempt must be able to succeed");
    assert_eq!(
        registry.state.exchanges(),
        2,
        "the endpoint must be hit again — one transient failure must not poison the key"
    );
}

/// C-004 edge (b). Two repositories are two flights. The barrier proves it:
/// it only releases if both exchanges genuinely arrive.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_repositories_do_not_share_a_flight() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let release = registry.hold();

    let mut handles = Vec::new();
    for repository in ["test/one", "test/two"] {
        let client = client.clone();
        let image = registry.reference(repository);
        handles.push(tokio::spawn(async move {
            client
                .auth(&image, &basic(), RegistryOperation::Pull)
                .await
                .unwrap()
        }));
    }

    tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    release.send(true).unwrap();
    for joined in futures_util::future::join_all(handles).await {
        joined.unwrap();
    }

    assert_eq!(
        registry.state.exchanges(),
        2,
        "two repositories are two scopes and must not share one exchange"
    );
}

// ── C-005 / C-025: host granularity, and the purge that makes it safe ───────

/// The probe is issued once per host, however many repositories are touched.
///
/// Red against the pre-change client, where the probe count equalled the
/// repository count — assert `== 1`, never `<= N`.
#[tokio::test]
async fn the_challenge_probe_is_issued_once_per_host() {
    let registry = StubRegistry::start().await;
    let client = registry.client();

    for repository in ["test/one", "test/two", "test/three"] {
        client
            .auth(
                &registry.reference(repository),
                &basic(),
                RegistryOperation::Pull,
            )
            .await
            .unwrap();
    }

    assert_eq!(
        registry.state.probes(),
        1,
        "three repositories under one host share one challenge probe"
    );
    assert_eq!(
        registry.state.exchanges(),
        3,
        "each repository still mints its own scoped token"
    );
}

/// A cached `200` on `/v2/` never suppresses a later per-repository `401`, and
/// the rejection drops the whole host entry so the next probe is re-derived.
///
/// Granularity is the assertion: repository A stays served from the cached
/// probe while repository B's `401` still triggers a full challenge. A test that
/// only asserted "a challenge happened" would pass against a registry-wide
/// latch, which is the containers/image#2754 bug.
#[tokio::test]
async fn a_cached_probe_does_not_suppress_a_repository_401() {
    let registry = StubRegistry::start_with(false).await;
    let client = registry.client();
    let allowed = registry.reference("test/allowed");
    let denied = registry.reference("test/denied");

    // An unchallenged host: A is served with no token at all.
    client
        .list_tags(&allowed, &basic(), None, None)
        .await
        .unwrap();
    assert_eq!(registry.state.probes(), 1);
    assert_eq!(registry.state.exchanges(), 0);

    // B rejects with a challenge naming an error, which is containerd's signal
    // that everything cached for the host is stale.
    registry
        .state
        .reject_with_error
        .store(true, Ordering::SeqCst);
    registry.state.reject("test/denied", 1);
    registry.state.challenges.store(true, Ordering::SeqCst);
    client
        .list_tags(&denied, &basic(), None, None)
        .await
        .unwrap();

    assert_eq!(
        registry.state.exchanges(),
        1,
        "the rejected repository must perform its own challenge exchange"
    );
    assert_eq!(
        registry.state.probes(),
        2,
        "the rejection must drop the host entry so the probe is re-derived"
    );
}

// ── C-020: a 401 refreshes the token and retries once ───────────────────────

/// A `401 + WWW-Authenticate` on the first request, `200` on the retried one:
/// the operation succeeds with one extra exchange and exactly one retry.
#[tokio::test]
async fn a_401_refreshes_the_token_and_retries_once() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    registry.state.reject("test/pkg", 1);
    let tags = client
        .list_tags(&image, &basic(), None, None)
        .await
        .expect("a 401 followed by a 200 must succeed");

    assert_eq!(tags.tags, vec!["1.0".to_string()]);
    assert_eq!(
        registry.state.resource_requests(),
        2,
        "exactly one retry — the rejected request and the retried one"
    );
    assert_eq!(
        registry.state.exchanges(),
        2,
        "the retry must carry a freshly minted token, not the rejected one"
    );
    let sent = registry.state.authorizations();
    assert_eq!(
        sent.last().map(String::as_str),
        Some("Bearer minted-2"),
        "the retry must send the fresh token, saw {sent:?}"
    );
}

/// A second consecutive `401` after a fresh token is an authentication failure,
/// not a retry loop.
#[tokio::test]
async fn a_second_401_is_an_authentication_failure() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let image = registry.reference("test/pkg");

    registry.state.reject("test/pkg", 10);
    let error = client
        .list_tags(&image, &basic(), None, None)
        .await
        .expect_err("a persistently rejecting registry must fail");

    assert!(
        matches!(
            error,
            OciDistributionError::UnauthorizedError { .. }
                | OciDistributionError::AuthenticationFailure(_)
                | OciDistributionError::RegistryError { .. }
        ),
        "a persistent 401 must classify as an authentication failure, got {error:?}"
    );
    assert_eq!(
        registry.state.resource_requests(),
        2,
        "one retry and no more — a loop would keep going"
    );
}
