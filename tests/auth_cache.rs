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
    /// Whether `GET /v2/` answers with a `WWW-Authenticate` challenge at all.
    challenges: AtomicBool,
    /// Answer the probe with a `Basic` challenge instead of a `Bearer` one —
    /// the shape that drives `_auth` into its HTTP Basic fallback.
    basic_challenge: AtomicBool,
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

    /// A client that treats a token carrying no expiry claim as living `secs`
    /// seconds — the knob a short-lived registry token would turn.
    fn client_with_token_lifetime(&self, secs: usize) -> Client {
        Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            default_token_expiration_secs: secs,
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
        if state.basic_challenge.load(Ordering::SeqCst) {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                [("www-authenticate", r#"Basic realm="stub""#)],
                "unauthorized",
            )
                .into_response();
        }
        return challenge_response(&state);
    }

    state.resource_requests.fetch_add(1, Ordering::SeqCst);
    if state.take_rejection(&path) {
        return challenge_response(&state);
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

/// A plain `Bearer` challenge with **no** `error` parameter — the shape a
/// registry that has revoked a token commonly answers with, and precisely the
/// one an `error=`-only purge would ignore.
fn challenge_response(state: &Registry) -> Response {
    (
        axum::http::StatusCode::UNAUTHORIZED,
        [(
            "www-authenticate",
            format!(r#"Bearer realm="{}",service="stub""#, state.realm()),
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

    // B is rejected with a plain challenge — no `error` parameter, the shape a
    // revoked token draws and the one an `error=`-only purge would ignore.
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
        1,
        "the retry re-derives its challenge from the 401, not from a fresh probe"
    );
}

/// A `401` that survives a freshly minted token drops every scoped token under
/// the host, not just the one that was rejected — containerd's
/// `invalidAuthorization`, which deletes the whole handler. A registry that
/// revokes one credential has usually revoked them all, and a sibling
/// repository still holding a token minted from it would go on sending it until
/// expiry.
///
/// The *terminal* `401` is the trigger, not the first one. A plain `Bearer`
/// challenge carries no `error` parameter, so the first rejection cannot
/// separate a refused scope from a revoked credential; a rejection that
/// outlives a token minted seconds ago can. Until then the purge stays narrow —
/// see `a_recovered_401_leaves_the_other_scopes_alone`.
#[tokio::test]
async fn a_terminal_401_purges_every_scoped_token_for_the_host() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let sibling = registry.reference("test/sibling");
    let rejected = registry.reference("test/rejected");

    client
        .list_tags(&sibling, &basic(), None, None)
        .await
        .unwrap();
    client
        .list_tags(&rejected, &basic(), None, None)
        .await
        .unwrap();
    assert_eq!(registry.state.exchanges(), 2, "one exchange per repository");

    // The retry is rejected too, which is what makes the credential — and so
    // every token minted from it — suspect.
    registry.state.reject("test/rejected", 10);
    client
        .list_tags(&rejected, &basic(), None, None)
        .await
        .expect_err("a repository that rejects the retry as well must fail");
    assert_eq!(
        registry.state.exchanges(),
        3,
        "the rejected repository re-authenticates for its one retry"
    );

    client
        .list_tags(&sibling, &basic(), None, None)
        .await
        .unwrap();
    assert_eq!(
        registry.state.exchanges(),
        4,
        "the sibling's token was minted from the same credential and must be dropped too"
    );
    assert_eq!(
        registry.state.probes(),
        1,
        "the seeded challenge covers the whole host — no second probe"
    );
}

/// A `401` the retry recovers from leaves every *other* scope's token alone.
///
/// The rejection is scoped: it is evidence about the repository it names and
/// about nothing else under the host. Purging the host on it costs one fresh
/// token exchange per sibling — a single forbidden repository inside a wide
/// index fan-out re-mints every authorised one, O(N) exchanges for one `403`
/// wearing a `401`'s clothes.
#[tokio::test]
async fn a_recovered_401_leaves_the_other_scopes_alone() {
    let registry = StubRegistry::start().await;
    let client = registry.client();
    let sibling = registry.reference("test/sibling");
    let rejected = registry.reference("test/rejected");

    client
        .list_tags(&sibling, &basic(), None, None)
        .await
        .unwrap();
    client
        .list_tags(&rejected, &basic(), None, None)
        .await
        .unwrap();
    assert_eq!(registry.state.exchanges(), 2, "one exchange per repository");

    // One rejection only: the retry succeeds, so nothing casts doubt on the
    // credential itself.
    registry.state.reject("test/rejected", 1);
    client
        .list_tags(&rejected, &basic(), None, None)
        .await
        .expect("a 401 followed by a 200 must succeed");
    assert_eq!(
        registry.state.exchanges(),
        3,
        "the rejected scope re-mints its own token for the retry"
    );

    client
        .list_tags(&sibling, &basic(), None, None)
        .await
        .unwrap();
    assert_eq!(
        registry.state.exchanges(),
        3,
        "the sibling was never rejected — its token must survive the retry"
    );
}

/// The token cache never answers with a caller's own credentials.
///
/// `_auth` builds its HTTP Basic fallback from the `authentication` argument it
/// was handed, and the cache key carries no credential identity — so a cached
/// Basic entry is served to whoever asks next whatever secret *they* passed,
/// and it wins over the client's own credential store. A pre-warmed entry
/// standing in for the previous caller is the shape of that bleed.
#[tokio::test]
async fn a_cached_credential_never_outranks_the_callers_own() {
    let registry = StubRegistry::start().await;
    registry.state.basic_challenge.store(true, Ordering::SeqCst);
    let client = registry.client();
    let image = registry.reference("test/pkg");

    client
        .tokens
        .insert(
            &image,
            RegistryOperation::Pull,
            RegistryTokenType::Basic("cached-user".to_string(), "cached-pass".to_string()),
        )
        .await;

    let credentials = RegistryAuth::Basic("real-user".to_string(), "real-pass".to_string());
    client
        .list_tags(&image, &credentials, None, None)
        .await
        .unwrap();

    let sent = registry.state.authorizations();
    assert_eq!(
        sent.last().cloned().unwrap_or_default(),
        format!("Basic {}", base64_basic("real-user", "real-pass")),
        "the caller's own credentials must reach the wire, saw {sent:?}"
    );
}

/// C-029 on the live path: a short-lived token is never handed to a *later*
/// caller, so the second call mints again rather than sending one the registry
/// is about to refuse.
///
/// The unit tests pin the predicate; this pins that it is wired into the path
/// `auth()` actually takes. What it cannot pin is the token handed back to the
/// caller that minted it, or to a coalesced waiter — nothing better exists to
/// hand them, and a request that outlives it is what C-020's retry is for.
#[tokio::test]
async fn a_short_lived_token_is_never_served_to_a_later_caller() {
    let registry = StubRegistry::start().await;
    let client = registry.client_with_token_lifetime(10);
    let image = registry.reference("test/pkg");

    for _ in 0..2 {
        client
            .auth(&image, &basic(), RegistryOperation::Pull)
            .await
            .unwrap();
    }

    assert_eq!(
        registry.state.exchanges(),
        2,
        "a token with 10 s of life must not be cached across the 30 s renewal margin"
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

/// `base64(user:password)`, the one line of RFC 7617 this file needs. A
/// dependency for a 64-entry table lookup would cost more than it saves.
fn base64_basic(user: &str, password: &str) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let input = format!("{user}:{password}").into_bytes();
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let bits = chunk.iter().enumerate().fold(0u32, |acc, (index, byte)| {
            acc | (u32::from(*byte) << (16 - 8 * index))
        });
        for slot in 0..4 {
            if slot <= chunk.len() {
                out.push(ALPHABET[((bits >> (18 - 6 * slot)) & 0x3f) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}
