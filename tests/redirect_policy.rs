//! The general client's redirect policy: how far it follows, how it stops, and
//! what the stopping says.
//!
//! `no_scheme_downgrade_policy` replaces reqwest's default wholesale, so the
//! properties the default provided have to be re-established here rather than
//! assumed: an over-long chain must still *fail*, the limit must still be ten,
//! and the URL reqwest attaches to the resulting error must not carry the
//! registry's credentials into a log.

use std::net::SocketAddr;

use axum::{
    extract::{Path, State},
    http::{header::LOCATION, StatusCode},
    response::IntoResponse,
    routing::get,
    Router,
};
use oci_client::{
    client::{ClientConfig, ClientProtocol},
    errors::OciDistributionError,
    secrets::RegistryAuth,
    Client, Reference,
};
use tokio::{net::TcpListener, task::JoinHandle};

/// A presigned-storage handoff, in the shape GHCR/ECR and every S3-backed
/// registry use. Both halves are credentials; neither may reach a log.
const USERINFO: &str = "user:hunter2";
const SIGNATURE: &str = "deadbeef";

struct Server {
    handle: JoinHandle<()>,
    authority: String,
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

/// A registry whose tag listing is `hops` redirects away, every hop carrying a
/// presigned query and userinfo so the last one is what reqwest attaches to a
/// refusal.
async fn registry_with_redirect_chain(hops: usize) -> Server {
    Server::spawn(move |authority| {
        let hop_url = move |n: usize| {
            format!("http://{USERINFO}@{authority}/hop/{n}?X-Amz-Signature={SIGNATURE}")
        };
        let first = hop_url(1);
        let next = move |Path(n): Path<usize>| {
            let target = hop_url(n + 1);
            async move {
                if n >= hops {
                    return (
                        StatusCode::OK,
                        [("Content-Type", "application/json")],
                        r#"{"name":"testrepo","tags":["latest"]}"#,
                    )
                        .into_response();
                }
                (StatusCode::FOUND, [(LOCATION, target)]).into_response()
            }
        };
        Router::new()
            .route("/hop/{n}", get(next))
            .route(
                "/v2/testrepo/tags/list",
                get(|State(first): State<String>| async move {
                    (StatusCode::FOUND, [(LOCATION, first)]).into_response()
                }),
            )
            .with_state(first)
    })
    .await
}

fn client() -> Client {
    Client::new(ClientConfig {
        protocol: ClientProtocol::Http,
        ..Default::default()
    })
}

async fn list_tags_through(hops: usize) -> Result<(), OciDistributionError> {
    let registry = registry_with_redirect_chain(hops).await;
    let reference = Reference::try_from(format!("{}/testrepo:latest", registry.authority)).unwrap();
    client()
        .list_tags(&reference, &RegistryAuth::Anonymous, None, None)
        .await
        .map(|_| ())
}

/// Ten hops is the documented limit and must still be reachable.
///
/// The green half of the test below. Without it, a policy that refused every
/// redirect — or one off by one — would pass that test and break every registry
/// that hands blobs to a CDN.
#[tokio::test]
async fn the_limit_admits_ten_hops() {
    list_tags_through(10)
        .await
        .expect("ten redirects is within the documented limit");
}

/// Eleven must not be, and must be an **error** rather than the 3xx handed back
/// as a successful response.
///
/// `attempt.stop()` returns the 30x as `Ok` (reqwest 0.13.4
/// `src/redirect.rs:189-196`), and `error_for_status_ref` only errors on
/// 4xx/5xx — so a blob behind an over-long chain would answer "exists" to a
/// HEAD and the push would skip a layer it never uploaded. reqwest's own limit
/// arm errors; replacing the default policy must not quietly relax that.
#[tokio::test]
async fn the_eleventh_hop_is_an_error_not_a_3xx_handed_back_as_success() {
    let error = list_tags_through(11)
        .await
        .expect_err("eleven redirects must be refused");

    match &error {
        OciDistributionError::RequestError(err) => assert!(
            err.is_redirect(),
            "the limit must keep reqwest's redirect-error shape, got {err:?}"
        ),
        other => panic!("the 3xx was handed back as a response rather than refused: {other:?}"),
    }
}

/// Redacting only the message this crate writes is not enough: reqwest wraps
/// the policy's error with the *previous* URL (`src/redirect.rs:334`) and prints
/// it verbatim in both `Display` (`src/error.rs:279-281`) and `Debug`
/// (`:225-227`). On a real refusal that URL is the presigned CDN handoff — the
/// one URL in the exchange that actually carries a credential.
#[tokio::test]
async fn the_url_reqwest_attaches_to_a_refusal_is_redacted() {
    let error = list_tags_through(11)
        .await
        .expect_err("eleven redirects must be refused");

    // Both renderings: `{err:#}` walks Display, and a bug report pastes `{:?}`.
    for (label, rendered) in [
        ("Display", format!("{error}")),
        ("Debug", format!("{error:?}")),
    ] {
        for secret in ["hunter2", SIGNATURE] {
            assert!(
                !rendered.contains(secret),
                "{label} published {secret}: {rendered}"
            );
        }
        // Diagnosis survives: the host and the parameter name stay.
        for kept in ["127.0.0.1", "X-Amz-Signature"] {
            assert!(
                rendered.contains(kept),
                "{label} dropped {kept}, leaving nothing to diagnose: {rendered}"
            );
        }
    }
}
