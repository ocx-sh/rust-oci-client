//! A manifest response is bytes plus a claim about what those bytes are. A
//! captive portal, a proxy error page and a mis-routed mirror all answer 200
//! with HTML, and until the content type is read that HTML reaches digest
//! verification — where it fails as "corrupted content" and names nothing that
//! would let anyone find the real cause. These tests hold the gate that refuses
//! it first, and the two shapes the gate must keep admitting.
use std::net::SocketAddr;

use axum::extract::Path;
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use oci_client::client::{ClientConfig, ClientProtocol};
use oci_client::errors::OciDistributionError;
use oci_client::secrets::RegistryAuth;
use oci_client::{Client, Reference};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

const SUBJECT: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

const MANIFEST: &str = r#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json","config":{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":2},"layers":[]}"#;

/// What a captive portal, an SSO gateway or a dead tenant answers with.
const PORTAL: &str = "<!DOCTYPE html><html><head><title>Sign in</title></head><body>Sign in to continue</body></html>";

async fn html_portal() -> Response {
    ([("content-type", "text/html; charset=utf-8")], PORTAL).into_response()
}

/// Registries legitimately omit the header; the digest check still covers the
/// bytes, so the gate must let this through.
async fn untyped_manifest() -> Response {
    Response::builder().body(MANIFEST.into()).unwrap()
}

/// `application/json` without the OCI suffix — a plain but honest answer.
async fn plain_json_manifest() -> Response {
    ([("content-type", "application/json")], MANIFEST).into_response()
}

struct MisroutedRegistry {
    handle: JoinHandle<()>,
    server: String,
}

impl Drop for MisroutedRegistry {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

impl MisroutedRegistry {
    async fn new() -> Self {
        let app = Router::new()
            .route("/v2/html/manifests/{reference}", get(html_portal))
            .route("/v2/untyped/manifests/{reference}", get(untyped_manifest))
            .route(
                "/v2/plainjson/manifests/{reference}",
                get(plain_json_manifest),
            )
            // HEAD is answered from the same handler with the body dropped, so
            // it carries no digest header and the client falls through to GET.
            .route("/v2/probe/manifests/{reference}", get(html_portal));

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
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

    /// Digest-pinned, so an unguarded client reaches digest verification.
    fn pinned(&self, repository: &str) -> Reference {
        format!("{}/{repository}@{SUBJECT}", self.server)
            .parse()
            .unwrap()
    }

    /// Tag-addressed, so nothing but the content-type gate can refuse it.
    fn tagged(&self, repository: &str) -> Reference {
        format!("{}/{repository}:1.0.0", self.server)
            .parse()
            .unwrap()
    }
}

/// A host that answers every manifest request by bouncing the client onto
/// `target` — a mirror pointed at a tenant that no longer serves the registry.
struct Bouncer {
    handle: JoinHandle<()>,
    server: String,
}

impl Drop for Bouncer {
    fn drop(&mut self) {
        self.handle.abort()
    }
}

impl Bouncer {
    async fn new(target: String) -> Self {
        let app =
            Router::new().route(
                "/v2/{repository}/manifests/{reference}",
                get(move |Path((_, reference)): Path<(String, String)>| {
                    let target = target.clone();
                    async move {
                        Redirect::temporary(&format!("{target}/v2/html/manifests/{reference}"))
                    }
                }),
            );

        let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .unwrap();
        let server = format!("127.0.0.1:{}", listener.local_addr().unwrap().port());
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { handle, server }
    }

    fn reference(&self, repository: &str) -> Reference {
        format!("{}/{repository}@{SUBJECT}", self.server)
            .parse()
            .unwrap()
    }
}

#[tokio::test]
async fn an_html_manifest_response_is_refused_before_the_digest_check() {
    let registry = MisroutedRegistry::new().await;
    let error = registry
        .client()
        .pull_manifest_raw(
            &registry.pinned("html"),
            &RegistryAuth::Anonymous,
            &["application/vnd.oci.image.manifest.v1+json"],
        )
        .await
        .expect_err("an HTML body must not reach digest verification");
    assert!(
        matches!(error, OciDistributionError::UnexpectedContentType { .. }),
        "expected a content-type refusal, got: {error}"
    );
}

#[tokio::test]
async fn a_manifest_digest_probe_refuses_html_on_the_get_fallback() {
    let registry = MisroutedRegistry::new().await;
    let error = registry
        .client()
        .fetch_manifest_digest(&registry.tagged("probe"), &RegistryAuth::Anonymous)
        .await
        .expect_err("a digest probe must not hash an HTML page");
    assert!(
        matches!(error, OciDistributionError::UnexpectedContentType { .. }),
        "expected a content-type refusal, got: {error}"
    );
}

#[tokio::test]
async fn a_manifest_response_with_no_content_type_is_admitted() {
    let registry = MisroutedRegistry::new().await;
    let (body, _) = registry
        .client()
        .pull_manifest_raw(
            &registry.tagged("untyped"),
            &RegistryAuth::Anonymous,
            &["application/vnd.oci.image.manifest.v1+json"],
        )
        .await
        .expect("a manifest with no content type must still be accepted");
    assert_eq!(body, MANIFEST.as_bytes());
}

#[tokio::test]
async fn a_manifest_response_typed_application_json_is_admitted() {
    let registry = MisroutedRegistry::new().await;
    let (body, _) = registry
        .client()
        .pull_manifest_raw(
            &registry.tagged("plainjson"),
            &RegistryAuth::Anonymous,
            &["application/vnd.oci.image.manifest.v1+json"],
        )
        .await
        .expect("a manifest typed application/json must be accepted");
    assert_eq!(body, MANIFEST.as_bytes());
}

#[tokio::test]
async fn a_redirected_manifest_error_names_the_final_url() {
    let portal = MisroutedRegistry::new().await;
    let bouncer = Bouncer::new(format!("http://{}", portal.server)).await;

    let error = portal
        .client()
        .pull_manifest_raw(
            &bouncer.reference("anything"),
            &RegistryAuth::Anonymous,
            &["application/vnd.oci.image.manifest.v1+json"],
        )
        .await
        .expect_err("a redirect onto an HTML portal must be refused");

    let OciDistributionError::UnexpectedContentType { url, .. } = &error else {
        panic!("expected a content-type refusal, got: {error}");
    };
    assert!(
        url.contains(&portal.server),
        "the error must name where the response came from ({}), got: {url}",
        portal.server
    );
    assert!(
        !url.contains(&bouncer.server),
        "the error must not name the address the request was sent to, got: {url}"
    );
}
