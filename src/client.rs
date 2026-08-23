//! OCI distribution client for fetching oci images from an OCI compliant remote store
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;
use std::hash::Hash;
use std::pin::{pin, Pin};
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use futures_util::stream::{self, BoxStream, StreamExt, TryStreamExt};
use futures_util::{future, Stream};
use http::header::RANGE;
use http::{HeaderValue, StatusCode};
use http_auth::{parser::ChallengeParser, ChallengeRef};
use oci_spec::image::{Arch, Os};
use olpc_cjson::CanonicalFormatter;
use reqwest::header::HeaderMap;
use reqwest::{NoProxy, Proxy, RequestBuilder, Response, Url};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::RwLock;
use tokio_util::io::{ReaderStream, StreamReader};
use tracing::{debug, trace, warn};

use crate::auth_cache::{ChallengeCache, ChallengeInfo, TokenFlights};
pub use crate::blob::*;
use crate::config::ConfigFile;
use crate::digest::{digest_header_value, validate_digest, Digest, Digester};
use crate::errors::*;
use crate::manifest::{
    ImageIndexEntry, OciDescriptor, OciImageIndex, OciImageManifest, OciManifest, Versioned,
    IMAGE_CONFIG_MEDIA_TYPE, IMAGE_LAYER_GZIP_MEDIA_TYPE, IMAGE_LAYER_MEDIA_TYPE,
    IMAGE_MANIFEST_LIST_MEDIA_TYPE, IMAGE_MANIFEST_MEDIA_TYPE, OCI_IMAGE_INDEX_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
};
use crate::secrets::RegistryAuth;
use crate::secrets::*;
use crate::sha256_digest;
use crate::token_cache::{
    RegistryOperation, RegistryToken, RegistryTokenType, TokenCache, TokenCacheKey,
};
use crate::Reference;

const MIME_TYPES_DISTRIBUTION_MANIFEST: &[&str] = &[
    IMAGE_MANIFEST_MEDIA_TYPE,
    IMAGE_MANIFEST_LIST_MEDIA_TYPE,
    OCI_IMAGE_MEDIA_TYPE,
    OCI_IMAGE_INDEX_MEDIA_TYPE,
];

/// Default value for `ClientConfig::push_chunk_size`.
pub const DEFAULT_PUSH_CHUNK_SIZE: usize = 4096 * 1024;

/// Default value for `ClientConfig::max_concurrent_upload`
pub const DEFAULT_MAX_CONCURRENT_UPLOAD: usize = 16;

/// Default value for `ClientConfig::max_concurrent_download`
pub const DEFAULT_MAX_CONCURRENT_DOWNLOAD: usize = 16;

/// Default value for `ClientConfig:default_token_expiration_secs`
pub const DEFAULT_TOKEN_EXPIRATION_SECS: usize = 60;

static DEFAULT_USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// The data for an image or module.
#[derive(Clone)]
pub struct ImageData {
    /// The layers of the image or module.
    pub layers: Vec<ImageLayer>,
    /// The digest of the image or module.
    pub digest: Option<String>,
    /// The Configuration object of the image or module.
    pub config: Config,
    /// The manifest of the image or module.
    pub manifest: Option<OciImageManifest>,
}

/// The data returned by an OCI registry after a successful push
/// operation is completed
pub struct PushResponse {
    /// Pullable url for the config
    pub config_url: String,
    /// Pullable url for the manifest
    pub manifest_url: String,
}

/// The data returned by a successful tags/list Request
#[derive(Deserialize, Debug)]
pub struct TagResponse {
    /// Repository Name
    pub name: String,
    /// List of existing Tags
    #[serde(deserialize_with = "null_as_default")]
    pub tags: Vec<String>,
}

/// Helper to deserialize an empty value from a JSON `null`.
fn null_as_default<'de, D, T>(d: D) -> std::result::Result<T, D::Error>
where
    D: Deserializer<'de>,
    T: Default + Deserialize<'de>,
{
    let res = <Option<T>>::deserialize(d)?.unwrap_or_default();
    Ok(res)
}

/// The data returned by a successful catalog request.
#[derive(Deserialize, Debug)]
pub struct CatalogResponse {
    /// List of available repositories in the registry.
    pub repositories: Vec<String>,
}

/// Layer descriptor required to pull a layer
pub struct LayerDescriptor<'a> {
    /// The digest of the layer
    pub digest: &'a str,
    /// Optional list of additional URIs to pull the layer from
    pub urls: &'a Option<Vec<String>>,
}

/// A trait for converting any type into a [`LayerDescriptor`]
pub trait AsLayerDescriptor {
    /// Convert the type to a LayerDescriptor reference
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_>;
}

impl<T: AsLayerDescriptor> AsLayerDescriptor for &T {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        (*self).as_layer_descriptor()
    }
}

impl AsLayerDescriptor for &str {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: self,
            urls: &None,
        }
    }
}

impl AsLayerDescriptor for &OciDescriptor {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: &self.digest,
            urls: &self.urls,
        }
    }
}

impl AsLayerDescriptor for &LayerDescriptor<'_> {
    fn as_layer_descriptor(&self) -> LayerDescriptor<'_> {
        LayerDescriptor {
            digest: self.digest,
            urls: self.urls,
        }
    }
}

/// The data and media type for an image layer
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct ImageLayer {
    /// The data of this layer
    pub data: bytes::Bytes,
    /// The media type of this layer
    pub media_type: String,
    /// This OPTIONAL property contains arbitrary metadata for this descriptor.
    /// This OPTIONAL property MUST use the [annotation rules](https://github.com/opencontainers/image-spec/blob/main/annotations.md#rules)
    pub annotations: Option<BTreeMap<String, String>>,
}

impl ImageLayer {
    /// Constructs a new ImageLayer struct with provided data and media type
    pub fn new(
        data: impl Into<bytes::Bytes>,
        media_type: String,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        ImageLayer {
            data: data.into(),
            media_type,
            annotations,
        }
    }

    /// Constructs a new ImageLayer struct with provided data and
    /// media type application/vnd.oci.image.layer.v1.tar
    pub fn oci_v1(
        data: impl Into<bytes::Bytes>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::new(data, IMAGE_LAYER_MEDIA_TYPE.to_string(), annotations)
    }
    /// Constructs a new ImageLayer struct with provided data and
    /// media type application/vnd.oci.image.layer.v1.tar+gzip
    pub fn oci_v1_gzip(
        data: impl Into<bytes::Bytes>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::new(data, IMAGE_LAYER_GZIP_MEDIA_TYPE.to_string(), annotations)
    }

    /// Helper function to compute the sha256 digest of an image layer
    pub fn sha256_digest(&self) -> String {
        sha256_digest(&self.data)
    }
}

/// The data and media type for a configuration object
#[derive(Clone)]
pub struct Config {
    /// The data of this config object
    pub data: bytes::Bytes,
    /// The media type of this object
    pub media_type: String,
    /// This OPTIONAL property contains arbitrary metadata for this descriptor.
    /// This OPTIONAL property MUST use the [annotation rules](https://github.com/opencontainers/image-spec/blob/main/annotations.md#rules)
    pub annotations: Option<BTreeMap<String, String>>,
}

impl Config {
    /// Constructs a new Config struct with provided data and media type
    pub fn new(
        data: impl Into<bytes::Bytes>,
        media_type: String,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Config {
            data: data.into(),
            media_type,
            annotations,
        }
    }

    /// Constructs a new Config struct with provided data and
    /// media type application/vnd.oci.image.config.v1+json
    pub fn oci_v1(
        data: impl Into<bytes::Bytes>,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Self {
        Self::new(data, IMAGE_CONFIG_MEDIA_TYPE.to_string(), annotations)
    }

    /// Construct a new Config struct with provided [`ConfigFile`] and
    /// media type `application/vnd.oci.image.config.v1+json`
    pub fn oci_v1_from_config_file(
        config_file: ConfigFile,
        annotations: Option<BTreeMap<String, String>>,
    ) -> Result<Self> {
        let data = serde_json::to_vec(&config_file)?;
        Ok(Self::new(
            data,
            IMAGE_CONFIG_MEDIA_TYPE.to_string(),
            annotations,
        ))
    }

    /// Helper function to compute the sha256 digest of this config object
    pub fn sha256_digest(&self) -> String {
        sha256_digest(&self.data)
    }
}

impl TryFrom<Config> for ConfigFile {
    type Error = crate::errors::OciDistributionError;

    fn try_from(config: Config) -> Result<Self> {
        let config = String::from_utf8(config.data.into())
            .map_err(|e| OciDistributionError::ConfigConversionError(e.to_string()))?;
        let config_file: ConfigFile = serde_json::from_str(&config)
            .map_err(|e| OciDistributionError::ConfigConversionError(e.to_string()))?;
        Ok(config_file)
    }
}

/// The OCI client connects to an OCI registry and fetches OCI images.
///
/// An OCI registry is a container registry that adheres to the OCI Distribution
/// specification. DockerHub is one example, as are ACR and GCR. This client
/// provides a native Rust implementation for pulling OCI images.
///
/// Some OCI registries support completely anonymous access. But most require
/// at least an Oauth2 handshake. Typically, you will want to create a new
/// client, and then run the `auth()` method, which will attempt to get
/// a read-only bearer token. From there, pulling images can be done with
/// the `pull_*` functions.
///
/// For true anonymous access, you can skip `auth()`. This is not recommended
/// unless you are sure that the remote registry does not require Oauth2.
#[derive(Clone)]
pub struct Client {
    config: Arc<ClientConfig>,
    // Registry -> RegistryAuth
    auth_store: Arc<RwLock<HashMap<String, RegistryAuth>>>,
    /// Token cache for the client
    pub tokens: TokenCache,
    // Host -> the `WWW-Authenticate` challenge `GET /v2/` answered with. Probed
    // once per host rather than once per repository, and dropped wholesale when
    // a `401` says what is cached for that host is stale.
    challenges: Arc<ChallengeCache>,
    // Token exchanges currently running, so N cold callers for one scope share
    // one handshake instead of each running their own.
    token_flights: Arc<TokenFlights>,
    client: reqwest::Client,
    // The same configuration as `client`, minus redirect following. Requests
    // addressed to a registry-supplied upload-session URL go through this one:
    // see `RequestBuilderWrapper::from_client_no_redirect`.
    no_redirect_client: reqwest::Client,
    push_chunk_size: usize,
}

impl Default for Client {
    fn default() -> Self {
        Self {
            config: Arc::default(),
            auth_store: Arc::default(),
            tokens: TokenCache::new(DEFAULT_TOKEN_EXPIRATION_SECS),
            challenges: Arc::default(),
            token_flights: Arc::default(),
            client: default_seeded_client(no_scheme_downgrade_policy),
            no_redirect_client: default_seeded_client(reqwest::redirect::Policy::none),
            push_chunk_size: DEFAULT_PUSH_CHUNK_SIZE,
        }
    }
}

/// A source that can provide a `ClientConfig`.
/// If you are using this crate in your own application, you can implement this
/// trait on your configuration type so that it can be passed to `Client::from_source`.
pub trait ClientConfigSource {
    /// Provides a `ClientConfig`.
    fn client_config(&self) -> ClientConfig;
}

/// reqwest's default redirect limit, restated because a custom policy replaces
/// the default wholesale rather than wrapping it.
///
/// Compared with `>`, not `>=`, for the same reason reqwest's own limit arm
/// does (`reqwest-0.13.4/src/redirect.rs:132-136`): `previous` is pushed before
/// the policy is consulted (`:315`) and its first entry is the original
/// request, not a redirection. `>=` would have allowed nine hops while claiming
/// ten.
const MAX_REDIRECTS: usize = 10;

/// Follows redirects like reqwest's default, except never from `https` to
/// `http`.
///
/// reqwest already strips `Authorization` on a scheme-only change — its
/// `cross_host` predicate compares scheme alongside host and port
/// (`reqwest-0.13.4/src/redirect.rs:241-243`) — so the credential leak is not
/// what this policy adds. It adds the other half: stripping a header is a
/// *header* mitigation and the request still goes, so the URL, the request
/// body, and the manifest or blob bytes travel to the plaintext target in the
/// clear (CWE-319 on the request itself, not only CWE-522 on the header).
/// Refusing the hop means nothing reaches that target at all.
///
/// The `redirect.rs` claim is version-dependent: reqwest 0.12's predicate has
/// only the host and port terms, and a future version could drop the scheme
/// term again. Re-check it on a reqwest bump rather than trusting this comment
/// — if it ever regresses, the credential leak returns and this policy becomes
/// the only thing closing it.
///
/// Redirects are load-bearing on the pull path — registries hand blobs off to
/// CDNs that way — so refusing all of them (`Policy::none`) is not an option
/// here, and `https_only` would break registries deliberately configured as
/// plain HTTP. The upload path is the exception and does use `Policy::none`:
/// see [`RequestBuilderWrapper::from_client_no_redirect`].
fn no_scheme_downgrade_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if is_scheme_downgrade(attempt.previous().last(), attempt.url()) {
            let refusal = scheme_downgrade_refusal(attempt.url());
            return attempt.error(OciDistributionError::GenericError(Some(refusal)));
        }
        // `attempt.error`, never `attempt.stop`: stop hands the 3xx back as an
        // `Ok` response (`redirect.rs:189-196`), which `error_for_status_ref`
        // treats as success — so a blob behind an over-long chain would answer
        // "exists" to a HEAD and the layer would never be uploaded. reqwest's
        // own limit arm errors, and replacing the default policy must not
        // quietly relax that.
        if attempt.previous().len() > MAX_REDIRECTS {
            return attempt.error(OciDistributionError::GenericError(Some(format!(
                "too many redirects (limit {MAX_REDIRECTS})"
            ))));
        }
        attempt.follow()
    })
}

/// Whether following `next` would move a request from TLS to the clear.
///
/// The decision `no_scheme_downgrade_policy` is built on, factored out because
/// `reqwest::redirect::Attempt` cannot be constructed outside reqwest, so the
/// closure itself has no test seam.
fn is_scheme_downgrade(previous: Option<&Url>, next: &Url) -> bool {
    previous.is_some_and(|previous| previous.scheme() == "https" && next.scheme() == "http")
}

/// What a refused downgrade says, factored out for the same reason
/// [`is_scheme_downgrade`] is: the closure has no test seam.
///
/// The target is registry-chosen — a downgrade to a collector carries whatever
/// query that collector wants echoed — so it is redacted before it reaches a
/// message the user pastes into a bug report.
fn scheme_downgrade_refusal(target: &Url) -> String {
    format!(
        "refusing a redirect from HTTPS to plaintext {}",
        redacted_display_url(target)
    )
}

/// Everything a `ClientConfig` implies about the underlying HTTP client except
/// its redirect policy.
///
/// Factored out because a `Client` holds two `reqwest::Client`s that differ on
/// exactly that one axis, and a `reqwest::ClientBuilder` cannot be cloned. Any
/// setting added here reaches both automatically; a setting applied to one
/// builder only would silently make the upload path less configured than the
/// rest of the client.
fn configured_builder(config: &ClientConfig) -> Result<reqwest::ClientBuilder> {
    #[allow(unused_mut)]
    let mut client_builder = reqwest::Client::builder();
    #[cfg(not(target_arch = "wasm32"))]
    let mut client_builder =
        client_builder.danger_accept_invalid_certs(config.accept_invalid_certificates);

    client_builder = match () {
        #[cfg(all(feature = "native-tls", not(target_arch = "wasm32")))]
        () => client_builder.danger_accept_invalid_hostnames(config.accept_invalid_hostnames),
        #[cfg(any(not(feature = "native-tls"), target_arch = "wasm32"))]
        () => client_builder,
    };

    #[cfg(not(target_arch = "wasm32"))]
    {
        if !config.tls_certs_only.is_empty() {
            client_builder =
                client_builder.tls_certs_only(convert_certificates(&config.tls_certs_only)?);
        }
        client_builder =
            client_builder.tls_certs_merge(convert_certificates(&config.extra_root_certificates)?);
    }

    if let Some(timeout) = config.read_timeout {
        client_builder = client_builder.read_timeout(timeout);
    }
    if let Some(timeout) = config.connect_timeout {
        client_builder = client_builder.connect_timeout(timeout);
    }

    client_builder = client_builder.user_agent(config.user_agent);

    if let Some(proxy_addr) = &config.https_proxy {
        let no_proxy = config
            .no_proxy
            .as_ref()
            .and_then(|no_proxy| NoProxy::from_string(no_proxy));
        let proxy = Proxy::https(proxy_addr)?.no_proxy(no_proxy);
        client_builder = client_builder.proxy(proxy);
    }

    if let Some(proxy_addr) = &config.http_proxy {
        let no_proxy = config
            .no_proxy
            .as_ref()
            .and_then(|no_proxy| NoProxy::from_string(no_proxy));
        let proxy = Proxy::http(proxy_addr)?.no_proxy(no_proxy);
        client_builder = client_builder.proxy(proxy);
    }

    if let Some(resolver) = &config.dns_resolver {
        client_builder = client_builder.dns_resolver(resolver.clone());
    }

    Ok(client_builder)
}

impl TryFrom<ClientConfig> for Client {
    type Error = OciDistributionError;

    fn try_from(config: ClientConfig) -> std::result::Result<Self, Self::Error> {
        let client = configured_builder(&config)?
            .redirect(no_scheme_downgrade_policy())
            .build()?;
        // Redirects off entirely, not merely origin-checked: this client only
        // ever addresses a URL the registry chose, and a 3xx there is a second
        // registry-chosen target that would replay the blob body to whatever
        // host it names. Surfacing the 3xx as a status is the refusal.
        let no_redirect_client = configured_builder(&config)?
            .redirect(reqwest::redirect::Policy::none())
            .build()?;

        let default_token_expiration_secs = config.default_token_expiration_secs;
        let push_chunk_size = config.push_chunk_size;
        Ok(Self {
            config: Arc::new(config),
            tokens: TokenCache::new(default_token_expiration_secs),
            challenges: Arc::default(),
            token_flights: Arc::default(),
            client,
            no_redirect_client,
            push_chunk_size,
            // Explicit `auth_store` rather than `..Default::default()`: the
            // struct-update tail would eagerly build a throwaway `Client::default()`
            // — its `reqwest::Client::default()` panics on a host with no system
            // trust store, defeating the seeded `client_builder` above. Fill the
            // one remaining field directly and never construct that throwaway.
            auth_store: Arc::default(),
        })
    }
}

/// Outcome of [`Client::mount_blob`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BlobMountResponse {
    /// 201 - blob mounted into the target repository.
    Mounted,
    /// 202 - registry declined the mount and opened a regular upload session
    /// at the returned location (spec-conforming miss); caller must upload.
    UploadSessionOpened(String),
}

impl Client {
    /// Create a new client with the supplied config
    pub fn new(config: ClientConfig) -> Self {
        let default_token_expiration_secs = config.default_token_expiration_secs;
        let push_chunk_size = config.push_chunk_size;
        Client::try_from(config).unwrap_or_else(|err| {
            warn!("Cannot create OCI client from config: {:?}", err);
            warn!("Creating client with default configuration");
            Self {
                tokens: TokenCache::new(default_token_expiration_secs),
                push_chunk_size,
                ..Default::default()
            }
        })
    }

    /// Create a new client with the supplied config
    pub fn from_source(config_source: &impl ClientConfigSource) -> Self {
        Self::new(config_source.client_config())
    }

    async fn store_auth(&self, registry: &str, auth: RegistryAuth) {
        self.auth_store
            .write()
            .await
            .insert(registry.to_string(), auth);
    }

    async fn is_stored_auth(&self, registry: &str) -> bool {
        self.auth_store.read().await.contains_key(registry)
    }

    /// Store the authentication information for this registry if it's not already stored in the client.
    ///
    /// Most of the time, you don't need to call this method directly. It's called by other
    /// methods (where you have to provide the authentication information as parameter).
    ///
    /// But if you want to pull/push a blob without calling any of the other methods first, which would
    /// store the authentication information, you can call this method to store the authentication
    /// information manually.
    pub async fn store_auth_if_needed(&self, registry: &str, auth: &RegistryAuth) {
        if !self.is_stored_auth(registry).await {
            self.store_auth(registry, auth.clone()).await;
        }
    }

    /// Checks if we got a token, if we don't - create it and store it in cache.
    async fn get_auth_token(
        &self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let registry = reference.resolve_registry();
        let auth = self.auth_store.read().await.get(registry)?.clone();
        match self.tokens.get(reference, op).await {
            Some(token) => Some(token),
            None => self.acquire_token(reference, &auth, op).await.ok()?,
        }
    }

    /// Fetches the available Tags for the given Reference
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub async fn list_tags(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<TagResponse> {
        let op = RegistryOperation::Pull;
        let url = self.to_list_tags_url(image);

        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        let request = self.client.get(&url);
        let request = if let Some(num) = n {
            request.query(&[("n", num)])
        } else {
            request
        };
        let request = if let Some(l) = last {
            request.query(&[("last", l)])
        } else {
            request
        };
        let request = RequestBuilderWrapper {
            client: self,
            request_builder: request,
        };
        let res = request.send_authed(image, op).await?;
        let status = res.status();
        let body = res.bytes().await?;

        validate_registry_response(status, &body, &url)?;

        Ok(serde_json::from_str(std::str::from_utf8(&body)?)?)
    }

    /// Pull an image and return the bytes
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    pub async fn pull(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: Vec<&str>,
    ) -> Result<ImageData> {
        debug!("Pulling image: {:?}", image);
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        let (manifest, digest, config) = self._pull_manifest_and_config(image).await?;

        self.validate_layers(&manifest, accepted_media_types)
            .await?;

        let layers = stream::iter(&manifest.layers)
            .map(|layer| {
                // This avoids moving `self` which is &Self
                // into the async block. We only want to capture
                // as &Self
                let this = &self;
                async move {
                    let mut out: Vec<u8> = Vec::new();
                    debug!("Pulling image layer");
                    this.pull_blob(image, layer, &mut out).await?;
                    Ok::<_, OciDistributionError>(ImageLayer::new(
                        out,
                        layer.media_type.clone(),
                        layer.annotations.clone(),
                    ))
                }
            })
            .boxed() // Workaround to rustc issue https://github.com/rust-lang/rust/issues/104382
            .buffer_unordered(self.config.max_concurrent_download)
            .try_collect()
            .await?;

        Ok(ImageData {
            layers,
            manifest: Some(manifest),
            config,
            digest: Some(digest),
        })
    }

    /// Checks if a blob exists in the remote registry
    pub async fn blob_exists(&self, image: &Reference, digest: &str) -> Result<bool> {
        match self.head_blob_response(image, digest).await? {
            Some(_) => Ok(true),
            None => Ok(false),
        }
    }

    /// Fetches the size of a blob in the remote registry without
    /// downloading its body.
    ///
    /// Issues an HTTP HEAD against the blob URL and returns the
    /// `Content-Length` header value. Returns `Ok(None)` when the
    /// registry reports the blob as missing (404). Returns an error
    /// when the registry responds with a success status but omits
    /// `Content-Length` — callers rely on a known size to build a
    /// valid OCI descriptor, and silently falling back to zero would
    /// corrupt the manifest.
    pub async fn fetch_blob_size(&self, image: &Reference, digest: &str) -> Result<Option<u64>> {
        let Some(res) = self.head_blob_response(image, digest).await? else {
            return Ok(None);
        };
        let header = res
            .headers()
            .get(reqwest::header::CONTENT_LENGTH)
            .ok_or_else(|| {
                OciDistributionError::GenericError(Some(
                    "registry HEAD response did not include Content-Length".to_string(),
                ))
            })?;
        let header_str = header.to_str().map_err(|e| {
            OciDistributionError::GenericError(Some(format!("invalid Content-Length header: {e}")))
        })?;
        let content_length = header_str.parse::<u64>().map_err(|e| {
            OciDistributionError::GenericError(Some(format!(
                "non-numeric Content-Length header: {e}"
            )))
        })?;
        Ok(Some(content_length))
    }

    /// Internal helper: issue a HEAD against the blob URL and return
    /// the raw response when the blob exists, `None` on 404, or an
    /// error on any other non-success status.
    async fn head_blob_response(
        &self,
        image: &Reference,
        digest: &str,
    ) -> Result<Option<Response>> {
        let url = self.to_v2_blob_url(image, digest);
        let request = RequestBuilderWrapper {
            client: self,
            request_builder: self.client.head(&url),
        };

        let res = request.send_authed(image, RegistryOperation::Pull).await?;

        match res.error_for_status_ref() {
            Ok(_) => Ok(Some(res)),
            Err(err) => {
                if err.status() == Some(StatusCode::NOT_FOUND) {
                    Ok(None)
                } else {
                    Err(err.into())
                }
            }
        }
    }

    /// Push an image and return the uploaded URL of the image
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// If a manifest is not provided, the client will attempt to generate
    /// it from the provided image and config data.
    ///
    /// Returns pullable URL for the image
    pub async fn push(
        &self,
        image_ref: &Reference,
        layers: &[ImageLayer],
        config: Config,
        auth: &RegistryAuth,
        manifest: Option<OciImageManifest>,
    ) -> Result<PushResponse> {
        debug!("Pushing image: {:?}", image_ref);
        self.store_auth_if_needed(image_ref.resolve_registry(), auth)
            .await;

        let manifest: OciImageManifest = match manifest {
            Some(m) => m,
            None => OciImageManifest::build(layers, &config, None),
        };

        // Upload layers.
        //
        // Reuse the per-layer digests already computed while building (or
        // supplied with) the manifest, rather than hashing every layer a
        // second time here. For large layers this avoids a full redundant
        // SHA-256 pass over the data. When `build` produced the manifest its
        // `layers` are in the same order as `layers`; if a caller supplied a
        // manifest whose layer count does not match, fall back to hashing each
        // layer so behaviour is unchanged.
        let layer_digests: Vec<String> = if manifest.layers.len() == layers.len() {
            manifest.layers.iter().map(|d| d.digest.clone()).collect()
        } else {
            layers.iter().map(|l| l.sha256_digest()).collect()
        };
        stream::iter(layers.iter().zip(layer_digests))
            .map(|(layer, digest)| {
                // This avoids moving `self` which is &Self
                // into the async block. We only want to capture
                // as &Self
                let this = &self;
                async move {
                    this.push_blob(image_ref, layer.data.clone(), &digest)
                        .await?;
                    Result::Ok(())
                }
            })
            .boxed() // Workaround to rustc issue https://github.com/rust-lang/rust/issues/104382
            .buffer_unordered(self.config.max_concurrent_upload)
            .try_for_each(future::ok)
            .await?;

        let config_url = self
            .push_blob(image_ref, config.data, &manifest.config.digest)
            .await?;
        let manifest_url = self.push_manifest(image_ref, &manifest.into()).await?;

        Ok(PushResponse {
            config_url,
            manifest_url,
        })
    }

    /// Pushes a blob to the registry
    pub async fn push_blob(
        &self,
        image_ref: &Reference,
        data: impl Into<bytes::Bytes>,
        digest: &str,
    ) -> Result<String> {
        if self.config.use_monolithic_push {
            return self.push_blob_monolithically(image_ref, data, digest).await;
        }
        let data = data.into();
        // Cloning the bytes here is cheap (e.g. doesn't allocate anything except some space for
        // some pointers). If any cloning happened, it is because the caller's passed data was not
        // already a `Bytes` type or static data.
        match self
            .push_blob_chunked(image_ref, data.clone(), digest)
            .await
        {
            Ok(url) => Ok(url),
            Err(OciDistributionError::SpecViolationError(violation)) => {
                warn!(?violation, "Registry is not respecting the OCI Distribution Specification when doing chunked push operations");
                warn!("Attempting monolithic push");
                self.push_blob_monolithically(image_ref, data, digest).await
            }
            Err(e) => Err(e),
        }
    }

    /// Pushes a blob to the registry as a monolith
    ///
    /// Returns the pullable location of the blob
    async fn push_blob_monolithically(
        &self,
        image: &Reference,
        blob_data: impl Into<bytes::Bytes>,
        blob_digest: &str,
    ) -> Result<String> {
        let location = self.begin_push_monolithical_session(image).await?;
        self.push_monolithically(&location, image, blob_data, blob_digest)
            .await
    }

    /// Pushes a blob to the registry as a series of chunks
    ///
    /// Returns the pullable location of the blob
    async fn push_blob_chunked(
        &self,
        image: &Reference,
        blob_data: impl Into<bytes::Bytes>,
        blob_digest: &str,
    ) -> Result<String> {
        let mut location = self.begin_push_chunked_session(image).await?;
        let mut start: usize = 0;

        let mut blob_data: bytes::Bytes = blob_data.into();
        while !blob_data.is_empty() {
            let chunk_size = self.push_chunk_size.min(blob_data.len());
            let chunk = blob_data.split_to(chunk_size);
            (location, start) = self.push_chunk(&location, image, chunk, start).await?;
        }
        self.end_push_chunked_session(&location, image, blob_digest)
            .await
    }

    /// Pushes a blob to the registry from an input stream.
    ///
    /// If `use_monolithic_push` is set in the client config, a single PUT is used (monolithic
    /// push). In that case `size` must be `Some`, as it is required to set `Content-Length` on the
    /// request. If `size` is `None` and `use_monolithic_push` is true, an error is returned.
    ///
    /// If `use_monolithic_push` is false the blob is sent as a series of chunked PATCH requests
    /// and `size` is ignored.
    ///
    /// Note: unlike [`push_blob`], there is no automatic fallback to monolithic push on a
    /// `SpecViolationError` from the chunked path, because a stream cannot be replayed after
    /// it has been consumed.
    ///
    /// Returns the pullable location of the blob.
    pub async fn push_blob_stream<T: Stream<Item = Result<bytes::Bytes>> + Send + 'static>(
        &self,
        image: &Reference,
        blob_data_stream: T,
        blob_digest: &str,
        size: Option<usize>,
    ) -> Result<String> {
        if self.config.use_monolithic_push {
            let size = size.ok_or_else(|| {
                OciDistributionError::GenericError(Some(
                    "size must be provided when use_monolithic_push is enabled".to_string(),
                ))
            })?;
            let location = self.begin_push_monolithical_session(image).await?;
            return self
                .push_stream_monolithically(&location, image, blob_data_stream, size, blob_digest)
                .await;
        }

        // When the total size is known, stream each PATCH body directly from the
        // input stream (bounded to `push_chunk_size`) rather than buffering the whole
        // chunk in memory. reqwest pulls from each body only as the socket accepts
        // more (backpressure), so a progress wrapper the caller layered onto
        // `blob_data_stream` advances as bytes are pulled for the wire — while every
        // request body stays bounded for registries / proxies that cap single-request
        // body size. Falls back to the buffered chunked path below when size is None.
        if let Some(total) = size {
            let mut location = self.begin_push_chunked_session(image).await?;
            let mapped = blob_data_stream.map(|frame| frame.map_err(std::io::Error::other));
            let shared = SharedReader::new(StreamReader::new(mapped));
            let mut range_start = 0;
            let mut remaining = total;
            while remaining > 0 {
                let chunk_len = self.push_chunk_size.min(remaining);
                let body = ReaderStream::new(shared.clone().take(chunk_len as u64));
                (location, range_start) = self
                    .push_chunk_streamed(&location, image, body, range_start, chunk_len)
                    .await?;
                remaining -= chunk_len;
            }
            return self
                .end_push_chunked_session(&location, image, blob_digest)
                .await;
        }

        let mut location = self.begin_push_chunked_session(image).await?;
        let mut range_start = 0;

        let mut blob_data_stream = pin!(blob_data_stream);

        while let Some(blob_data) = blob_data_stream.next().await {
            let mut blob_data = blob_data?;
            while !blob_data.is_empty() {
                let chunk = blob_data.split_to(self.push_chunk_size.min(blob_data.len()));
                (location, range_start) = self
                    .push_chunk(&location, image, chunk, range_start)
                    .await?;
            }
        }
        self.end_push_chunked_session(&location, image, blob_digest)
            .await
    }

    /// Perform an OAuth v2 auth request if necessary.
    ///
    /// This performs authorization and then stores the token internally to be used
    /// on other requests.
    /// # Caching
    ///
    /// A live cached token for `(registry, repository, operation)` answers
    /// without a single request. The [`store_auth_if_needed`] call above it is
    /// **not** part of that shortcut and runs either way: it is the side effect
    /// a later `apply_auth` reads to decide whether the request is
    /// authenticated at all, so an early return placed before it makes a
    /// cache-resolved pull go out anonymous and come back `401`.
    ///
    /// [`RegistryAuth::Bearer`] is excluded from the shortcut. `_auth` returns
    /// the caller-supplied token without any request, so the cache saves
    /// nothing there — while this is the only route by which a *rotated* bearer
    /// token replaces the cached one, and short-circuiting would keep serving
    /// the stale token until its recorded expiry.
    ///
    /// [`store_auth_if_needed`]: Client::store_auth_if_needed
    pub async fn auth(
        &self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<String>> {
        self.store_auth_if_needed(image.resolve_registry(), authentication)
            .await;

        if !matches!(authentication, RegistryAuth::Bearer(_)) {
            if let Some(token) = self.tokens.get(image, operation).await {
                return Ok(bearer_value(&token));
            }
        }

        let token = self.acquire_token(image, authentication, operation).await?;
        Ok(token.as_ref().and_then(bearer_value))
    }

    /// Runs the authentication handshake and caches what it yields, coalescing
    /// concurrent cold callers on `(registry, repository, operation)`.
    ///
    /// This pair — the handshake and the cache write — is the unit that must be
    /// coalesced. A refresh of an index or a multi-layer pull enters here N-wide
    /// and cold, and every caller misses the token cache before any of them has
    /// finished writing to it.
    async fn acquire_token(
        &self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<RegistryTokenType>> {
        let key = TokenCacheKey::new(image, operation);
        self.token_flights
            .acquire(key, || async {
                let token = self._auth(image, authentication, operation).await?;
                if let Some(token) = &token {
                    self.tokens.insert(image, operation, token.clone()).await;
                }
                Ok(token)
            })
            .await
    }

    /// The `WWW-Authenticate` challenge this host answers `GET /v2/` with,
    /// probed once per host and shared by every repository under it.
    ///
    /// The probe URL is built from the registry alone, so its answer never
    /// depended on the repository; caching it per host is what takes a
    /// P-package sync from P probes to one. Staleness is handled by the `401`
    /// path in `send_authed`, which drops the cached challenge and reseeds it
    /// from the rejection's own header, not by re-probing.
    async fn challenge_for(&self, registry: &str) -> Result<ChallengeInfo> {
        // The version request will tell us where to go.
        let url = format!(
            "{}://{}/v2/",
            self.config.protocol.scheme_for(registry),
            registry
        );
        self.challenges
            .get_or_probe(registry, || async {
                debug!(?url, "Probing for an authentication challenge");
                let res = self.client.get(&url).send().await?;
                let Some(dist_hdr) = res.headers().get(reqwest::header::WWW_AUTHENTICATE) else {
                    return Ok(ChallengeInfo::Unchallenged);
                };
                Ok(match BearerChallenge::try_from(dist_hdr) {
                    Ok(challenge) => ChallengeInfo::Bearer(challenge),
                    Err(e) => {
                        debug!(error = ?e, "Falling back to HTTP Basic Auth");
                        ChallengeInfo::Unsupported
                    }
                })
            })
            .await
    }

    /// Internal auth that retrieves token.
    async fn _auth(
        &self,
        image: &Reference,
        authentication: &RegistryAuth,
        operation: RegistryOperation,
    ) -> Result<Option<RegistryTokenType>> {
        debug!("Authorizing for image: {:?}", image);

        if let RegistryAuth::Bearer(token) = authentication {
            return Ok(Some(RegistryTokenType::Bearer(RegistryToken::Token {
                token: token.clone(),
            })));
        }

        let basic_fallback = || match authentication {
            RegistryAuth::Basic(username, password) => Ok(Some(RegistryTokenType::Basic(
                username.to_string(),
                password.to_string(),
            ))),
            _ => Ok(None),
        };

        let challenge = match self.challenge_for(image.resolve_registry()).await? {
            ChallengeInfo::Bearer(challenge) => challenge,
            // No challenge at all: nothing to exchange, and Basic credentials
            // stay unused rather than being volunteered to a host that never
            // asked for them — the pre-cache behaviour, unchanged.
            ChallengeInfo::Unchallenged => return Ok(None),
            ChallengeInfo::Unsupported => return basic_fallback(),
        };

        // Allow for either push or pull authentication
        let scope = match operation {
            RegistryOperation::Pull => format!("repository:{}:pull", image.repository()),
            RegistryOperation::Push => format!("repository:{}:pull,push", image.repository()),
        };

        let realm = challenge.realm.as_ref();
        self.require_secure_realm(image, realm)?;
        let service = challenge.service.as_ref();
        let mut query = vec![("scope", &scope)];

        if let Some(s) = service {
            query.push(("service", s))
        }

        // TODO: At some point in the future, we should support sending a secret to the
        // server for auth. This particular workflow is for read-only public auth.
        debug!(?realm, ?service, ?scope, "Making authentication call");

        let auth_res = self
            .client
            .get(realm)
            .query(&query)
            .apply_authentication(authentication)
            .send()
            .await?;

        match auth_res.status() {
            reqwest::StatusCode::OK => {
                let text = auth_res.text().await?;
                debug!("Received response from auth request");
                let token: RegistryToken = serde_json::from_str(&text)
                    .map_err(|e| OciDistributionError::RegistryTokenDecodeError(e.to_string()))?;
                debug!("Successfully authorized for image '{:?}'", image);
                Ok(Some(RegistryTokenType::Bearer(token)))
            }
            status => {
                let reason = auth_res.text().await?;
                debug!("Failed to authenticate for image '{:?}': {}", image, reason);
                // A token-service outage (5xx) or rate-limit (429) is an
                // availability failure, not a credential rejection. Preserve the
                // status via ServerError so callers can classify it apart from a
                // genuine 401/403 (which stays AuthenticationFailure).
                if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Err(OciDistributionError::ServerError {
                        code: status.as_u16(),
                        url: redacted_display_str(realm),
                        message: reason,
                    });
                }
                Err(OciDistributionError::AuthenticationFailure(reason))
            }
        }
    }

    /// Fetch a manifest's digest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// Will first attempt to read the `Docker-Content-Digest` header using a
    /// HEAD request. If this header is not present, will make a second GET
    /// request and return the SHA256 of the response body.
    pub async fn fetch_manifest_digest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<String> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        let url = self.to_v2_manifest_url(image);
        debug!("HEAD image manifest from {}", url);
        let res = RequestBuilderWrapper::from_client(self, |client| client.head(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .send_authed(image, RegistryOperation::Pull)
            .await?;

        if let Some(digest) = digest_header_value(res.headers().clone())? {
            let status = res.status();
            let body = res.bytes().await?;
            validate_registry_response(status, &body, &url)?;

            // If the reference has a digest and the digest header has a matching algorithm, compare
            // them and return an error if they don't match.
            if let Some(img_digest) = image.digest() {
                let header_digest = Digest::new(&digest)?;
                let image_digest = Digest::new(img_digest)?;
                if header_digest.algorithm == image_digest.algorithm
                    && header_digest != image_digest
                {
                    return Err(DigestError::VerificationError {
                        expected: img_digest.to_string(),
                        actual: digest,
                    }
                    .into());
                }
            }

            Ok(digest)
        } else {
            debug!("GET image manifest from {}", url);
            let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
                .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
                .send_authed(image, RegistryOperation::Pull)
                .await?;
            let status = res.status();
            trace!(headers = ?res.headers(), "Got Headers");
            let headers = res.headers().clone();
            let final_url = self.note_manifest_redirect(image, &url, &res);
            // Before the body is read: an HTML portal has no size a manifest
            // reader should ever pull into memory. A non-200 keeps the old
            // order — its body is the OCI error envelope.
            if status == reqwest::StatusCode::OK {
                validate_manifest_content_type(&headers, &final_url)?;
            }
            let body = res.bytes().await?;
            validate_registry_response(status, &body, &final_url)?;

            validate_digest(&body, digest_header_value(headers)?, image.digest())
                .map_err(OciDistributionError::from)
        }
    }

    async fn validate_layers(
        &self,
        manifest: &OciImageManifest,
        accepted_media_types: Vec<&str>,
    ) -> Result<()> {
        if manifest.layers.is_empty() {
            return Err(OciDistributionError::PullNoLayersError);
        }

        for layer in &manifest.layers {
            if !accepted_media_types.iter().any(|i| i.eq(&layer.media_type)) {
                return Err(OciDistributionError::IncompatibleLayerMediaTypeError(
                    layer.media_type.clone(),
                ));
            }
        }

        Ok(())
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [OciImageManifest]
    /// and the manifest content digest hash.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub async fn pull_image_manifest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_image_manifest(image).await
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// Returns `(image_manifest, manifest_digest, Option<manifest_list_digest>)`.
    /// The manifest list digest is `Some` when the original reference pointed to
    /// an image index / manifest list; `None` when it pointed directly to a
    /// single-platform image manifest.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub async fn pull_image_manifest_and_list_digest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, Option<String>)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_image_manifest_and_list_digest(image).await
    }

    /// Pull a manifest from the remote OCI Distribution service without parsing it.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing raw byte representation of the manifest
    /// and the manifest content digest.
    pub async fn pull_manifest_raw(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        accepted_media_types: &[&str],
    ) -> Result<(bytes::Bytes, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_manifest_raw(image, accepted_media_types).await
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [Manifest](crate::manifest::OciImageManifest)
    /// and the manifest content digest hash.
    pub async fn pull_manifest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciManifest, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_manifest(image).await
    }

    /// Pull an image manifest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    async fn _pull_image_manifest(&self, image: &Reference) -> Result<(OciImageManifest, String)> {
        let (manifest, digest, _list_digest) =
            self._pull_image_manifest_and_list_digest(image).await?;
        Ok((manifest, digest))
    }

    /// Pull an image manifest from the remote OCI Distribution service,
    /// also returning the manifest list digest if the image is multi-arch.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    ///
    /// Returns `(image_manifest, manifest_digest, Option<manifest_list_digest>)`.
    /// The manifest list digest is `Some` when the original reference pointed to
    /// an image index / manifest list; `None` when it pointed directly to a
    /// single-platform image manifest.
    async fn _pull_image_manifest_and_list_digest(
        &self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String, Option<String>)> {
        let (manifest, digest) = self._pull_manifest(image).await?;
        match manifest {
            OciManifest::Image(image_manifest) => Ok((image_manifest, digest, None)),
            OciManifest::ImageIndex(image_index_manifest) => {
                let list_digest = digest;
                debug!("Inspecting Image Index Manifest");
                let platform_digest = if let Some(resolver) = &self.config.platform_resolver {
                    resolver(&image_index_manifest.manifests)
                } else {
                    return Err(OciDistributionError::ImageIndexParsingNoPlatformResolverError);
                };

                match platform_digest {
                    Some(platform_digest) => {
                        debug!("Selected manifest entry with digest: {}", platform_digest);
                        let manifest_entry_reference =
                            image.clone_with_digest(platform_digest.clone());
                        self._pull_manifest(&manifest_entry_reference)
                            .await
                            .and_then(|(manifest, _digest)| match manifest {
                                OciManifest::Image(manifest) => {
                                    Ok((manifest, platform_digest, Some(list_digest)))
                                }
                                OciManifest::ImageIndex(_) => {
                                    Err(OciDistributionError::ImageManifestNotFoundError(
                                        "received Image Index manifest instead".to_string(),
                                    ))
                                }
                            })
                    }
                    None => Err(OciDistributionError::ImageManifestNotFoundError(
                        "no entry found in image index manifest matching client's default platform"
                            .to_string(),
                    )),
                }
            }
        }
    }

    /// Pull a manifest from the remote OCI Distribution service without parsing it.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    async fn _pull_manifest_raw(
        &self,
        image: &Reference,
        accepted_media_types: &[&str],
    ) -> Result<(bytes::Bytes, String)> {
        let url = self.to_v2_manifest_url(image);
        debug!("Pulling image manifest from {}", url);

        let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(accepted_media_types)?
            .send_authed(image, RegistryOperation::Pull)
            .await?;
        let status = res.status();
        let headers = res.headers().clone();
        let final_url = self.note_manifest_redirect(image, &url, &res);
        // Before the body is read: an HTML portal has no size a manifest reader
        // should ever pull into memory. A non-200 keeps the old order — its
        // body is the OCI error envelope.
        if status == reqwest::StatusCode::OK {
            validate_manifest_content_type(&headers, &final_url)?;
        }
        let body = res.bytes().await?;

        validate_registry_response(status, &body, &final_url)?;

        let digest_header = digest_header_value(headers)?;
        let digest = validate_digest(&body, digest_header, image.digest())?;

        Ok((body, digest))
    }

    /// Pull a manifest from the remote OCI Distribution service.
    ///
    /// If the connection has already gone through authentication, this will
    /// use the bearer token. Otherwise, this will attempt an anonymous pull.
    async fn _pull_manifest(&self, image: &Reference) -> Result<(OciManifest, String)> {
        let (body, digest) = self
            ._pull_manifest_raw(image, MIME_TYPES_DISTRIBUTION_MANIFEST)
            .await?;

        self.validate_image_manifest(&body).await?;

        debug!("Parsing response as Manifest");
        let manifest = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;
        Ok((manifest, digest))
    }

    async fn validate_image_manifest(&self, body: &[u8]) -> Result<()> {
        let versioned: Versioned = serde_json::from_slice(body)
            .map_err(|e| OciDistributionError::VersionedParsingError(e.to_string()))?;
        debug!(?versioned, "validating manifest");
        if versioned.schema_version != 2 {
            return Err(OciDistributionError::UnsupportedSchemaVersionError(
                versioned.schema_version,
            ));
        }
        if let Some(media_type) = versioned.media_type {
            if media_type != IMAGE_MANIFEST_MEDIA_TYPE
                && media_type != OCI_IMAGE_MEDIA_TYPE
                && media_type != IMAGE_MANIFEST_LIST_MEDIA_TYPE
                && media_type != OCI_IMAGE_INDEX_MEDIA_TYPE
            {
                return Err(OciDistributionError::UnsupportedMediaTypeError(media_type));
            }
        }

        Ok(())
    }

    /// Pull a manifest and its config from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// A Tuple is returned containing the [OciImageManifest],
    /// the manifest content digest hash and the contents of the manifests config layer
    /// as a String.
    pub async fn pull_manifest_and_config(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, String)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_manifest_and_config(image)
            .await
            .and_then(|(manifest, digest, config)| {
                Ok((
                    manifest,
                    digest,
                    String::from_utf8(config.data.into()).map_err(|e| {
                        OciDistributionError::GenericError(Some(format!(
                            "Cannot parse config as UTF-8 string: {e}"
                        )))
                    })?,
                ))
            })
    }

    /// Pull a manifest and its config from the remote OCI Distribution service.
    ///
    /// The client will check if it's already been authenticated and if
    /// not will attempt to do.
    ///
    /// Returns `(image_manifest, manifest_digest, config_json, Option<manifest_list_digest>)`.
    /// The manifest list digest is `Some` when the original reference pointed to
    /// an image index / manifest list; `None` when it pointed directly to a
    /// single-platform image manifest.
    ///
    /// If a multi-platform Image Index manifest is encountered, a platform-specific
    /// Image manifest will be selected using the client's default platform resolution.
    pub async fn pull_manifest_and_config_and_list_digest(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
    ) -> Result<(OciImageManifest, String, String, Option<String>)> {
        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        self._pull_manifest_and_config_and_list_digest(image)
            .await
            .and_then(|(manifest, digest, config, list_digest)| {
                Ok((
                    manifest,
                    digest,
                    String::from_utf8(config.data.into()).map_err(|e| {
                        OciDistributionError::GenericError(Some(format!(
                            "Cannot parse config as UTF-8 string: {e}"
                        )))
                    })?,
                    list_digest,
                ))
            })
    }

    async fn _pull_manifest_and_config(
        &self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String, Config)> {
        let (manifest, digest, config, _list_digest) = self
            ._pull_manifest_and_config_and_list_digest(image)
            .await?;
        Ok((manifest, digest, config))
    }

    async fn _pull_manifest_and_config_and_list_digest(
        &self,
        image: &Reference,
    ) -> Result<(OciImageManifest, String, Config, Option<String>)> {
        let (manifest, digest, list_digest) =
            self._pull_image_manifest_and_list_digest(image).await?;

        let mut out: Vec<u8> = Vec::new();
        debug!("Pulling config layer");
        self.pull_blob(image, &manifest.config, &mut out).await?;
        let media_type = manifest.config.media_type.clone();
        let annotations = manifest.annotations.clone();
        Ok((
            manifest,
            digest,
            Config::new(out, media_type, annotations),
            list_digest,
        ))
    }

    /// Push a manifest list to an OCI registry.
    ///
    /// This pushes a manifest list to an OCI registry.
    pub async fn push_manifest_list(
        &self,
        reference: &Reference,
        auth: &RegistryAuth,
        manifest: OciImageIndex,
    ) -> Result<String> {
        self.store_auth_if_needed(reference.resolve_registry(), auth)
            .await;
        self.push_manifest(reference, &OciManifest::ImageIndex(manifest))
            .await
    }

    /// Pull a single layer from an OCI registry.
    ///
    /// This pulls the layer for a particular image that is identified by the given layer
    /// descriptor. The layer descriptor can be anything that can be referenced as a layer
    /// descriptor. The image reference is used to find the repository and the registry, but it is
    /// not used to verify that the digest is a layer inside of the image. (The manifest is used for
    /// that.)
    pub async fn pull_blob<T: AsyncWrite>(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        out: T,
    ) -> Result<()> {
        let response = self.pull_blob_response(image, &layer, None, None).await?;

        let mut maybe_header_digester = digest_header_value(response.headers().clone())?
            .map(|digest| Digester::new(&digest).map(|d| (d, digest)))
            .transpose()?;

        // With a blob pull, we need to use the digest from the layer and not the image
        let layer_digest = layer.as_layer_descriptor().digest.to_string();
        let mut layer_digester = Digester::new(&layer_digest)?;

        let status = response.status();
        let url = response.url().to_string();
        if !status.is_success() {
            let body = response.bytes().await?;
            return validate_registry_response(status, &body, &url);
        }
        let mut stream = response.bytes_stream();

        let mut out = pin!(out);

        while let Some(bytes) = stream.next().await {
            let bytes = bytes?;
            if let Some((ref mut digester, _)) = maybe_header_digester.as_mut() {
                digester.update(&bytes);
            }
            layer_digester.update(&bytes);
            out.write_all(&bytes).await?;
        }

        // Ensure all buffered writes are flushed before returning.
        out.flush().await?;

        if let Some((mut digester, expected)) = maybe_header_digester.take() {
            let digest = digester.finalize();

            if digest != expected {
                return Err(DigestError::VerificationError {
                    expected,
                    actual: digest,
                }
                .into());
            }
        }

        let digest = layer_digester.finalize();
        if digest != layer_digest {
            return Err(DigestError::VerificationError {
                expected: layer_digest,
                actual: digest,
            }
            .into());
        }

        Ok(())
    }

    /// Stream a single layer from an OCI registry.
    ///
    /// This is a streaming version of [`Client::pull_blob`]. Returns [`SizedStream`], which
    /// implements [`Stream`] or can be used directly to get the content
    /// length of the response
    ///
    /// # Example
    /// ```rust
    /// use std::future::Future;
    /// use std::io::Error;
    ///
    /// use futures_util::TryStreamExt;
    /// use oci_client::{Client, Reference};
    /// use oci_client::client::ClientConfig;
    /// use oci_client::manifest::OciDescriptor;
    ///
    /// async {
    ///   let client = Client::new(Default::default());
    ///   let imgRef: Reference = "busybox:latest".parse().unwrap();
    ///   let desc = OciDescriptor { digest: "sha256:deadbeef".to_owned(), ..Default::default() };
    ///   let mut stream = client.pull_blob_stream(&imgRef, &desc).await.unwrap();
    ///   // Check the optional content length
    ///   let content_length = stream.content_length.unwrap_or_default();
    ///   // Use as a stream
    ///   stream.try_next().await.unwrap().unwrap();
    ///   // Use the underlying stream
    ///   let mut stream = stream.stream;
    /// };
    /// ```
    pub async fn pull_blob_stream(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
    ) -> Result<SizedStream> {
        stream_from_response(
            self.pull_blob_response(image, &layer, None, None).await?,
            layer,
            true,
        )
        .await
    }

    /// Stream a single layer from an OCI registry starting with a byte offset. This can be used to
    /// continue downloading a layer after a network error. Please note that when doing a partial
    /// download (meaning it returns the [`BlobResponse::Partial`] variant), the layer digest is not
    /// verified as all the bytes are not available. The returned blob response will contain the
    /// header from the request digest, if it was set, that can be used (in addition to the digest
    /// from the layer) to verify the blob once all the bytes have been downloaded. Failure to do
    /// this means your content will not be verified.
    ///
    /// Returns [`BlobResponse`] which indicates if the response was a full or partial response.
    pub async fn pull_blob_stream_partial(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        offset: u64,
        length: Option<u64>,
    ) -> Result<BlobResponse> {
        let response = self
            .pull_blob_response(image, &layer, Some(offset), length)
            .await?;

        let status = response.status();
        match status {
            StatusCode::OK => Ok(BlobResponse::Full(
                stream_from_response(response, &layer, true).await?,
            )),
            StatusCode::PARTIAL_CONTENT => Ok(BlobResponse::Partial(
                stream_from_response(response, &layer, false).await?,
            )),
            _ => {
                let url = response.url().to_string();
                let body = response.bytes().await?;
                Err(validate_registry_response(status, &body, &url).expect_err("validate_registry_response should return an error for non-success status codes"))
            }
        }
    }

    /// Pull a single layer from an OCI registry.
    async fn pull_blob_response(
        &self,
        image: &Reference,
        layer: impl AsLayerDescriptor,
        offset: Option<u64>,
        length: Option<u64>,
    ) -> Result<Response> {
        let layer = layer.as_layer_descriptor();
        let url = self.to_v2_blob_url(image, layer.digest);

        let mut request = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .apply_auth(image, RegistryOperation::Pull)
            .await?
            .into_request_builder();
        if let (Some(off), Some(len)) = (offset, length) {
            let end = (off + len).saturating_sub(1);
            request = request.header(
                RANGE,
                HeaderValue::from_str(&format!("bytes={off}-{end}")).unwrap(),
            );
        } else if let Some(offset) = offset {
            request = request.header(
                RANGE,
                HeaderValue::from_str(&format!("bytes={offset}-")).unwrap(),
            );
        }
        let mut response = request.send().await?;

        if let Some(urls) = &layer.urls {
            for url in urls {
                if response.error_for_status_ref().is_ok() {
                    break;
                }

                let url = Url::parse(url)
                    .map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;

                if url.scheme() == "http" || url.scheme() == "https" {
                    // NOTE: we must not authenticate on additional URLs as those
                    // can be abused to leak credentials or tokens.  Please
                    // refer to CVE-2020-15157 for more information.
                    request =
                        RequestBuilderWrapper::from_client(self, |client| client.get(url.clone()))
                            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
                            .into_request_builder();
                    if let Some(offset) = offset {
                        request = request.header(
                            RANGE,
                            HeaderValue::from_str(&format!("bytes={offset}-")).unwrap(),
                        );
                    }
                    response = request.send().await?
                }
            }
        }

        Ok(response)
    }

    /// Begins a session to push an image to registry in a monolithical way
    ///
    /// Returns URL with session UUID
    async fn begin_push_monolithical_session(&self, image: &Reference) -> Result<String> {
        let url = &self.to_v2_blob_upload_url(image);
        debug!(?url, "begin_push_monolithical_session");
        let res = RequestBuilderWrapper::from_client_no_redirect(self, |client| client.post(url))
            .apply_auth(image, RegistryOperation::Push)
            .await?
            .into_request_builder()
            // We set "Content-Length" to 0 here even though the OCI Distribution
            // spec does not strictly require that. In practice we have seen that
            // certain registries require "Content-Length" to be present for all
            // types of push sessions.
            .header("Content-Length", 0)
            .send()
            .await?;

        // OCI spec requires the status code be 202 Accepted to successfully begin the push process
        self.extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
            .await
    }

    /// Begins a session to push an image to registry as a series of chunks
    ///
    /// Returns URL with session UUID
    async fn begin_push_chunked_session(&self, image: &Reference) -> Result<String> {
        let url = &self.to_v2_blob_upload_url(image);
        debug!(?url, "begin_push_session");
        let res = RequestBuilderWrapper::from_client_no_redirect(self, |client| client.post(url))
            .apply_auth(image, RegistryOperation::Push)
            .await?
            .into_request_builder()
            .header("Content-Length", 0)
            .send()
            .await?;

        // OCI spec requires the status code be 202 Accepted to successfully begin the push process
        self.extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
            .await
    }

    /// Closes the chunked push session
    ///
    /// Returns the pullable URL for the image
    async fn end_push_chunked_session(
        &self,
        location: &str,
        image: &Reference,
        digest: &str,
    ) -> Result<String> {
        let url = Url::parse_with_params(location, &[("digest", digest)])
            .map_err(|e| OciDistributionError::GenericError(Some(e.to_string())))?;
        self.require_same_registry(image, url.as_str())?;
        let res =
            RequestBuilderWrapper::from_client_no_redirect(self, |client| client.put(url.clone()))
                .apply_auth(image, RegistryOperation::Push)
                .await?
                .into_request_builder()
                .header("Content-Length", 0)
                .send()
                .await?;
        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
            .await
    }

    /// Pushes a layer to a registry as a monolithical blob.
    ///
    /// Returns the URL location for the next layer
    async fn push_stream_monolithically(
        &self,
        location: &str,
        image: &Reference,
        layer: impl Stream<Item = Result<bytes::Bytes>> + Send + 'static,
        size: usize,
        blob_digest: &str,
    ) -> Result<String> {
        let mut url =
            Url::parse(location).map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;
        url.query_pairs_mut().append_pair("digest", blob_digest);
        let url = url.to_string();

        debug!(size, location = ?url, "Pushing monolithically");
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Length",
            format!("{}", size)
                .parse()
                .map_err(|e: reqwest::header::InvalidHeaderValue| {
                    OciDistributionError::GenericError(Some(e.to_string()))
                })?,
        );
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

        self.require_same_registry(image, &url)?;
        let res = RequestBuilderWrapper::from_client_no_redirect(self, |client| client.put(&url))
            .apply_auth(image, RegistryOperation::Push)
            .await?
            .into_request_builder()
            .headers(headers)
            .body(reqwest::Body::wrap_stream(layer))
            .send()
            .await?;

        // Returns location
        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
            .await
    }

    /// Pushes a layer to a registry as a monolithical blob.
    ///
    /// Returns the URL location for the next layer
    async fn push_monolithically(
        &self,
        location: &str,
        image: &Reference,
        layer: impl Into<bytes::Bytes>,
        blob_digest: &str,
    ) -> Result<String> {
        let mut url =
            Url::parse(location).map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;
        url.query_pairs_mut().append_pair("digest", blob_digest);
        let url = url.to_string();

        let layer = layer.into();
        debug!(size = layer.len(), location = ?url, "Pushing monolithically");
        if layer.is_empty() {
            return Err(OciDistributionError::PushNoDataError);
        };
        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Length",
            format!("{}", layer.len()).parse().unwrap(),
        );
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

        self.require_same_registry(image, &url)?;
        let res = RequestBuilderWrapper::from_client_no_redirect(self, |client| client.put(&url))
            .apply_auth(image, RegistryOperation::Push)
            .await?
            .into_request_builder()
            .headers(headers)
            .body(layer)
            .send()
            .await?;

        // Returns location
        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
            .await
    }

    /// Sends one chunk `PATCH` with `Content-Range` and an explicit
    /// `Content-Length` of `chunk_len` bytes.
    ///
    /// Shared by [`push_chunk`] (buffered `Bytes` body) and
    /// [`push_chunk_streamed`] (streamed body) — the single source of truth for the
    /// chunk-upload request contract. Returns the location for the next chunk
    /// alongside the next range start.
    async fn push_chunk_body(
        &self,
        location: &str,
        image: &Reference,
        body: reqwest::Body,
        range_start: usize,
        chunk_len: usize,
    ) -> Result<(String, usize)> {
        let end_range_inclusive = range_start + chunk_len - 1;

        let mut headers = HeaderMap::new();
        headers.insert(
            "Content-Range",
            format!("{range_start}-{end_range_inclusive}")
                .parse()
                .unwrap(),
        );
        headers.insert("Content-Length", format!("{chunk_len}").parse().unwrap());
        headers.insert("Content-Type", "application/octet-stream".parse().unwrap());

        debug!(
            ?range_start,
            ?end_range_inclusive,
            chunk_len,
            ?location,
            "Pushing chunk"
        );

        self.require_same_registry(image, location)?;
        let res =
            RequestBuilderWrapper::from_client_no_redirect(self, |client| client.patch(location))
                .apply_auth(image, RegistryOperation::Push)
                .await?
                .into_request_builder()
                .headers(headers)
                .body(body)
                .send()
                .await?;

        // The registry reports what it actually stored via `Range: [bytes=]0-<end>`
        // (inclusive, from byte 0 of the blob). Trusting our own offsets when the
        // server accepted fewer bytes would send the next chunk at the wrong start,
        // and the final PUT would then commit a blob that does not match the digest
        // naming it. Neither body shape here can be rewound, so a disagreement is a
        // hard stop: `SpecViolationError` is the variant callers already treat as
        // "restart this blob", so `push_blob` retries it monolithically and
        // `push_blob_stream`'s caller re-pushes from a fresh body.
        let accepted_end = res.headers().get("Range").and_then(parse_range_end);
        let next_location = self
            .extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
            .await?;
        match accepted_end {
            Some(accepted_end) if accepted_end != end_range_inclusive => {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "registry accepted bytes 0-{accepted_end} of the chunk sent as {range_start}-{end_range_inclusive}"
                )));
            }
            _ => {}
        }

        // Returns location for next chunk and the start byte for the next range
        Ok((next_location, end_range_inclusive + 1))
    }

    /// Pushes a single buffered chunk of a blob, as part of a chunked blob upload.
    /// The caller is responsible for chunking the blob data into smaller parts, if needed.
    ///
    /// Returns the URL location for the next chunk, alongside the start of the next range to upload.
    async fn push_chunk(
        &self,
        location: &str,
        image: &Reference,
        blob_chunk: bytes::Bytes,
        range_start: usize,
    ) -> Result<(String, usize)> {
        if blob_chunk.is_empty() {
            return Err(OciDistributionError::PushNoDataError);
        }
        let chunk_len = blob_chunk.len();
        self.push_chunk_body(location, image, blob_chunk.into(), range_start, chunk_len)
            .await
    }

    /// Pushes a single chunk whose body is streamed rather than buffered.
    ///
    /// Identical wire behavior to [`push_chunk`] — one `PATCH` with `Content-Range`
    /// and an explicit `Content-Length` of `chunk_len` — but the body is a
    /// [`Stream`] drained by reqwest under socket backpressure. `chunk_len` must
    /// equal the number of bytes `body` will yield (the caller derives it from the
    /// known total size), so the registry receives an exact `Content-Length`.
    ///
    /// Returns the location for the next chunk alongside the next range start.
    async fn push_chunk_streamed<S>(
        &self,
        location: &str,
        image: &Reference,
        body: S,
        range_start: usize,
        chunk_len: usize,
    ) -> Result<(String, usize)>
    where
        S: Stream<Item = std::io::Result<bytes::Bytes>> + Send + 'static,
    {
        if chunk_len == 0 {
            return Err(OciDistributionError::PushNoDataError);
        }
        self.push_chunk_body(
            location,
            image,
            reqwest::Body::wrap_stream(body),
            range_start,
            chunk_len,
        )
        .await
    }

    /// Mounts a blob to the provided reference, from the given source
    pub async fn mount_blob(
        &self,
        image: &Reference,
        source: &Reference,
        digest: &str,
    ) -> Result<BlobMountResponse> {
        let base_url = self.to_v2_blob_upload_url(image);
        let url = Url::parse_with_params(
            &base_url,
            &[("mount", digest), ("from", source.repository())],
        )
        .map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;

        let res =
            RequestBuilderWrapper::from_client_no_redirect(self, |client| client.post(url.clone()))
                .apply_auth(image, RegistryOperation::Push)
                .await?
                .into_request_builder()
                .send()
                .await?;

        // A spec-conforming registry either mounts the blob (201) or, on a miss,
        // declines and opens a regular upload session (202) at the returned
        // Location instead of erroring - the caller uploads there. Any other
        // status still routes through extract_location_header's existing
        // SpecViolationError / ServerError mapping (checked against CREATED,
        // matching prior behavior).
        if res.status() == reqwest::StatusCode::ACCEPTED {
            let location = self
                .extract_location_header(image, res, &reqwest::StatusCode::ACCEPTED)
                .await?;
            return Ok(BlobMountResponse::UploadSessionOpened(location));
        }

        self.extract_location_header(image, res, &reqwest::StatusCode::CREATED)
            .await?;

        Ok(BlobMountResponse::Mounted)
    }

    /// Pushes the manifest for a specified image
    ///
    /// Returns pullable manifest URL
    pub async fn push_manifest(&self, image: &Reference, manifest: &OciManifest) -> Result<String> {
        let mut headers = HeaderMap::new();
        let content_type = manifest.content_type();
        headers.insert("Content-Type", content_type.parse().unwrap());

        // Serialize the manifest with a canonical json formatter, as described at
        // https://github.com/opencontainers/image-spec/blob/main/considerations.md#json
        let mut body = Vec::new();
        let mut ser = serde_json::Serializer::with_formatter(&mut body, CanonicalFormatter::new());
        manifest.serialize(&mut ser).unwrap();

        self.push_manifest_raw(image, body, manifest.content_type().parse().unwrap())
            .await
    }

    /// Pushes the manifest, provided as raw bytes, for a specified image
    ///
    /// Returns pullable manifest url
    pub async fn push_manifest_raw(
        &self,
        image: &Reference,
        body: impl Into<bytes::Bytes>,
        content_type: HeaderValue,
    ) -> Result<String> {
        let url = self.to_v2_manifest_url(image);
        debug!(?url, ?content_type, "push manifest");

        let mut headers = HeaderMap::new();
        headers.insert("Content-Type", content_type);

        let body = body.into();

        // Calculate the digest of the manifest, this is useful
        // if the remote registry is violating the OCI Distribution Specification.
        // See below for more details.
        let manifest_hash = sha256_digest(&body);

        let res = RequestBuilderWrapper::from_client(self, |client| client.put(url.clone()))
            .apply_auth(image, RegistryOperation::Push)
            .await?
            .into_request_builder()
            .headers(headers)
            .body(body)
            .send()
            .await?;

        let ret = self
            .extract_location_header(image, res, &reqwest::StatusCode::CREATED)
            .await;

        if matches!(ret, Err(OciDistributionError::RegistryNoLocationError)) {
            // The registry is violating the OCI Distribution Spec, BUT the OCI
            // image/artifact has been uploaded successfully.
            // The `Location` header contains the sha256 digest of the manifest,
            // we can reuse the value we calculated before.
            // The workaround is there because repositories such as
            // AWS ECR are violating this aspect of the spec. This at least let the
            // oci-distribution users interact with these registries.
            warn!("Registry is not respecting the OCI Distribution Specification: it didn't return the Location of the uploaded Manifest inside of the response headers. Working around this issue...");

            let url_base = url
                .strip_suffix(image.tag().unwrap_or("latest"))
                .expect("The manifest URL always ends with the image tag suffix");
            let url_by_digest = format!("{url_base}{manifest_hash}");

            return Ok(url_by_digest);
        }

        ret
    }

    /// Pulls the referrers for the given image filtering by the optionally provided artifact type.
    ///
    /// Implements the [OCI Distribution Spec referrers API][oci-referrers] with an automatic
    /// fallback to the [referrers tag schema][oci-tag-schema] when the registry returns a
    /// `404 Not Found` for the native endpoint (as required by the spec).
    ///
    /// Many registries (e.g. ghcr.io) do not implement the native
    /// `/v2/<name>/referrers/<digest>` endpoint and return 404 instead. The OCI spec
    /// defines a fallback: the referrers index is stored as a regular OCI Image Index
    /// under a tag derived from the subject digest by replacing `:` with `-`
    /// (e.g. `sha256:abc…` → tag `sha256-abc…`).
    ///
    /// When the fallback is used, `artifact_type` filtering is applied client-side,
    /// since the tag schema stores a single unfiltered index with no query-parameter
    /// support.
    ///
    /// If both the native API and the tag schema fail, an empty `OciImageIndex` is
    /// returned, as per the spec recommendation.
    ///
    /// [oci-referrers]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#listing-referrers
    /// [oci-tag-schema]: https://github.com/opencontainers/distribution-spec/blob/main/spec.md#referrers-tag-schema
    pub async fn pull_referrers(
        &self,
        image: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<OciImageIndex> {
        let url = self.to_v2_referrers_url(image, artifact_type)?;
        debug!("Pulling referrers from {}", url);

        let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .send_authed(image, RegistryOperation::Pull)
            .await?;
        let status = res.status();
        let body = res.bytes().await?;

        // Per the OCI Distribution Spec, a 404 on the native referrers endpoint means the
        // registry does not support it; fall back to the referrers tag schema.
        if status == reqwest::StatusCode::NOT_FOUND {
            debug!(
                url = %url,
                "Native referrers API returned 404; falling back to OCI referrers tag schema"
            );
            return self
                .pull_referrers_via_tag_schema(image, artifact_type)
                .await;
        }

        validate_registry_response(status, &body, &url)?;
        let manifest = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;

        Ok(manifest)
    }

    /// Native-only referrers lookup that distinguishes an unsupported registry
    /// from a supported one with zero referrers.
    ///
    /// Unlike [`Self::pull_referrers`], this does NOT fall back to the referrers
    /// tag schema: it performs only the native `/v2/<name>/referrers/<digest>`
    /// GET. A `404` on that endpoint returns `Ok(None)` — the registry does not
    /// implement the native OCI 1.1 Referrers API. A `200` returns
    /// `Ok(Some(index))` (supported; the index may be empty). Any other status
    /// is an error. Callers that need the OCI-spec tag-schema fallback should
    /// use [`Self::pull_referrers`]; callers that must fail hard on an
    /// unsupported registry (rather than silently returning an empty list) use
    /// this.
    pub async fn pull_referrers_native(
        &self,
        image: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<Option<OciImageIndex>> {
        let url = self.to_v2_referrers_url(image, artifact_type)?;
        debug!("Pulling referrers (native-only) from {}", url);

        let res = RequestBuilderWrapper::from_client(self, |client| client.get(&url))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .send_authed(image, RegistryOperation::Pull)
            .await?;
        let status = res.status();
        if status == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }

        let body = read_body_bounded(res, &url, MAX_REFERRERS_INDEX_BYTES).await?;
        validate_registry_response(status, &body, &url)?;
        let manifest: OciImageIndex = serde_json::from_slice(&body)
            .map_err(|e| OciDistributionError::ManifestParsingError(e.to_string()))?;

        // The byte cap alone does not bound the work a caller does per entry, and
        // a compact descriptor is ~200 bytes: 4 MiB of them is tens of thousands
        // of signatures to fetch and verify for one subject.
        if manifest.manifests.len() > MAX_REFERRERS_DESCRIPTORS {
            return Err(OciDistributionError::SpecViolationError(format!(
                "referrers index at {url} lists {} descriptors, above the {MAX_REFERRERS_DESCRIPTORS} limit",
                manifest.manifests.len()
            )));
        }

        Ok(Some(manifest))
    }

    /// Pulls the referrers index using the OCI referrers tag schema fallback.
    ///
    /// The tag is the subject digest with `:` replaced by `-`
    /// (e.g. `sha256:abc…` → `sha256-abc…`).
    ///
    /// If `artifact_type` is provided, the returned index is filtered client-side
    /// to include only entries whose `artifact_type` matches.
    ///
    /// If the tag does not exist or does not contain a valid image index, an empty
    /// `OciImageIndex` is returned as per the OCI spec recommendation.
    async fn pull_referrers_via_tag_schema(
        &self,
        image: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<OciImageIndex> {
        let digest = image.digest().ok_or_else(|| {
            OciDistributionError::GenericError(Some(
                "Getting referrers for a tag is not supported".into(),
            ))
        })?;

        let fallback_tag = digest.replace(':', "-");
        let fallback_ref = Reference::with_tag(
            image.resolve_registry().to_string(),
            image.repository().to_string(),
            fallback_tag.clone(),
        );

        debug!(
            tag = %fallback_tag,
            "Pulling referrers via tag schema"
        );

        let manifest = match self._pull_manifest(&fallback_ref).await {
            Ok((manifest, _digest)) => manifest,
            Err(e) => match &e {
                OciDistributionError::ImageManifestNotFoundError(_)
                | OciDistributionError::RegistryError { .. }
                | OciDistributionError::ServerError { code: 404, .. } => {
                    debug!(
                        error = ?e,
                        "Referrers tag schema not found; assuming no referrers"
                    );
                    return Ok(empty_image_index());
                }
                _ => return Err(e),
            },
        };

        let mut index = match manifest {
            OciManifest::ImageIndex(idx) => idx,
            OciManifest::Image(_) => {
                return Err(OciDistributionError::SpecViolationError(format!(
                    "referrers tag schema: tag '{fallback_tag}' contains an Image manifest; \
                     expected an OCI Image Index"
                )));
            }
        };

        // Apply client-side artifact_type filtering when requested, since the tag
        // schema stores a single unfiltered index.
        if let Some(at) = artifact_type {
            index.manifests.retain(|entry| {
                entry
                    .artifact_type
                    .as_deref()
                    .map(|t| t == at)
                    .unwrap_or(false)
            });
        }

        Ok(index)
    }

    /// Lists available repositories in the registry.
    ///
    /// Implements the OCI Distribution Spec catalog endpoint (`/v2/_catalog`).
    /// Supports pagination via `n` (page size) and `last` (last repo from
    /// previous page).
    pub async fn catalog(
        &self,
        image: &Reference,
        auth: &RegistryAuth,
        n: Option<usize>,
        last: Option<&str>,
    ) -> Result<CatalogResponse> {
        let op = RegistryOperation::Pull;
        let url = self.to_catalog_url(image);

        self.store_auth_if_needed(image.resolve_registry(), auth)
            .await;

        let request = self.client.get(&url);
        let request = if let Some(num) = n {
            request.query(&[("n", num)])
        } else {
            request
        };
        let request = if let Some(l) = last {
            request.query(&[("last", l)])
        } else {
            request
        };
        let request = RequestBuilderWrapper {
            client: self,
            request_builder: request,
        };
        let res = request.send_authed(image, op).await?;
        let status = res.status();
        let body = res.bytes().await?;

        validate_registry_response(status, &body, &url)?;

        Ok(serde_json::from_str(std::str::from_utf8(&body)?)?)
    }

    async fn extract_location_header(
        &self,
        image: &Reference,
        res: reqwest::Response,
        expected_status: &reqwest::StatusCode,
    ) -> Result<String> {
        debug!(expected_status_code=?expected_status.as_u16(),
            status_code=?res.status().as_u16(),
            "extract location header");
        if res.status().eq(expected_status) {
            let location_header = res.headers().get("Location");
            debug!(location=?location_header, "Location header");
            match location_header {
                None => Err(OciDistributionError::RegistryNoLocationError),
                Some(lh) => self.location_header_to_url(image, lh),
            }
        } else if res.status().is_success() && expected_status.is_success() {
            Err(OciDistributionError::SpecViolationError(format!(
                "Expected HTTP Status {}, got {} instead",
                expected_status,
                res.status(),
            )))
        } else {
            // Registry-chosen on both clients: the upload-session URL on the
            // no-redirect one, the post-redirect URL on the general one. Only
            // its origin was ever vetted, so path and query are still theirs.
            let url = redacted_display_url(res.url());
            let code = res.status().as_u16();
            let message = res.text().await?;
            Err(OciDistributionError::ServerError { url, code, message })
        }
    }

    /// Refuses a registry-supplied URL that is not on the reference's own
    /// registry.
    ///
    /// An upload session's URL comes from a registry-controlled `Location`
    /// header, so it can name any host. Following it hands that host this
    /// registry's credentials (CWE-522 / CWE-200), the blob body, and a
    /// request the caller never addressed — an internal address included
    /// (CWE-918). Sending it unauthenticated would close only the first of
    /// those three, so a cross-host session URL is refused outright. Relative
    /// and same-host absolute `Location` values are unaffected.
    ///
    /// This check is on the `Location` *string*, so it holds for exactly one
    /// hop on its own. Every caller therefore issues its request through
    /// [`RequestBuilderWrapper::from_client_no_redirect`], which is what stops
    /// a registry from answering the vetted request with a 3xx to the host the
    /// string check just refused.
    fn require_same_registry(&self, image: &Reference, url: &str) -> Result<()> {
        if self.is_same_registry_origin(image, url) {
            return Ok(());
        }
        Err(OciDistributionError::CrossHostRefused {
            // The refused URL is registry-chosen and reaches stderr, which in
            // CI is a public log. Redacting at construction rather than at the
            // `Display` impl leaves no caller able to reintroduce the raw form.
            url: redacted_display_str(url),
            registry: image.resolve_registry().to_string(),
        })
    }

    /// Refuses a token-service realm that would carry credentials in the clear.
    ///
    /// The realm comes verbatim from the registry's `WWW-Authenticate` header
    /// and is fetched with the user's Basic credentials attached, so a registry
    /// answering `realm="http://…"` collects the password in cleartext
    /// (CWE-522 / CWE-319). A cross-*host* realm is legitimate and stays
    /// allowed — federated token services are how Docker Hub works
    /// (`registry-1.docker.io` → `auth.docker.io`) — but a registry we reached
    /// over HTTPS may not hand its credentials to a plaintext one.
    ///
    /// Keyed on this registry's own scheme, never on a plain-HTTP allowance
    /// granted to some other host: a registry deliberately configured as
    /// plaintext may name a plaintext realm, and an unrelated allowance must
    /// not be able to redirect a credential.
    ///
    /// A plaintext registry is not a blanket licence either. Declaring one host
    /// plain HTTP admits an on-path attacker *on that host's traffic*; it does
    /// not agree to that attacker naming an arbitrary internet host as the
    /// realm and collecting the password there. So a plaintext realm on a
    /// plaintext registry is accepted only on the registry's own authority, or
    /// on a host that carries its own plain-HTTP allowance.
    fn require_secure_realm(&self, image: &Reference, realm: &str) -> Result<()> {
        let registry = image.resolve_registry();
        let refuse = || {
            Err(OciDistributionError::InsecureAuthRealm {
                // Registry-supplied, and a realm may carry a query; same
                // disclosure hazard as `CrossHostRefused`.
                realm: redacted_display_str(realm),
            })
        };
        let Ok(url) = Url::parse(realm) else {
            return refuse();
        };
        if url.scheme() == "https" {
            return Ok(());
        }
        if self.config.protocol.scheme_for(registry) == "https" {
            return refuse();
        }
        match url_authority(&url) {
            Some(authority)
                if authority == registry
                    || self.config.protocol.scheme_for(&authority) != "https" =>
            {
                Ok(())
            }
            _ => refuse(),
        }
    }

    /// Whether `url` shares the origin (scheme, host, port) the image reference
    /// resolves to.
    ///
    /// Fails closed: a URL neither side can parse counts as a mismatch, and so
    /// does an opaque origin (a non-http(s) scheme).
    ///
    /// One relaxation, in the safe direction: a registry configured as plain
    /// HTTP may hand out an `https` session URL on its own authority. That adds
    /// transport security rather than removing it, so it is not the handoff
    /// this check exists to catch. The reverse — an `https` registry naming an
    /// `http` URL on the same host — stays a mismatch.
    fn is_same_registry_origin(&self, image: &Reference, url: &str) -> bool {
        let registry = image.resolve_registry();
        let scheme = self.config.protocol.scheme_for(registry);
        let (Ok(expected), Ok(actual)) = (
            Url::parse(&format!("{scheme}://{registry}/")),
            Url::parse(url),
        ) else {
            return false;
        };
        if expected.origin() == actual.origin() {
            return true;
        }
        scheme == "http"
            && actual.scheme() == "https"
            && expected.host() == actual.host()
            && expected.port() == actual.port()
    }

    /// The URL a manifest response finally came from, warning when the client
    /// was redirected off the registry's own origin.
    ///
    /// Every error raised about a manifest response must name this URL rather
    /// than the one the request was addressed to: a mirror or proxy that
    /// redirects to a login portal is otherwise indistinguishable from the
    /// registry answering nonsense. The origin comparison includes the scheme,
    /// so a plain http -> https upgrade warns too; that is deliberate, since
    /// the point is visibility and the warning costs nothing.
    fn note_manifest_redirect(&self, image: &Reference, url: &str, res: &Response) -> String {
        // The origin comparison runs on the raw URL; only what is displayed is
        // redacted, so a credential can never widen the same-origin decision.
        let safe_url = redacted_display_url(res.url());
        if !self.is_same_registry_origin(image, res.url().as_str()) {
            warn!(
                request = %url,
                redirected_to = %safe_url,
                "manifest request left the registry origin"
            );
        }
        safe_url
    }

    /// Helper function to convert location header to URL
    ///
    /// Location may be absolute (containing the protocol and/or hostname), or relative (containing just the URL path)
    /// Returns a properly formatted absolute URL
    fn location_header_to_url(
        &self,
        image: &Reference,
        location_header: &reqwest::header::HeaderValue,
    ) -> Result<String> {
        let lh = location_header.to_str()?;
        if lh.starts_with("/") {
            let registry = image.resolve_registry();
            Ok(format!(
                "{scheme}://{registry}{lh}",
                scheme = self.config.protocol.scheme_for(registry)
            ))
        } else {
            Ok(lh.to_string())
        }
    }

    /// Convert a Reference to a v2 manifest URL.
    fn to_v2_manifest_url(&self, reference: &Reference) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/{repository}/manifests/{reference}{ns}",
            scheme = self.config.protocol.scheme_for(registry),
            repository = reference.repository(),
            reference = if let Some(digest) = reference.digest() {
                digest
            } else {
                reference.tag().unwrap_or("latest")
            },
            ns = reference
                .namespace()
                .map(|ns| format!("?ns={ns}"))
                .unwrap_or_default(),
        )
    }

    /// Convert a Reference to a v2 blob (layer) URL.
    fn to_v2_blob_url(&self, reference: &Reference, digest: &str) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/{repository}/blobs/{digest}{ns}",
            scheme = self.config.protocol.scheme_for(registry),
            repository = reference.repository(),
            ns = reference
                .namespace()
                .map(|ns| format!("?ns={ns}"))
                .unwrap_or_default(),
        )
    }

    /// Convert a Reference to a v2 blob upload URL.
    fn to_v2_blob_upload_url(&self, reference: &Reference) -> String {
        self.to_v2_blob_url(reference, "uploads/")
    }

    fn to_list_tags_url(&self, reference: &Reference) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/{repository}/tags/list{ns}",
            scheme = self.config.protocol.scheme_for(registry),
            repository = reference.repository(),
            ns = reference
                .namespace()
                .map(|ns| format!("?ns={ns}"))
                .unwrap_or_default(),
        )
    }

    fn to_catalog_url(&self, reference: &Reference) -> String {
        let registry = reference.resolve_registry();
        format!(
            "{scheme}://{registry}/v2/_catalog",
            scheme = self.config.protocol.scheme_for(registry),
        )
    }

    /// Convert a Reference to a v2 referrers URL.
    fn to_v2_referrers_url(
        &self,
        reference: &Reference,
        artifact_type: Option<&str>,
    ) -> Result<String> {
        let digest = reference.digest().ok_or_else(|| {
            OciDistributionError::GenericError(Some(
                "Getting referrers for a tag is not supported".into(),
            ))
        })?;

        let registry = reference.resolve_registry();
        let base = format!(
            "{scheme}://{registry}",
            scheme = self.config.protocol.scheme_for(registry),
        );
        let mut url =
            Url::parse(&base).map_err(|e| OciDistributionError::UrlParseError(e.to_string()))?;
        url.path_segments_mut()
            .map_err(|_| {
                OciDistributionError::GenericError(Some(
                    "cannot build referrers URL: base URL is cannot-be-a-base".into(),
                ))
            })?
            .push("v2")
            .extend(reference.repository().split('/'))
            .push("referrers")
            .push(digest);
        if let Some(at) = artifact_type {
            url.query_pairs_mut().append_pair("artifactType", at);
        }
        Ok(url.into())
    }
}

/// Parses the inclusive end offset out of an upload-progress `Range` header.
///
/// Registries answer a chunk `PATCH` with the range they have stored so far,
/// counted from byte 0 of the blob — `0-1023`, and with the optional unit prefix
/// `bytes=0-1023`. Anything else (a missing start, a non-numeric end, a start
/// other than 0) yields `None`, which the caller reads as "the registry did not
/// report progress" rather than as a disagreement.
fn parse_range_end(header: &reqwest::header::HeaderValue) -> Option<usize> {
    let value = header.to_str().ok()?.trim();
    let value = value.strip_prefix("bytes=").unwrap_or(value);
    let (start, end) = value.split_once('-')?;
    (start.trim() == "0").then_some(())?;
    end.trim().parse().ok()
}

/// The OCI spec technically does not allow any codes but 200, 500, 401, and 404.
/// Obviously, HTTP servers are going to send other codes. This tries to catch the
/// obvious ones (200, 4XX, 5XX). Anything else is just treated as an error.
/// Byte ceiling on a referrers index response.
///
/// Nothing in the distribution spec bounds this body: its length is a function
/// of how many artifacts the registry claims refer to the subject. 4 MiB is far
/// above any real index and far below a memory-pressure event.
const MAX_REFERRERS_INDEX_BYTES: u64 = 4 * 1024 * 1024;

/// Descriptor-count ceiling on a referrers index.
const MAX_REFERRERS_DESCRIPTORS: usize = 4096;

/// Read a response body, refusing anything past `limit` bytes.
///
/// `Response::bytes` buffers whatever the peer sends, so it is not usable on a
/// registry-controlled body with no protocol-level length bound. The declared
/// `Content-Length` is treated as a hint worth refusing early on, never as the
/// bound — the bound is the bytes actually counted through the stream.
async fn read_body_bounded(response: Response, url: &str, limit: u64) -> Result<Vec<u8>> {
    let too_large = || OciDistributionError::ResponseTooLargeError {
        url: url.to_string(),
        limit,
    };

    if let Some(declared) = response.content_length() {
        if declared > limit {
            return Err(too_large());
        }
    }

    // Sized from the hint only after it has been clamped, so a hostile
    // Content-Length cannot drive the allocation.
    let hint = response.content_length().unwrap_or(0).min(limit);
    let mut body = Vec::with_capacity(hint as usize);
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() as u64 + chunk.len() as u64 > limit {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Query parameter names whose value is a credential in every scheme that uses
/// them — presigned S3/GCS/Azure URLs and the registry token exchange.
const REDACTED_QUERY_PARAMS: &[&str] = &[
    "x-amz-signature",
    "x-amz-credential",
    "signature",
    "sig",
    "token",
    "access_token",
];

/// A URL safe to print, with userinfo dropped and signed-query values masked.
///
/// A redirect target is chosen by the registry, so anything displayed from it
/// is attacker-influenced: a blob redirect to presigned storage carries its
/// signature in the query, and a proxy can send credentials in userinfo. Both
/// end up in an error message a user pastes into a bug report. Parameter names
/// survive, because knowing a request was signed is the diagnosis.
fn redacted_display_url(url: &Url) -> String {
    redact_url(url).to_string()
}

/// [`redacted_display_url`] as a `Url`, for the places that must store one
/// rather than print it — notably `From<reqwest::Error>`, which rewrites the
/// URL reqwest attached so that every renderer sees the redacted form.
pub(crate) fn redact_url(url: &Url) -> Url {
    let mut url = url.clone();
    // Both fail only for a cannot-be-a-base URL, which has no userinfo to strip.
    let _ = url.set_username(""); // redaction: nothing to strip on an opaque URL
    let _ = url.set_password(None); // redaction: same

    if url.query().is_some() {
        let masked: Vec<(String, String)> = url
            .query_pairs()
            .map(|(name, value)| {
                let value = if REDACTED_QUERY_PARAMS
                    .iter()
                    .any(|candidate| name.eq_ignore_ascii_case(candidate))
                {
                    "***".to_string()
                } else {
                    value.into_owned()
                };
                (name.into_owned(), value)
            })
            .collect();
        url.query_pairs_mut().clear().extend_pairs(masked);
    }
    url
}

/// [`redacted_display_url`] for a value that has not been parsed yet.
///
/// A string no URL parser accepts has no structure to redact and is returned
/// as-is: it is what the operator needs to see to diagnose the refusal.
fn redacted_display_str(url: &str) -> String {
    match Url::parse(url) {
        Ok(parsed) => redacted_display_url(&parsed),
        Err(_) => url.to_string(),
    }
}

/// `host[:port]` as a registry name is spelled, or `None` for a URL with no
/// host (`file:`, `data:`, and other cannot-be-a-base forms).
///
/// The default port is omitted, matching `Url`'s own normalization, so
/// `https://reg:443` and `https://reg` yield the same name.
fn url_authority(url: &Url) -> Option<String> {
    let host = url.host_str()?;
    Some(match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    })
}

/// Refuses a manifest response whose declared type cannot be a manifest.
///
/// Runs on manifest GET paths only — a blob carries arbitrary content, and a
/// HEAD answer carries no body to mistype. Registries legitimately omit the
/// header, and the digest check still covers those bytes, so an absent header
/// is admitted; anything present must be JSON.
fn validate_manifest_content_type(headers: &HeaderMap, url: &str) -> Result<()> {
    let Some(value) = headers.get(reqwest::header::CONTENT_TYPE) else {
        return Ok(());
    };
    let declared = String::from_utf8_lossy(value.as_bytes()).into_owned();
    let essence = declared
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    if essence == "application/json" || essence.ends_with("+json") {
        return Ok(());
    }
    Err(OciDistributionError::UnexpectedContentType {
        content_type: declared,
        url: url.to_string(),
    })
}

fn validate_registry_response(status: reqwest::StatusCode, body: &[u8], url: &str) -> Result<()> {
    match status {
        reqwest::StatusCode::OK => Ok(()),
        reqwest::StatusCode::UNAUTHORIZED => Err(OciDistributionError::UnauthorizedError {
            url: url.to_string(),
        }),
        s if s.is_success() => Err(OciDistributionError::SpecViolationError(format!(
            "Expected HTTP Status {}, got {} instead",
            reqwest::StatusCode::OK,
            status,
        ))),
        s if s.is_client_error() => {
            match serde_json::from_slice::<OciEnvelope>(body) {
                // According to the OCI spec, we should see an error in the message body.
                Ok(envelope) => Err(OciDistributionError::RegistryError {
                    envelope,
                    url: url.to_string(),
                }),
                // Fall back to a plain server error if the body isn't a valid `OciEnvelope`
                Err(_) => Err(OciDistributionError::ServerError {
                    code: s.as_u16(),
                    url: url.to_string(),
                    message: String::from_utf8_lossy(body).to_string(),
                }),
            }
        }
        s => {
            let text = std::str::from_utf8(body)?;

            Err(OciDistributionError::ServerError {
                code: s.as_u16(),
                url: url.to_string(),
                message: text.to_string(),
            })
        }
    }
}

/// Returns an empty OCI Image Index, as used when no referrers exist.
fn empty_image_index() -> OciImageIndex {
    OciImageIndex {
        schema_version: 2,
        media_type: Some(crate::manifest::OCI_IMAGE_INDEX_MEDIA_TYPE.to_string()),
        artifact_type: None,
        annotations: None,
        manifests: vec![],
    }
}

/// Converts a response into a stream
async fn stream_from_response(
    response: Response,
    layer: impl AsLayerDescriptor,
    verify: bool,
) -> Result<SizedStream> {
    let status = response.status();
    let url = response.url().to_string();
    let content_length = response.content_length();
    let headers = response.headers().clone();
    if !status.is_success() {
        let body = response.bytes().await?;
        return Err(validate_registry_response(status, &body, &url).expect_err(
            "validate_registry_response should return an error for non-success status codes",
        ));
    }
    let stream = response.bytes_stream().map_err(std::io::Error::other);

    let expected_layer_digest = layer.as_layer_descriptor().digest.to_string();
    let layer_digester = Digester::new(&expected_layer_digest)?;
    let header_digester_and_digest = match digest_header_value(headers)? {
        // If the digests match, we don't need to do both digesters
        Some(digest) if digest == expected_layer_digest => None,
        Some(digest) => Some((Digester::new(&digest)?, digest)),
        None => None,
    };
    let header_digest = header_digester_and_digest
        .as_ref()
        .map(|(_, digest)| digest.to_owned());
    let stream: BoxStream<'static, std::result::Result<bytes::Bytes, std::io::Error>> = if verify {
        Box::pin(VerifyingStream::new(
            Box::pin(stream),
            layer_digester,
            expected_layer_digest,
            header_digester_and_digest,
        ))
    } else {
        Box::pin(stream)
    };
    Ok(SizedStream {
        content_length,
        digest_header_value: header_digest,
        stream,
    })
}

/// A cheaply-clonable handle to one shared, pinned [`AsyncRead`].
///
/// Consecutive chunk bodies in a streamed chunked push must each be an owned,
/// `'static` request body, yet resume reading exactly where the previous chunk
/// stopped. Each chunk gets a `SharedReader` clone (an `Arc` bump) wrapped in
/// [`AsyncReadExt::take`] so it reads at most `chunk_len` bytes from the one
/// underlying reader. Chunks are streamed strictly one at a time, so the mutex is
/// never actually contended; it exists only to satisfy `Send + 'static` on the
/// request body. The guard is held only across a single non-`async` `poll_read`,
/// never across an `.await`.
#[derive(Clone)]
struct SharedReader(Arc<std::sync::Mutex<Pin<Box<dyn AsyncRead + Send>>>>);

impl SharedReader {
    fn new<R: AsyncRead + Send + 'static>(reader: R) -> Self {
        SharedReader(Arc::new(std::sync::Mutex::new(Box::pin(reader))))
    }
}

impl AsyncRead for SharedReader {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        // Recover from a poisoned lock rather than panic across the `AsyncRead`
        // boundary: poisoning means a wrapped reader panicked mid-poll, but the
        // reader value itself is intact, so continue with it.
        let mut reader = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        reader.as_mut().poll_read(cx, buf)
    }
}

/// What [`Client::auth`] reports to its caller: the bearer token, or `None`
/// for Basic credentials, which the caller already holds.
fn bearer_value(token: &RegistryTokenType) -> Option<String> {
    match token {
        RegistryTokenType::Bearer(token) => Some(token.token().to_string()),
        RegistryTokenType::Basic(..) => None,
    }
}

/// The request builder wrapper allows to be instantiated from a
/// `Client` and allows composable operations on the request builder,
/// to produce a `RequestBuilder` object that can be executed.
struct RequestBuilderWrapper<'a> {
    client: &'a Client,
    request_builder: RequestBuilder,
}

// RequestBuilderWrapper type management
impl<'a> RequestBuilderWrapper<'a> {
    /// Create a `RequestBuilderWrapper` from a `Client` instance, by
    /// instantiating the internal `RequestBuilder` with the provided
    /// function `f`.
    fn from_client(
        client: &'a Client,
        f: impl Fn(&reqwest::Client) -> RequestBuilder,
    ) -> RequestBuilderWrapper<'a> {
        let request_builder = f(&client.client);
        RequestBuilderWrapper {
            client,
            request_builder,
        }
    }

    /// Like [`from_client`], but on a client that never follows redirects.
    ///
    /// For the whole blob-upload flow — the `POST` that opens or mounts a
    /// session, and every request addressed to the session URL it hands back.
    ///
    /// On the session URL the reason is that `require_same_registry` vets the
    /// `Location` *string*: a followed 3xx is a second registry-chosen target
    /// the string check never saw, and reqwest replays the request there, blob
    /// body included, with only the credential stripped. Refusing to follow is
    /// what makes the origin check hold for more than one hop.
    ///
    /// On the opening `POST` there is no `Location` yet, and that is precisely
    /// the gap: the URL is minted from the `Reference`, so nothing about it is
    /// registry-chosen, but a `3xx` relocates the request itself before any
    /// check exists to run. A plaintext registry answering
    /// `307 Location: http://169.254.169.254/…` gets a `POST` to an address the
    /// caller never named (CWE-918). Credentials are not the exposure — reqwest
    /// strips them cross-origin — the reachability is.
    ///
    /// Either way the 3xx surfaces as a status, which `extract_location_header`
    /// reports as a `ServerError`. The spec permits a redirect on any endpoint,
    /// but in practice registries use it for blob `GET`s handing off to storage;
    /// on this endpoint the 202's own `Location` is the designed channel for
    /// exactly that, so a 3xx here is redundant with it.
    fn from_client_no_redirect(
        client: &'a Client,
        f: impl Fn(&reqwest::Client) -> RequestBuilder,
    ) -> RequestBuilderWrapper<'a> {
        let request_builder = f(&client.no_redirect_client);
        RequestBuilderWrapper {
            client,
            request_builder,
        }
    }

    // Produces a final `RequestBuilder` out of this `RequestBuilderWrapper`
    fn into_request_builder(self) -> RequestBuilder {
        self.request_builder
    }
}

// Composable functions applicable to a `RequestBuilderWrapper`
impl<'a> RequestBuilderWrapper<'a> {
    fn apply_accept(&self, accept: &[&str]) -> Result<RequestBuilderWrapper<'_>> {
        let request_builder = self
            .request_builder
            .try_clone()
            .ok_or_else(|| {
                OciDistributionError::GenericError(Some(
                    "could not clone request builder".to_string(),
                ))
            })?
            .header("Accept", Vec::from(accept).join(", "));

        Ok(RequestBuilderWrapper {
            client: self.client,
            request_builder,
        })
    }

    /// Updates request as necessary for authentication.
    ///
    /// If the struct has Some(bearer), this will insert the bearer token in an
    /// Authorization header. It will also set the Accept header, which must
    /// be set on all OCI Registry requests. If the struct has HTTP Basic Auth
    /// credentials, these will be configured.
    async fn apply_auth(
        &self,
        image: &Reference,
        op: RegistryOperation,
    ) -> Result<RequestBuilderWrapper<'_>> {
        let mut headers = HeaderMap::new();

        if let Some(token) = self.client.get_auth_token(image, op).await {
            match token {
                RegistryTokenType::Bearer(token) => {
                    debug!("Using bearer token authentication.");
                    headers.insert("Authorization", token.bearer_token().parse().unwrap());
                }
                RegistryTokenType::Basic(username, password) => {
                    debug!("Using HTTP basic authentication.");
                    return Ok(RequestBuilderWrapper {
                        client: self.client,
                        request_builder: self
                            .request_builder
                            .try_clone()
                            .ok_or_else(|| {
                                OciDistributionError::GenericError(Some(
                                    "could not clone request builder".to_string(),
                                ))
                            })?
                            .headers(headers)
                            .basic_auth(username.to_string(), Some(password.to_string())),
                    });
                }
            }
        }
        Ok(RequestBuilderWrapper {
            client: self.client,
            request_builder: self
                .request_builder
                .try_clone()
                .ok_or_else(|| {
                    OciDistributionError::GenericError(Some(
                        "could not clone request builder".to_string(),
                    ))
                })?
                .headers(headers),
        })
    }

    /// Applies auth, sends, and on a `401` carrying a challenge refreshes the
    /// token and retries **once**.
    ///
    /// The compensating control for a cached token that aged out between the
    /// cache's renewal margin and what the registry actually honours: the
    /// margin makes that window small, this makes falling into it survivable.
    /// A second consecutive `401` is returned as it stands — an authentication
    /// failure, not a retry loop.
    ///
    /// Scoped to the request builders that carry no body, which is every read
    /// path here: the retry re-sends by cloning the builder, and a streaming
    /// body cannot be cloned.
    async fn send_authed(&self, image: &Reference, op: RegistryOperation) -> Result<Response> {
        let res = self
            .apply_auth(image, op)
            .await?
            .into_request_builder()
            .send()
            .await?;
        if res.status() != StatusCode::UNAUTHORIZED {
            return Ok(res);
        }
        let Some(header) = res.headers().get(reqwest::header::WWW_AUTHENTICATE) else {
            // A `401` with nothing to act on: no challenge to re-derive and no
            // scope to re-request, so a retry would send the same request again.
            return Ok(res);
        };

        // Drop the rejected scope's token, and only that one. A registry that
        // has *revoked* a token commonly refuses it with a plain `Bearer`
        // challenge and no `error` parameter, so this response cannot tell a
        // refused scope from a dead credential — but nor is that a reason to
        // charge every other scope under the host a fresh token exchange on
        // the guess.
        //
        // The wide purge is deferred, not abandoned: the retry below is the
        // experiment that separates the two cases, and a `401` that survives a
        // freshly minted token escalates to `purge_registry`.
        //
        // So this narrows the *recovered* case only, and deliberately claims no
        // more. A repository that is **persistently** forbidden answers the
        // retry with a second `401` (`insufficient_scope`), the escalation
        // fires, and every other scope under the host re-mints after all — one
        // round-trip later than before, never more. What it buys is that a
        // transient rejection, which is the common one, no longer charges a
        // 512-wide fan-out for a token exchange each. Gating the escalation on
        // the challenge's `error` parameter would close the persistent case
        // too; that is a separate decision, not an oversight here.
        //
        // The cached *challenge* is dropped unconditionally and reseeded from
        // this rejection's own header — it is a realm, not a credential, and
        // refreshing it from the live response is what stops a cached probe
        // suppressing a legitimate later `401`.
        let registry = image.resolve_registry();
        let challenge = BearerChallenge::try_from(header).ok();
        self.client.challenges.purge(registry);
        self.client.tokens.purge_scope(image, op).await;
        if let Some(challenge) = challenge {
            // The rejection carried the challenge the retry needs, so seed it
            // rather than paying a `GET /v2/` to ask the host for it again.
            self.client
                .challenges
                .seed(registry, ChallengeInfo::Bearer(challenge));
        }

        let Some(authentication) = self.client.auth_store.read().await.get(registry).cloned()
        else {
            // Nothing was ever stored for this registry, so the request went out
            // anonymous and re-authenticating would change nothing.
            return Ok(res);
        };
        debug!(%registry, "Re-authenticating after a 401 and retrying once");
        self.client.auth(image, &authentication, op).await?;
        let retried = self
            .apply_auth(image, op)
            .await?
            .into_request_builder()
            .send()
            .await?;
        if retried.status() == StatusCode::UNAUTHORIZED {
            // A token minted seconds ago was refused too, so what is dead is
            // the credential behind every scope under this host, not the one
            // scope that was rejected — containerd's `invalidAuthorization`.
            // Purging now stops a sibling repository sending a token minted
            // from the same credential until it expires.
            //
            // Terminal all the same: this response is returned as it stands.
            self.client.tokens.purge_registry(registry).await;
        }
        Ok(retried)
    }
}

/// The encoding of the certificate
#[derive(Debug, Clone)]
pub enum CertificateEncoding {
    #[allow(missing_docs)]
    Der,
    #[allow(missing_docs)]
    Pem,
}

/// A x509 certificate
#[derive(Debug, Clone)]
pub struct Certificate {
    /// Which encoding is used by the certificate
    pub encoding: CertificateEncoding,

    /// Actual certificate
    pub data: Vec<u8>,
}

impl TryFrom<&Certificate> for reqwest::Certificate {
    type Error = OciDistributionError;

    fn try_from(cert: &Certificate) -> Result<Self> {
        match cert.encoding {
            CertificateEncoding::Der => Ok(reqwest::Certificate::from_der(cert.data.as_slice())?),
            CertificateEncoding::Pem => Ok(reqwest::Certificate::from_pem(cert.data.as_slice())?),
        }
    }
}

fn convert_certificates(certs: &[Certificate]) -> Result<Vec<reqwest::Certificate>> {
    certs.iter().map(reqwest::Certificate::try_from).collect()
}

/// A client configuration
pub struct ClientConfig {
    /// Which protocol the client should use
    pub protocol: ClientProtocol,

    /// Accept invalid hostname. Defaults to false
    #[cfg(feature = "native-tls")]
    pub accept_invalid_hostnames: bool,

    /// Accept invalid certificates. Defaults to false
    pub accept_invalid_certificates: bool,

    /// Use monolithic push for pushing blobs. Defaults to false
    pub use_monolithic_push: bool,

    /// Use only the provided certificate roots.
    ///
    /// This option disables any native or built-in roots, and **only** uses
    /// the roots provided to this method.
    pub tls_certs_only: Vec<Certificate>,

    /// A list of extra root certificate to trust. This can be used to connect
    /// to servers using self-signed certificates
    pub extra_root_certificates: Vec<Certificate>,

    /// A function that defines the client's behaviour if an Image Index Manifest
    /// (i.e Manifest List) is encountered when pulling an image.
    /// Defaults to [current_platform_resolver],
    /// which attempts to choose an image matching the running OS and Arch.
    ///
    /// If set to None, an error is raised if an Image Index manifest is received
    /// during an image pull.
    pub platform_resolver: Option<Box<PlatformResolverFn>>,

    /// An optional custom DNS resolver, injected into the underlying
    /// `reqwest::Client` at build time. When set, every connection resolves host
    /// names through it, and reqwest connects only to the addresses it returns.
    /// This is the seam a caller uses to pin an externally-validated address at
    /// connect time (e.g. an SSRF resolve -> validate -> pin guard). Defaults to
    /// `None`, which keeps reqwest's built-in resolver.
    pub dns_resolver: Option<std::sync::Arc<dyn reqwest::dns::Resolve>>,

    /// Maximum chunk size in bytes used to perform a `push` operation.
    ///
    /// This defaults to [`DEFAULT_PUSH_CHUNK_SIZE`].
    pub push_chunk_size: usize,

    /// Maximum number of concurrent uploads to perform during a `push`
    /// operation.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_UPLOAD`].
    pub max_concurrent_upload: usize,

    /// Maximum number of concurrent downloads to perform during a `pull`
    /// operation.
    ///
    /// This defaults to [`DEFAULT_MAX_CONCURRENT_DOWNLOAD`].
    pub max_concurrent_download: usize,

    /// Default token expiration in seconds, to use when the token claim
    /// doesn't provide a value.
    ///
    /// This defaults to [`DEFAULT_TOKEN_EXPIRATION_SECS`].
    pub default_token_expiration_secs: usize,

    /// Enables a read timeout for the client.
    ///
    /// See [`reqwest::ClientBuilder::read_timeout`] for more information.
    pub read_timeout: Option<Duration>,

    /// Set a timeout for the connect phase for the client.
    ///
    /// See [`reqwest::ClientBuilder::connect_timeout`] for more information.
    pub connect_timeout: Option<Duration>,

    /// Set the `User-Agent` used by the client.
    ///
    /// This defaults to `oci-client/<version>` where `<version>` is the crate version.
    pub user_agent: &'static str,

    /// Set the `HTTPS PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub https_proxy: Option<String>,

    /// Set the `HTTP PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub http_proxy: Option<String>,

    /// Set the `NO PROXY` used by the client.
    ///
    /// This defaults to `None`.
    pub no_proxy: Option<String>,
}

/// Mozilla's CA root set, compiled into the binary and DER-encoded.
///
/// Seeded into every `ClientConfig::default().extra_root_certificates` so the
/// client is self-contained on a host with no system trust store. Under
/// reqwest 0.13 the `rustls` path delegates trust to `rustls-platform-verifier`,
/// which — with an *empty* root set — loads roots only from the system store and
/// hard-errors (`No CA certificates were loaded from the system`) when that store
/// is empty. `Client::new` then "falls back" to `reqwest::Client::default()`,
/// whose internal `.expect()` re-triggers the identical failure as a panic.
/// A non-empty root set forces reqwest onto the `Verifier::new_with_extra_roots`
/// branch, which never errors on an empty store and still *merges* whatever the
/// native store provides (e.g. a corporate root via `SSL_CERT_FILE`).
fn bundled_root_certificates() -> Vec<Certificate> {
    webpki_root_certs::TLS_SERVER_ROOT_CERTS
        .iter()
        .map(|cert| Certificate {
            encoding: CertificateEncoding::Der,
            data: cert.as_ref().to_vec(),
        })
        .collect()
}

/// `reqwest::Client` seeded with the bundled Mozilla roots — the panic-free
/// replacement for `reqwest::Client::default()` in `Client::default()`.
///
/// `reqwest::Client::default()` hard-panics on a host with no system trust
/// store: reqwest's rustls path takes `Verifier::new`, which errors on an empty
/// store, and `Client::new` `.expect()`s the build. Because `Client::default()`
/// is what every `..Default::default()` tail constructs to fill `auth_store`,
/// that panic fires even when the real, seeded client built alongside it is
/// fine. Seeding the bundled roots takes the `Verifier::new_with_extra_roots`
/// path, which never errors on an empty store and still merges the native store
/// (`SSL_CERT_FILE` / `SSL_CERT_DIR`) on top.
fn default_seeded_client(redirect: impl Fn() -> reqwest::redirect::Policy) -> reqwest::Client {
    // A factory rather than a `Policy`, which is not `Clone`: every builder
    // below mints its own, so the roots are the only thing that can degrade.
    let with_policy = || reqwest::Client::builder().redirect(redirect());
    match convert_certificates(&bundled_root_certificates()) {
        Ok(certs) => with_policy().tls_certs_merge(certs).build(),
        // ponytail: the bundled roots are a compiled-in constant, so a
        // conversion failure means there is no other set to reach for.
        Err(_) => with_policy().build(),
    }
    // Retry without the roots rather than falling straight through: the roots
    // are the only input here a build can plausibly reject, and dropping them
    // keeps the redirect policy that `unwrap_or_default` below would not.
    .or_else(|_| with_policy().build())
    // ponytail: this last resort IS policy-free — `reqwest::Client::default()`
    // is a stock client that follows redirects. Nothing better exists: a
    // `reqwest::Client` is only reachable through a builder, so a builder that
    // refuses twice leaves this or a panic, and `Client::default()` panics
    // anyway on the one host where a seeded build could plausibly fail (no
    // system trust store). Named rather than claimed away — no test can reach
    // it, because no input available here makes `build()` fail.
    .unwrap_or_default()
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            protocol: ClientProtocol::default(),
            #[cfg(feature = "native-tls")]
            accept_invalid_hostnames: false,
            accept_invalid_certificates: false,
            use_monolithic_push: false,
            tls_certs_only: Vec::new(),
            extra_root_certificates: bundled_root_certificates(),
            platform_resolver: Some(Box::new(current_platform_resolver)),
            dns_resolver: None,
            push_chunk_size: DEFAULT_PUSH_CHUNK_SIZE,
            max_concurrent_upload: DEFAULT_MAX_CONCURRENT_UPLOAD,
            max_concurrent_download: DEFAULT_MAX_CONCURRENT_DOWNLOAD,
            default_token_expiration_secs: DEFAULT_TOKEN_EXPIRATION_SECS,
            read_timeout: None,
            connect_timeout: None,
            user_agent: DEFAULT_USER_AGENT,
            https_proxy: None,
            http_proxy: None,
            no_proxy: None,
        }
    }
}

// Be explicit about the traits supported by this type. This is needed to use
// the Client behind a dynamic reference.
// Something similar to what is described here: https://users.rust-lang.org/t/how-to-send-function-closure-to-another-thread/43549
type PlatformResolverFn = dyn Fn(&[ImageIndexEntry]) -> Option<String> + Send + Sync;

/// A platform resolver that chooses the first linux/amd64 variant, if present
pub fn linux_amd64_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os == Os::Linux && platform.architecture == Arch::Amd64
            })
        })
        .map(|entry| entry.digest.clone())
}

/// A platform resolver that chooses the first windows/amd64 variant, if present
pub fn windows_amd64_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os == Os::Windows && platform.architecture == Arch::Amd64
            })
        })
        .map(|entry| entry.digest.clone())
}

/// A platform resolver that chooses the first variant matching the running OS/Arch, if present.
/// Doesn't currently handle platform.variants.
pub fn current_platform_resolver(manifests: &[ImageIndexEntry]) -> Option<String> {
    manifests
        .iter()
        .find(|entry| {
            entry.platform.as_ref().is_some_and(|platform| {
                platform.os == Os::default() && platform.architecture == Arch::default()
            })
        })
        .map(|entry| entry.digest.clone())
}

/// The protocol that the client should use to connect
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub enum ClientProtocol {
    #[allow(missing_docs)]
    Http,
    #[allow(missing_docs)]
    #[default]
    Https,
    #[allow(missing_docs)]
    HttpsExcept(Vec<String>),
}

impl ClientProtocol {
    fn scheme_for(&self, registry: &str) -> &str {
        match self {
            ClientProtocol::Https => "https",
            ClientProtocol::Http => "http",
            ClientProtocol::HttpsExcept(exceptions) => {
                if exceptions.contains(&registry.to_owned()) {
                    "http"
                } else {
                    "https"
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct BearerChallenge {
    pub realm: Box<str>,
    pub service: Option<String>,
}

impl TryFrom<&HeaderValue> for BearerChallenge {
    type Error = String;

    fn try_from(value: &HeaderValue) -> std::result::Result<Self, Self::Error> {
        let parser = ChallengeParser::new(
            value
                .to_str()
                .map_err(|e| format!("cannot convert header value to string: {e:?}"))?,
        );
        parser
            .filter_map(|parser_res| {
                if let Ok(chalenge_ref) = parser_res {
                    let bearer_challenge = BearerChallenge::try_from(&chalenge_ref);
                    bearer_challenge.ok()
                } else {
                    None
                }
            })
            .next()
            .ok_or_else(|| "Cannot find Bearer challenge".to_string())
    }
}

impl TryFrom<&ChallengeRef<'_>> for BearerChallenge {
    type Error = String;

    fn try_from(value: &ChallengeRef<'_>) -> std::result::Result<Self, Self::Error> {
        if !value.scheme.eq_ignore_ascii_case("Bearer") {
            return Err(format!(
                "BearerChallenge doesn't support challenge scheme {:?}",
                value.scheme
            ));
        }
        let mut realm = None;
        let mut service = None;
        for (k, v) in &value.params {
            if k.eq_ignore_ascii_case("realm") {
                realm = Some(v.to_unescaped());
            }

            if k.eq_ignore_ascii_case("service") {
                service = Some(v.to_unescaped());
            }
        }

        let realm = realm.ok_or("missing required parameter realm")?;

        Ok(BearerChallenge {
            realm: realm.into_boxed_str(),
            service,
        })
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::convert::TryFrom;
    use std::fs;
    use std::path;
    use std::result::Result;

    use bytes::Bytes;
    use rstest::rstest;

    /// Regression: every default-constructed `ClientConfig` ships the full
    /// bundled Mozilla CA root set, so a client built on a host with no system
    /// trust store never hits the empty-store `Verifier::new` panic. This covers
    /// every direct construction (`ClientConfig::default()`, `..Default::default()`),
    /// including callers that bypass a higher-level builder.
    #[test]
    fn default_config_seeds_bundled_ca_roots() {
        let config = ClientConfig::default();
        assert_eq!(
            config.extra_root_certificates.len(),
            webpki_root_certs::TLS_SERVER_ROOT_CERTS.len(),
            "the full Mozilla root set must be seeded into ClientConfig::default()"
        );
        assert!(
            config.extra_root_certificates.len() > 100,
            "the Mozilla root set should be well over 100 certificates, got {}",
            config.extra_root_certificates.len()
        );
        // Building the client runs `convert_certificates` (DER decode) over every
        // seeded root; reaching this line proves the encoding is valid and the
        // empty-store panic branch is unreachable.
        let _client = Client::try_from(config).expect("client builds with bundled roots");
    }

    /// Regression for the empty-store panic that `default_config_seeds_bundled_ca_roots`
    /// could not catch: it builds on a dev host *with* a system store, so the
    /// `..Default::default()` tail's throwaway `reqwest::Client::default()` never
    /// panicked there. Force an empty system store (`SSL_CERT_FILE` → an empty
    /// file, `SSL_CERT_DIR` → a missing dir) and assert both constructors return
    /// instead of panicking. Fails on the pre-fix code (panics through
    /// `Client::default` → `reqwest::Client::default`).
    #[test]
    fn builds_without_a_system_trust_store() {
        // rustls-native-certs reads these at each `Verifier::new*`; after the fix
        // every construction is seeded, so a concurrent test that also builds a
        // client still succeeds under the same env.
        std::env::set_var("SSL_CERT_FILE", "/dev/null");
        std::env::set_var("SSL_CERT_DIR", "/oci-client-no-such-dir");

        // Direct `..Default::default()` path (the login auth-ping shape).
        let _ = Client::new(ClientConfig::default());
        // The explicit try_from path returns Ok rather than panicking.
        Client::try_from(ClientConfig::default())
            .expect("client builds with no system trust store");
        // `Client::default()` itself must not panic (it backs every fallback).
        let _ = Client::default();

        std::env::remove_var("SSL_CERT_FILE");
        std::env::remove_var("SSL_CERT_DIR");
    }
    use sha2::Digest as _;
    use tempfile::TempDir;
    use tokio::io::AsyncReadExt;
    use tokio_util::io::StreamReader;

    use crate::manifest::{self, IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE};

    #[cfg(feature = "test-registry")]
    use testcontainers::{
        core::{Mount, WaitFor},
        runners::AsyncRunner,
        ContainerRequest, GenericImage, ImageExt,
    };

    const HELLO_IMAGE_NO_TAG: &str = "webassembly.azurecr.io/hello-wasm";
    const HELLO_IMAGE_TAG: &str = "webassembly.azurecr.io/hello-wasm:v1";
    const HELLO_IMAGE_DIGEST: &str = "webassembly.azurecr.io/hello-wasm@sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7";
    const HELLO_IMAGE_TAG_AND_DIGEST: &str = "webassembly.azurecr.io/hello-wasm:v1@sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7";
    const TEST_IMAGES: &[&str] = &[
        // TODO(jlegrone): this image cannot be pulled currently because no `latest`
        //                 tag exists on the image repository. Re-enable this image
        //                 in tests once `latest` is published.
        // HELLO_IMAGE_NO_TAG,
        HELLO_IMAGE_TAG,
        HELLO_IMAGE_DIGEST,
        HELLO_IMAGE_TAG_AND_DIGEST,
    ];
    const GHCR_IO_IMAGE: &str = "ghcr.io/krustlet/oci-distribution/hello-wasm:v1";
    const DOCKER_IO_IMAGE: &str = "docker.io/library/hello-world@sha256:37a0b92b08d4919615c3ee023f7ddb068d12b8387475d64c622ac30f45c29c51";
    const HTPASSWD: &str = "testuser:$2y$05$8/q2bfRcX74EuxGf0qOcSuhWDQJXrgWiy6Fi73/JM2tKC66qSrLve";
    const HTPASSWD_USERNAME: &str = "testuser";
    const HTPASSWD_PASSWORD: &str = "testpassword";

    const EMPTY_JSON_BLOB: &str = "{}";
    const EMPTY_JSON_DIGEST: &str =
        "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a";

    #[test]
    fn test_apply_accept() -> anyhow::Result<()> {
        assert_eq!(
            RequestBuilderWrapper::from_client(&Client::default(), |client| client
                .get("https://example.com/some/module.wasm"))
            .apply_accept(&["*/*"])?
            .into_request_builder()
            .build()?
            .headers()["Accept"],
            "*/*"
        );

        assert_eq!(
            RequestBuilderWrapper::from_client(&Client::default(), |client| client
                .get("https://example.com/some/module.wasm"))
            .apply_accept(MIME_TYPES_DISTRIBUTION_MANIFEST)?
            .into_request_builder()
            .build()?
            .headers()["Accept"],
            MIME_TYPES_DISTRIBUTION_MANIFEST.join(", ")
        );

        Ok(())
    }

    #[tokio::test]
    async fn test_apply_auth_no_token() -> anyhow::Result<()> {
        assert!(
            !RequestBuilderWrapper::from_client(&Client::default(), |client| client
                .get("https://example.com/some/module.wasm"))
            .apply_auth(
                &Reference::try_from(HELLO_IMAGE_TAG)?,
                RegistryOperation::Pull
            )
            .await?
            .into_request_builder()
            .build()?
            .headers()
            .contains_key("Authorization")
        );

        Ok(())
    }

    #[derive(Serialize)]
    struct EmptyClaims {}

    #[tokio::test]
    async fn test_apply_auth_bearer_token() -> anyhow::Result<()> {
        crate::test_helpers::jsonwebtoken_install_default_crypto_provider();
        let _ = tracing_subscriber::fmt::try_init();
        let client = Client::default();
        let header = jsonwebtoken::Header::default();
        let claims = EmptyClaims {};
        let key = jsonwebtoken::EncodingKey::from_secret(b"some-secret");
        let token = jsonwebtoken::encode(&header, &claims, &key)?;

        // we have to have it in the stored auth so we'll get to the token cache check.
        client
            .store_auth(
                Reference::try_from(HELLO_IMAGE_TAG)?.resolve_registry(),
                RegistryAuth::Anonymous,
            )
            .await;

        client
            .tokens
            .insert(
                &Reference::try_from(HELLO_IMAGE_TAG)?,
                RegistryOperation::Pull,
                RegistryTokenType::Bearer(RegistryToken::Token {
                    token: token.clone(),
                }),
            )
            .await;

        assert_eq!(
            RequestBuilderWrapper::from_client(&client, |client| client
                .get("https://example.com/some/module.wasm"))
            .apply_auth(
                &Reference::try_from(HELLO_IMAGE_TAG)?,
                RegistryOperation::Pull
            )
            .await?
            .into_request_builder()
            .build()?
            .headers()["Authorization"],
            format!("Bearer {}", &token)
        );

        Ok(())
    }

    #[test]
    fn scheme_downgrade_is_the_only_refused_redirect() -> anyhow::Result<()> {
        let https = Url::parse("https://registry.example.com:8443/v2/x/blobs/uploads/1")?;
        let plaintext = Url::parse("http://registry.example.com:8443/collect")?;

        // Same host, same port, scheme dropped: reqwest keeps `Authorization`
        // here, which is exactly why this arm exists.
        assert!(is_scheme_downgrade(Some(&https), &plaintext));

        // Everything else keeps working - CDN handoff on the pull path is a
        // cross-host https redirect, and a plain-HTTP registry stays plain.
        for (previous, next) in [
            (
                "https://registry.example.com/v2/x",
                "https://cdn.example.net/blob",
            ),
            (
                "http://registry.example.com/v2/x",
                "http://registry.example.com/other",
            ),
            (
                "http://registry.example.com/v2/x",
                "https://registry.example.com/other",
            ),
        ] {
            let previous = Url::parse(previous)?;
            let next = Url::parse(next)?;
            assert!(
                !is_scheme_downgrade(Some(&previous), &next),
                "{previous} -> {next} must still follow"
            );
        }

        // The first hop has no predecessor to downgrade from.
        assert!(!is_scheme_downgrade(None, &plaintext));

        Ok(())
    }

    /// Every construction path yields a client carrying a redirect policy, the
    /// degradation fallback included.
    ///
    /// `Client::new` warns and falls back to `Default` when `try_from` errors,
    /// and a `ClientConfig` field a caller fills from a user-supplied string —
    /// `https_proxy` here — is enough to reach that arm. With the policy
    /// installed only inside `try_from`, the fallback silently restored
    /// reqwest's default: redirects followed, and the upload path following
    /// them off the registry (CWE-636, fail-open on error).
    ///
    /// Asserted through reqwest's `Debug`, which prints `redirect_policy` only
    /// when the policy is not the default one. It is the only seam reqwest
    /// offers short of a TLS fixture; the failure direction is safe, because a
    /// reqwest that stopped printing the field reds this test rather than
    /// quietly passing it.
    #[test]
    fn no_construction_path_yields_a_client_without_a_redirect_policy() {
        for (label, client) in [
            ("Default", Client::default()),
            (
                "try_from",
                Client::new(ClientConfig {
                    ..Default::default()
                }),
            ),
            (
                // `Proxy::https` rejects this, so `try_from` errors and
                // `Client::new` takes its degradation fallback.
                "degradation fallback",
                Client::new(ClientConfig {
                    https_proxy: Some("not a proxy".to_string()),
                    ..Default::default()
                }),
            ),
        ] {
            let pull = format!("{:?}", client.client);
            assert!(
                pull.contains(r#"redirect_policy: "Policy(Custom)""#),
                "{label}'s pull client lost the no-scheme-downgrade policy: {pull}"
            );
            let upload = format!("{:?}", client.no_redirect_client);
            assert!(
                upload.contains(r#"redirect_policy: "Policy(None)""#),
                "{label}'s upload client would follow a redirect: {upload}"
            );
        }
    }

    /// The refusal names a target the registry chose, so it is subject to the
    /// same disclosure rule as every other registry-supplied URL this crate
    /// prints.
    #[test]
    fn a_refused_downgrade_is_redacted_before_it_is_reported() -> anyhow::Result<()> {
        let target = Url::parse("http://user:hunter2@collector.example.net/x?token=deadbeef")?;
        let message = scheme_downgrade_refusal(&target);

        for secret in ["hunter2", "deadbeef"] {
            assert!(
                !message.contains(secret),
                "the refusal published {secret}: {message}"
            );
        }
        assert!(
            message.contains("collector.example.net"),
            "the refusal dropped the host, leaving nothing to diagnose: {message}"
        );

        Ok(())
    }

    #[test]
    fn plaintext_auth_realm_is_refused_for_an_https_registry() -> anyhow::Result<()> {
        let image = Reference::try_from(HELLO_IMAGE_TAG)?;

        let https = Client::default();
        https.require_secure_realm(&image, "https://auth.example.com/token")?;
        for realm in [
            "http://auth.example.com/token",
            "http://webassembly.azurecr.io/token",
            "not a url",
        ] {
            let err = https
                .require_secure_realm(&image, realm)
                .expect_err("an https registry must not name a plaintext realm");
            assert!(
                matches!(err, OciDistributionError::InsecureAuthRealm { realm: ref r } if r == realm),
                "unexpected error for {realm}: {err:?}"
            );
        }

        // A registry deliberately configured as plaintext may name a plaintext
        // realm on its OWN authority - there is no credential to downgrade that
        // the registry call itself did not already carry - and may upgrade to
        // https at any time.
        let plaintext = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["webassembly.azurecr.io".to_string()]),
            ..Default::default()
        });
        plaintext.require_secure_realm(&image, "http://webassembly.azurecr.io/token")?;
        plaintext.require_secure_realm(&image, "https://auth.example.com/token")?;

        // But it is not a licence to name an ARBITRARY plaintext host. The
        // plaintext declaration admits an on-path attacker on this registry's
        // own traffic; that attacker answering with a realm elsewhere would
        // walk the user's password out to the open internet, which an https
        // realm on the same hostile registry would not have done.
        let err = plaintext
            .require_secure_realm(&image, "http://collector.example.com/token")
            .expect_err("a plaintext registry must not name a foreign plaintext realm");
        assert!(
            matches!(err, OciDistributionError::InsecureAuthRealm { realm: ref r }
                if r == "http://collector.example.com/token"),
            "unexpected error: {err:?}"
        );

        // Unless that host carries its own plain-HTTP allowance - a federated
        // token service inside the same plaintext estate stays reachable.
        let estate = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![
                "webassembly.azurecr.io".to_string(),
                "auth.example.com".to_string(),
            ]),
            ..Default::default()
        });
        estate.require_secure_realm(&image, "http://auth.example.com/token")?;

        // An allowance granted to a DIFFERENT host does not license a plaintext
        // realm for this one.
        let elsewhere = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["other.example.com".to_string()]),
            ..Default::default()
        });
        elsewhere
            .require_secure_realm(&image, "http://auth.example.com/token")
            .expect_err("an unrelated plain-HTTP allowance must not redirect a credential");

        Ok(())
    }

    /// The `401` retry seeds the challenge cache from the rejection's own
    /// `WWW-Authenticate`, which is a second route by which a
    /// registry-controlled realm reaches `_auth` — one that did not exist when
    /// `require_secure_realm` was written, and one no probe-shaped test covers.
    /// A seeded plaintext realm has to be refused exactly like a probed one, or
    /// answering `401` becomes a way to launder a credential past the guard.
    ///
    /// The green half is `plaintext_auth_realm_is_refused_for_an_https_registry`
    /// above: asserting it here would mean letting `_auth` reach a realm.
    #[tokio::test]
    async fn a_seeded_plaintext_realm_is_refused_like_a_probed_one() -> anyhow::Result<()> {
        let client = Client::default();
        let image = Reference::try_from(HELLO_IMAGE_TAG)?;

        // Built the way `send_authed` builds it, from a header a hostile
        // registry could answer with.
        let header = HeaderValue::from_static(
            r#"Bearer realm="http://collector.example.net/token",service="webassembly.azurecr.io""#,
        );
        client.challenges.seed(
            image.resolve_registry(),
            ChallengeInfo::Bearer(BearerChallenge::try_from(&header).expect("a bearer challenge")),
        );

        let err = client
            ._auth(
                &image,
                &RegistryAuth::Basic("user".to_string(), "hunter2".to_string()),
                RegistryOperation::Pull,
            )
            .await
            .expect_err("a seeded plaintext realm must be refused");
        assert!(
            matches!(
                err,
                OciDistributionError::InsecureAuthRealm { ref realm }
                    if realm == "http://collector.example.net/token"
            ),
            "the seeded realm did not reach the guard: {err:?}"
        );

        Ok(())
    }

    #[test]
    fn session_url_off_the_registry_host_is_refused() -> anyhow::Result<()> {
        let client = Client::default();
        let image = Reference::try_from(HELLO_IMAGE_TAG)?;

        client.require_same_registry(
            &image,
            "https://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/abc",
        )?;

        // A registry answering the upload-session POST with a foreign Location,
        // downgrading the scheme on its own host, or naming something that is
        // not an http(s) URL at all, gets no follow-up request - not an
        // unauthenticated one either, since the body and the target host are
        // registry-chosen too.
        for url in [
            "https://evil.example.com/v2/hello-wasm/blobs/uploads/abc",
            "http://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/abc",
            "https://webassembly.azurecr.io:8443/v2/hello-wasm/blobs/uploads/abc",
            "file:///etc/passwd",
            "not a url",
        ] {
            let err = client
                .require_same_registry(&image, url)
                .expect_err("cross-host session URL must be refused");
            assert!(
                matches!(err, OciDistributionError::CrossHostRefused { url: ref u, .. } if u == url),
                "unexpected error for {url}: {err:?}"
            );
        }

        Ok(())
    }

    /// A registry declared plain HTTP that answers with an `https` session URL
    /// on its own authority is upgrading, not handing off, so the origin check
    /// admits it. Every other axis - host, port, and the reverse direction -
    /// stays a mismatch.
    #[test]
    fn a_plaintext_registry_may_upgrade_its_own_session_url() -> anyhow::Result<()> {
        let image = Reference::try_from(HELLO_IMAGE_TAG)?;
        let plaintext = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["webassembly.azurecr.io".to_string()]),
            ..Default::default()
        });

        plaintext.require_same_registry(
            &image,
            "https://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/abc",
        )?;
        plaintext.require_same_registry(
            &image,
            "http://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/abc",
        )?;

        for url in [
            // Upgrading is not a licence to move host or port.
            "https://evil.example.com/v2/hello-wasm/blobs/uploads/abc",
            "https://webassembly.azurecr.io:8443/v2/hello-wasm/blobs/uploads/abc",
        ] {
            plaintext
                .require_same_registry(&image, url)
                .expect_err("the upgrade allowance must not widen host or port");
        }

        // The reverse direction is the hazard and stays refused: an https
        // registry naming an http URL on its own host is a downgrade.
        Client::default()
            .require_same_registry(
                &image,
                "http://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/abc",
            )
            .expect_err("a downgrade on the registry's own host must stay a mismatch");

        Ok(())
    }

    /// A registry-chosen URL reaches the user's terminal - a CI job log in the
    /// common case - so the refusal must not be the thing that publishes the
    /// presigned signature the refusal exists to protect.
    #[test]
    fn a_refused_session_url_is_redacted_before_it_is_reported() -> anyhow::Result<()> {
        let client = Client::default();
        let image = Reference::try_from(HELLO_IMAGE_TAG)?;

        let err = client
            .require_same_registry(
                &image,
                "https://user:hunter2@bucket.s3.example/upload?X-Amz-Signature=deadbeef&partNumber=3",
            )
            .expect_err("a foreign session URL must be refused");

        let rendered = err.to_string();
        for secret in ["hunter2", "deadbeef"] {
            assert!(
                !rendered.contains(secret),
                "the refusal published {secret}: {rendered}"
            );
        }
        // Diagnosis survives redaction: the host and the parameter names stay.
        for kept in ["bucket.s3.example", "X-Amz-Signature", "partNumber=3"] {
            assert!(
                rendered.contains(kept),
                "the refusal dropped {kept}, leaving nothing to diagnose: {rendered}"
            );
        }

        Ok(())
    }

    #[test]
    fn test_to_v2_blob_url() {
        let mut image = Reference::try_from(HELLO_IMAGE_TAG).expect("failed to parse reference");
        let c = Client::default();

        assert_eq!(
            c.to_v2_blob_url(&image, "sha256:deadbeef"),
            "https://webassembly.azurecr.io/v2/hello-wasm/blobs/sha256:deadbeef"
        );

        image.set_mirror_registry("docker.mirror.io".to_owned());
        assert_eq!(
            c.to_v2_blob_url(&image, "sha256:deadbeef"),
            "https://docker.mirror.io/v2/hello-wasm/blobs/sha256:deadbeef?ns=webassembly.azurecr.io"
        );
    }

    #[rstest(image, expected_uri, expected_mirror_uri,
        case(HELLO_IMAGE_NO_TAG, "https://webassembly.azurecr.io/v2/hello-wasm/manifests/latest", "https://docker.mirror.io/v2/hello-wasm/manifests/latest?ns=webassembly.azurecr.io"), // TODO: confirm this is the right translation when no tag
        case(HELLO_IMAGE_TAG, "https://webassembly.azurecr.io/v2/hello-wasm/manifests/v1", "https://docker.mirror.io/v2/hello-wasm/manifests/v1?ns=webassembly.azurecr.io"),
        case(HELLO_IMAGE_DIGEST, "https://webassembly.azurecr.io/v2/hello-wasm/manifests/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7", "https://docker.mirror.io/v2/hello-wasm/manifests/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7?ns=webassembly.azurecr.io"),
        case(HELLO_IMAGE_TAG_AND_DIGEST, "https://webassembly.azurecr.io/v2/hello-wasm/manifests/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7", "https://docker.mirror.io/v2/hello-wasm/manifests/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7?ns=webassembly.azurecr.io"),
    )]
    fn test_to_v2_manifest(image: &str, expected_uri: &str, expected_mirror_uri: &str) {
        let mut reference = Reference::try_from(image).expect("failed to parse reference");
        let c = Client::default();
        assert_eq!(c.to_v2_manifest_url(&reference), expected_uri);

        reference.set_mirror_registry("docker.mirror.io".to_owned());
        assert_eq!(c.to_v2_manifest_url(&reference), expected_mirror_uri);
    }

    #[test]
    fn test_to_v2_blob_upload_url() {
        let image = Reference::try_from(HELLO_IMAGE_TAG).expect("failed to parse reference");
        let blob_url = Client::default().to_v2_blob_upload_url(&image);

        assert_eq!(
            blob_url,
            "https://webassembly.azurecr.io/v2/hello-wasm/blobs/uploads/"
        )
    }

    #[test]
    fn test_to_list_tags_url() {
        let mut image = Reference::try_from(HELLO_IMAGE_TAG).expect("failed to parse reference");
        let c = Client::default();

        assert_eq!(
            c.to_list_tags_url(&image),
            "https://webassembly.azurecr.io/v2/hello-wasm/tags/list"
        );

        image.set_mirror_registry("docker.mirror.io".to_owned());
        assert_eq!(
            c.to_list_tags_url(&image),
            "https://docker.mirror.io/v2/hello-wasm/tags/list?ns=webassembly.azurecr.io"
        );
    }

    #[test]
    fn test_to_catalog_url() {
        let mut image = Reference::try_from(HELLO_IMAGE_TAG).expect("failed to parse reference");
        let c = Client::default();

        assert_eq!(
            c.to_catalog_url(&image),
            "https://webassembly.azurecr.io/v2/_catalog"
        );

        image.set_mirror_registry("docker.mirror.io".to_owned());
        assert_eq!(
            c.to_catalog_url(&image),
            "https://docker.mirror.io/v2/_catalog"
        );
    }

    #[test]
    fn test_to_v2_referrers_url() {
        let image = Reference::try_from(HELLO_IMAGE_DIGEST).expect("failed to parse reference");
        let c = Client::default();

        // No filter: no query string.
        assert_eq!(
            c.to_v2_referrers_url(&image, None).unwrap(),
            "https://webassembly.azurecr.io/v2/hello-wasm/referrers/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7"
        );

        // With filter: the artifactType value is percent-encoded. The `+` in `+json`
        // media types must become `%2B`, otherwise standard query-string decoding turns
        // it into a space and the registry filter matches nothing.
        assert_eq!(
            c.to_v2_referrers_url(&image, Some("application/spdx+json")).unwrap(),
            "https://webassembly.azurecr.io/v2/hello-wasm/referrers/sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7?artifactType=application%2Fspdx%2Bjson"
        );
    }

    #[test]
    fn manifest_url_generation_respects_http_protocol() {
        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        let reference = Reference::try_from("webassembly.azurecr.io/hello:v1".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "http://webassembly.azurecr.io/v2/hello/manifests/v1",
            c.to_v2_manifest_url(&reference)
        );
    }

    #[test]
    fn blob_url_generation_respects_http_protocol() {
        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        let reference = Reference::try_from("webassembly.azurecr.io/hello@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "http://webassembly.azurecr.io/v2/hello/blobs/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            c.to_v2_blob_url(&reference, reference.digest().unwrap())
        );
    }

    #[test]
    fn manifest_url_generation_uses_https_if_not_on_exception_list() {
        let insecure_registries = vec!["localhost".to_owned(), "oci.registry.local".to_owned()];
        let protocol = ClientProtocol::HttpsExcept(insecure_registries);
        let c = Client::new(ClientConfig {
            protocol,
            ..Default::default()
        });
        let reference = Reference::try_from("webassembly.azurecr.io/hello:v1".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "https://webassembly.azurecr.io/v2/hello/manifests/v1",
            c.to_v2_manifest_url(&reference)
        );
    }

    #[test]
    fn manifest_url_generation_uses_http_if_on_exception_list() {
        let insecure_registries = vec!["localhost".to_owned(), "oci.registry.local".to_owned()];
        let protocol = ClientProtocol::HttpsExcept(insecure_registries);
        let c = Client::new(ClientConfig {
            protocol,
            ..Default::default()
        });
        let reference = Reference::try_from("oci.registry.local/hello:v1".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "http://oci.registry.local/v2/hello/manifests/v1",
            c.to_v2_manifest_url(&reference)
        );
    }

    #[test]
    fn blob_url_generation_uses_https_if_not_on_exception_list() {
        let insecure_registries = vec!["localhost".to_owned(), "oci.registry.local".to_owned()];
        let protocol = ClientProtocol::HttpsExcept(insecure_registries);
        let c = Client::new(ClientConfig {
            protocol,
            ..Default::default()
        });
        let reference = Reference::try_from("webassembly.azurecr.io/hello@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "https://webassembly.azurecr.io/v2/hello/blobs/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            c.to_v2_blob_url(&reference, reference.digest().unwrap())
        );
    }

    #[test]
    fn blob_url_generation_uses_http_if_on_exception_list() {
        let insecure_registries = vec!["localhost".to_owned(), "oci.registry.local".to_owned()];
        let protocol = ClientProtocol::HttpsExcept(insecure_registries);
        let c = Client::new(ClientConfig {
            protocol,
            ..Default::default()
        });
        let reference = Reference::try_from("oci.registry.local/hello@sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".to_owned())
            .expect("Could not parse reference");
        assert_eq!(
            "http://oci.registry.local/v2/hello/blobs/sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            c.to_v2_blob_url(&reference, reference.digest().unwrap())
        );
    }

    #[test]
    fn can_generate_valid_digest() {
        let bytes = b"hellobytes";
        let hash = sha256_digest(bytes);

        let combination = vec![b"hello".to_vec(), b"bytes".to_vec()];
        let combination_hash =
            sha256_digest(&combination.into_iter().flatten().collect::<Vec<u8>>());

        assert_eq!(
            hash,
            "sha256:fdbd95aafcbc814a2600fcc54c1e1706f52d2f9bf45cf53254f25bcd7599ce99"
        );
        assert_eq!(
            combination_hash,
            "sha256:fdbd95aafcbc814a2600fcc54c1e1706f52d2f9bf45cf53254f25bcd7599ce99"
        );
    }

    #[test]
    fn test_registry_token_deserialize() {
        // 'token' field, standalone
        let text = r#"{"token": "abc"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "abc");

        // 'access_token' field, standalone
        let text = r#"{"access_token": "xyz"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "xyz");

        // both 'token' and 'access_token' fields, 'token' field takes precedence
        let text = r#"{"access_token": "xyz", "token": "abc"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "abc");

        // both 'token' and 'access_token' fields, 'token' field takes precedence (reverse order)
        let text = r#"{"token": "abc", "access_token": "xyz"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "abc");

        // non-string fields do not break parsing
        let text = r#"{"aaa": 300, "access_token": "xyz", "token": "abc", "zzz": 600}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());

        // Note: tokens should always be strings. The next two tests ensure that if one field
        // is invalid (integer), then parse can still succeed if the other field is a string.
        //
        // numeric 'access_token' field, but string 'token' field does not in parse error
        let text = r#"{"access_token": 300, "token": "abc"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "abc");

        // numeric 'token' field, but string 'accesss_token' field does not in parse error
        let text = r#"{"access_token": "xyz", "token": 300}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_ok());
        let rt = res.unwrap();
        assert_eq!(rt.token(), "xyz");

        // numeric 'token' field results in parse error
        let text = r#"{"token": 300}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // numeric 'access_token' field results in parse error
        let text = r#"{"access_token": 300}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // object 'token' field results in parse error
        let text = r#"{"token": {"some": "thing"}}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // object 'access_token' field results in parse error
        let text = r#"{"access_token": {"some": "thing"}}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // missing fields results in parse error
        let text = r#"{"some": "thing"}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // bad JSON results in parse error
        let text = r#"{"token": "abc""#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());

        // worse JSON results in parse error
        let text = r#"_ _ _ kjbwef??98{9898 }} }}"#;
        let res: Result<RegistryToken, serde_json::Error> = serde_json::from_str(text);
        assert!(res.is_err());
    }

    fn check_auth_token(token: &str) {
        // We test that the token is longer than a minimal hash.
        assert!(token.len() > 64);
    }

    #[tokio::test]
    async fn test_auth() {
        let _ = tracing_subscriber::fmt::try_init();
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            let c = Client::default();
            let token = c
                .auth(
                    &reference,
                    &RegistryAuth::Anonymous,
                    RegistryOperation::Pull,
                )
                .await
                .expect("result from auth request");

            assert!(token.is_some());
            check_auth_token(token.unwrap().as_ref());

            let tok = c
                .tokens
                .get(&reference, RegistryOperation::Pull)
                .await
                .expect("token is available");
            // We test that the token is longer than a minimal hash.
            if let RegistryTokenType::Bearer(tok) = tok {
                check_auth_token(tok.token());
            } else {
                panic!("Unexpeted Basic Auth Token");
            }
        }
    }

    #[cfg(feature = "test-registry")]
    #[tokio::test]
    async fn test_list_tags() {
        let test_container = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");
        let auth =
            RegistryAuth::Basic(HTPASSWD_USERNAME.to_string(), HTPASSWD_PASSWORD.to_string());

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
            ..Default::default()
        });

        let image: Reference = HELLO_IMAGE_TAG_AND_DIGEST.parse().unwrap();
        client
            .auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .expect("cannot authenticate against registry for pull operation");

        let (manifest, _digest) = client
            ._pull_image_manifest(&image)
            .await
            .expect("failed to pull manifest");

        let image_data = client
            .pull(&image, &auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
            .await
            .expect("failed to pull image");

        for i in 0..=3 {
            let push_image: Reference = format!("localhost:{port}/hello-wasm:1.0.{i}")
                .parse()
                .unwrap();
            client
                .auth(&push_image, &auth, RegistryOperation::Push)
                .await
                .expect("authenticated");
            client
                .push(
                    &push_image,
                    &image_data.layers,
                    image_data.config.clone(),
                    &auth,
                    Some(manifest.clone()),
                )
                .await
                .expect("Failed to push Image");
        }

        let image: Reference = format!("localhost:{port}/hello-wasm:1.0.1")
            .parse()
            .unwrap();
        let response = client
            .list_tags(&image, &RegistryAuth::Anonymous, Some(2), Some("1.0.1"))
            .await
            .expect("Cannot list Tags");
        assert_eq!(response.tags, vec!["1.0.2", "1.0.3"])
    }

    #[cfg(feature = "test-registry")]
    #[tokio::test]
    async fn test_catalog() {
        let test_container = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");
        let auth =
            RegistryAuth::Basic(HTPASSWD_USERNAME.to_string(), HTPASSWD_PASSWORD.to_string());

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
            ..Default::default()
        });

        let image: Reference = HELLO_IMAGE_TAG_AND_DIGEST.parse().unwrap();
        client
            .auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .expect("cannot authenticate against registry for pull operation");

        let (manifest, _digest) = client
            ._pull_image_manifest(&image)
            .await
            .expect("failed to pull manifest");

        let image_data = client
            .pull(&image, &auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
            .await
            .expect("failed to pull image");

        // Push to two different repositories
        for repo in &["hello-catalog-a", "hello-catalog-b"] {
            let push_image: Reference = format!("localhost:{port}/{repo}:latest").parse().unwrap();
            client
                .auth(&push_image, &auth, RegistryOperation::Push)
                .await
                .expect("authenticated");
            client
                .push(
                    &push_image,
                    &image_data.layers,
                    image_data.config.clone(),
                    &auth,
                    Some(manifest.clone()),
                )
                .await
                .expect("Failed to push Image");
        }

        // Use any valid reference for the same registry to call catalog
        let catalog_ref: Reference = format!("localhost:{port}/hello-catalog-a:latest")
            .parse()
            .unwrap();
        let response = client
            .catalog(&catalog_ref, &RegistryAuth::Anonymous, None, None)
            .await
            .expect("Cannot list catalog");
        assert!(response
            .repositories
            .contains(&"hello-catalog-a".to_string()));
        assert!(response
            .repositories
            .contains(&"hello-catalog-b".to_string()));

        // Test pagination: request 1 result at a time
        let page1 = client
            .catalog(&catalog_ref, &RegistryAuth::Anonymous, Some(1), None)
            .await
            .expect("Cannot list catalog page 1");
        assert_eq!(page1.repositories.len(), 1);

        let page2 = client
            .catalog(
                &catalog_ref,
                &RegistryAuth::Anonymous,
                Some(1),
                Some(&page1.repositories[0]),
            )
            .await
            .expect("Cannot list catalog page 2");
        assert_eq!(page2.repositories.len(), 1);
        assert_ne!(page1.repositories[0], page2.repositories[0]);
    }

    #[tokio::test]
    async fn test_pull_manifest_private() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            // Currently, pull_manifest does not perform Authz, so this will fail.
            let c = Client::default();
            c._pull_image_manifest(&reference)
                .await
                .expect_err("pull manifest should fail");

            // But this should pass
            let c = Client::default();
            c.auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("authenticated");
            let (manifest, _) = c
                ._pull_image_manifest(&reference)
                .await
                .expect("pull manifest should not fail");

            // The test on the manifest checks all fields. This is just a brief sanity check.
            assert_eq!(manifest.schema_version, 2);
            assert!(!manifest.layers.is_empty());
        }
    }

    #[tokio::test]
    async fn test_pull_manifest_public() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            let c = Client::default();
            let (manifest, _) = c
                .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
                .await
                .expect("pull manifest should not fail");

            // The test on the manifest checks all fields. This is just a brief sanity check.
            assert_eq!(manifest.schema_version, 2);
            assert!(!manifest.layers.is_empty());
        }
    }

    #[tokio::test]
    async fn pull_manifest_and_config_public() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            let c = Client::default();
            let (manifest, _, config) = c
                .pull_manifest_and_config(&reference, &RegistryAuth::Anonymous)
                .await
                .expect("pull manifest and config should not fail");

            // The test on the manifest checks all fields. This is just a brief sanity check.
            assert_eq!(manifest.schema_version, 2);
            assert!(!manifest.layers.is_empty());
            assert!(!config.is_empty());
        }
    }

    #[tokio::test]
    async fn test_fetch_digest() {
        let c = Client::default();

        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            c.fetch_manifest_digest(&reference, &RegistryAuth::Anonymous)
                .await
                .expect("pull manifest should not fail");

            // This should pass
            let reference = Reference::try_from(image).expect("failed to parse reference");
            let c = Client::default();
            c.auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("authenticated");
            let digest = c
                .fetch_manifest_digest(&reference, &RegistryAuth::Anonymous)
                .await
                .expect("pull manifest should not fail");

            assert_eq!(
                digest,
                "sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7"
            );
        }
    }

    #[tokio::test]
    async fn test_pull_blob() {
        let c = Client::default();

        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            c.auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("authenticated");
            let (manifest, _) = c
                ._pull_image_manifest(&reference)
                .await
                .expect("failed to pull manifest");

            // Pull one specific layer
            let mut file: Vec<u8> = Vec::new();
            let layer0 = &manifest.layers[0];

            // This call likes to flake, so we try it at least 5 times
            let mut last_error = None;
            for i in 1..6 {
                if let Err(e) = c.pull_blob(&reference, layer0, &mut file).await {
                    println!("Got error on pull_blob call attempt {i}. Will retry in 1s: {e:?}");
                    last_error.replace(e);
                    tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                } else {
                    last_error = None;
                    break;
                }
            }

            if let Some(e) = last_error {
                panic!("Unable to pull layer: {e:?}");
            }

            // The manifest says how many bytes we should expect.
            assert_eq!(file.len(), layer0.size as usize);
        }
    }

    #[tokio::test]
    async fn test_pull_blob_stream() {
        let c = Client::default();

        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            c.auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("authenticated");
            let (manifest, _) = c
                ._pull_image_manifest(&reference)
                .await
                .expect("failed to pull manifest");

            // Pull one specific layer
            let mut file: Vec<u8> = Vec::new();
            let layer0 = &manifest.layers[0];

            let layer_stream = c
                .pull_blob_stream(&reference, layer0)
                .await
                .expect("failed to pull blob stream");

            assert_eq!(layer_stream.content_length, Some(layer0.size as u64));
            AsyncReadExt::read_to_end(&mut StreamReader::new(layer_stream.stream), &mut file)
                .await
                .unwrap();

            // The manifest says how many bytes we should expect.
            assert_eq!(file.len(), layer0.size as usize);
        }
    }

    #[tokio::test]
    async fn test_pull_blob_stream_partial() {
        let c = Client::default();

        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            c.auth(
                &reference,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("authenticated");
            let (manifest, _) = c
                ._pull_image_manifest(&reference)
                .await
                .expect("failed to pull manifest");

            // Pull part of one specific layer
            let mut partial_file: Vec<u8> = Vec::new();
            let layer0 = &manifest.layers[0];
            let (offset, length) = (10, 6);

            let partial_response = c
                .pull_blob_stream_partial(&reference, layer0, offset, Some(length))
                .await
                .expect("failed to pull blob stream");
            let full_response = c
                .pull_blob_stream_partial(&reference, layer0, 0, Some(layer0.size as u64))
                .await
                .expect("failed to pull blob stream");

            let layer_stream_partial = match partial_response {
                BlobResponse::Full(_stream) => panic!("expected partial response"),
                BlobResponse::Partial(stream) => stream,
            };
            assert_eq!(layer_stream_partial.content_length, Some(length));
            AsyncReadExt::read_to_end(
                &mut StreamReader::new(layer_stream_partial.stream),
                &mut partial_file,
            )
            .await
            .unwrap();

            // Also pull the full layer into a separate file to compare with the partial.
            let mut full_file: Vec<u8> = Vec::new();
            let layer_stream_full = match full_response {
                BlobResponse::Full(_stream) => panic!("expected partial response"),
                BlobResponse::Partial(stream) => stream,
            };
            assert_eq!(layer_stream_full.content_length, Some(layer0.size as u64));
            AsyncReadExt::read_to_end(
                &mut StreamReader::new(layer_stream_full.stream),
                &mut full_file,
            )
            .await
            .unwrap();

            // The partial read length says how many bytes we should expect.
            assert_eq!(partial_file.len(), length as usize);
            // The manifest says how many bytes we should expect on a full read.
            assert_eq!(full_file.len(), layer0.size as usize);
            // Check that the partial read retrieved the correct bytes.
            let end: usize = (offset + length) as usize;
            assert_eq!(partial_file, full_file[offset as usize..end]);
        }
    }

    #[tokio::test]
    async fn test_pull() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");

            // This call likes to flake, so we try it at least 5 times
            let mut last_error = None;
            let mut image_data = None;
            for i in 1..6 {
                match Client::default()
                    .pull(
                        &reference,
                        &RegistryAuth::Anonymous,
                        vec![manifest::WASM_LAYER_MEDIA_TYPE],
                    )
                    .await
                {
                    Ok(data) => {
                        image_data = Some(data);
                        last_error = None;
                        break;
                    }
                    Err(e) => {
                        println!("Got error on pull call attempt {i}. Will retry in 1s: {e:?}");
                        last_error.replace(e);
                        tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
                    }
                }
            }

            if let Some(e) = last_error {
                panic!("Unable to pull layer: {e:?}");
            }

            assert!(image_data.is_some());
            let image_data = image_data.unwrap();
            assert!(!image_data.layers.is_empty());
            assert!(image_data.digest.is_some());
        }
    }

    /// Attempting to pull an image without any layer validation should fail.
    #[tokio::test]
    async fn test_pull_without_layer_validation() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            assert!(Client::default()
                .pull(&reference, &RegistryAuth::Anonymous, vec![],)
                .await
                .is_err());
        }
    }

    /// Attempting to pull an image with the wrong list of layer validations should fail.
    #[tokio::test]
    async fn test_pull_wrong_layer_validation() {
        for &image in TEST_IMAGES {
            let reference = Reference::try_from(image).expect("failed to parse reference");
            assert!(Client::default()
                .pull(&reference, &RegistryAuth::Anonymous, vec!["text/plain"],)
                .await
                .is_err());
        }
    }

    // This is the latest build of distribution/distribution from the `main` branch
    // Until distribution v3 is relased, this is the only way to have this fix
    // https://github.com/distribution/distribution/pull/3143
    //
    // We require this fix only when testing the capability to list tags
    #[cfg(feature = "test-registry")]
    fn registry_image_edge() -> GenericImage {
        GenericImage::new("distribution/distribution", "edge")
            .with_wait_for(WaitFor::message_on_stderr("listening on "))
    }

    #[cfg(feature = "test-registry")]
    fn registry_image() -> GenericImage {
        GenericImage::new("docker.io/library/registry", "2")
            .with_wait_for(WaitFor::message_on_stderr("listening on "))
    }

    #[cfg(feature = "test-registry")]
    fn registry_image_basic_auth(auth_path: &str) -> ContainerRequest<GenericImage> {
        GenericImage::new("docker.io/library/registry", "2")
            .with_wait_for(WaitFor::message_on_stderr("listening on "))
            .with_env_var("REGISTRY_AUTH", "htpasswd")
            .with_env_var("REGISTRY_AUTH_HTPASSWD_REALM", "Registry Realm")
            .with_env_var("REGISTRY_AUTH_HTPASSWD_PATH", "/auth/htpasswd")
            .with_mount(Mount::bind_mount(auth_path, "/auth"))
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn can_push_chunk() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        let url = format!("localhost:{port}/hello-wasm:v1");
        let image: Reference = url.parse().unwrap();

        c.auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Push)
            .await
            .expect("result from auth request");

        let location = c
            .begin_push_chunked_session(&image)
            .await
            .expect("failed to begin push session");

        let image_data = Bytes::from(b"iamawebassemblymodule".to_vec());
        let (next_location, next_byte) = c
            .push_chunk(&location, &image, image_data.clone(), 0)
            .await
            .expect("failed to push layer");

        // Location should include original URL with at session ID appended
        assert!(next_location.len() >= url.len() + "6987887f-0196-45ee-91a1-2dfad901bea0".len());
        assert_eq!(next_byte, image_data.len());

        let layer_location = c
            .end_push_chunked_session(&next_location, &image, &sha256_digest(&image_data))
            .await
            .expect("failed to end push session");

        assert_eq!(layer_location, format!("http://localhost:{port}/v2/hello-wasm/blobs/sha256:6165c4ad43c0803798b6f2e49d6348c915d52c999a5f890846cee77ea65d230b"));
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn can_push_multiple_chunks() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let mut c = Client::new(ClientConfig {
            protocol: ClientProtocol::Http,
            ..Default::default()
        });
        // set a super small chunk size - done to force multiple pushes
        c.push_chunk_size = 3;
        let url = format!("localhost:{port}/hello-wasm:v1");
        let image: Reference = url.parse().unwrap();

        c.auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Push)
            .await
            .expect("result from auth request");

        let image_data: Vec<u8> =
            b"i am a big webassembly mode that needs chunked uploads".to_vec();
        let image_digest = sha256_digest(&image_data);

        let location = c
            .push_blob_chunked(&image, image_data, &image_digest)
            .await
            .expect("failed to begin push session");

        assert_eq!(
            location,
            format!("http://localhost:{port}/v2/hello-wasm/blobs/{image_digest}")
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_image_roundtrip_anon_auth() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry container");

        test_image_roundtrip(&RegistryAuth::Anonymous, &test_container).await;
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_image_roundtrip_basic_auth() {
        let auth_dir = TempDir::new().expect("cannot create tmp directory");
        let htpasswd_path = path::Path::join(auth_dir.path(), "htpasswd");
        fs::write(htpasswd_path, HTPASSWD).expect("cannot write htpasswd file");

        let image = registry_image_basic_auth(
            auth_dir
                .path()
                .to_str()
                .expect("cannot convert htpasswd_path to string"),
        );
        let test_container = image.start().await.expect("cannot registry container");

        let auth =
            RegistryAuth::Basic(HTPASSWD_USERNAME.to_string(), HTPASSWD_PASSWORD.to_string());

        test_image_roundtrip(&auth, &test_container).await;
    }

    #[cfg(feature = "test-registry")]
    async fn test_image_roundtrip(
        registry_auth: &RegistryAuth,
        test_container: &testcontainers::ContainerAsync<GenericImage>,
    ) {
        let _ = tracing_subscriber::fmt::try_init();
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
            ..Default::default()
        });

        // pulling webassembly.azurecr.io/hello-wasm:v1
        let image: Reference = HELLO_IMAGE_TAG_AND_DIGEST.parse().unwrap();
        c.auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .expect("cannot authenticate against registry for pull operation");

        let (manifest, _digest) = c
            ._pull_image_manifest(&image)
            .await
            .expect("failed to pull manifest");

        let image_data = c
            .pull(&image, registry_auth, vec![manifest::WASM_LAYER_MEDIA_TYPE])
            .await
            .expect("failed to pull image");

        let push_image: Reference = format!("localhost:{port}/hello-wasm:v1").parse().unwrap();
        c.auth(&push_image, registry_auth, RegistryOperation::Push)
            .await
            .expect("authenticated");

        c.push(
            &push_image,
            &image_data.layers,
            image_data.config.clone(),
            registry_auth,
            Some(manifest.clone()),
        )
        .await
        .expect("failed to push image");

        let pulled_image_data = c
            .pull(
                &push_image,
                registry_auth,
                vec![manifest::WASM_LAYER_MEDIA_TYPE],
            )
            .await
            .expect("failed to pull pushed image");

        let (pulled_manifest, _digest) = c
            ._pull_image_manifest(&push_image)
            .await
            .expect("failed to pull pushed image manifest");

        assert!(image_data.layers.len() == 1);
        assert!(pulled_image_data.layers.len() == 1);
        assert_eq!(
            image_data.layers[0].data.len(),
            pulled_image_data.layers[0].data.len()
        );
        assert_eq!(image_data.layers[0].data, pulled_image_data.layers[0].data);

        assert_eq!(manifest.media_type, pulled_manifest.media_type);
        assert_eq!(manifest.schema_version, pulled_manifest.schema_version);
        assert_eq!(manifest.config.digest, pulled_manifest.config.digest);
    }

    #[tokio::test]
    async fn test_raw_manifest_digest() {
        let _ = tracing_subscriber::fmt::try_init();

        let c = Client::default();

        // pulling webassembly.azurecr.io/hello-wasm:v1@sha256:51d9b231d5129e3ffc267c9d455c49d789bf3167b611a07ab6e4b3304c96b0e7
        let image: Reference = HELLO_IMAGE_TAG_AND_DIGEST.parse().unwrap();
        c.auth(&image, &RegistryAuth::Anonymous, RegistryOperation::Pull)
            .await
            .expect("cannot authenticate against registry for pull operation");

        let (manifest, _) = c
            .pull_manifest_raw(
                &image,
                &RegistryAuth::Anonymous,
                MIME_TYPES_DISTRIBUTION_MANIFEST,
            )
            .await
            .expect("failed to pull manifest");

        // Compute the digest of the returned manifest text.
        let digest = sha2::Sha256::digest(manifest);
        let hex = format!("sha256:{}", hex::encode(digest));

        // Validate that the computed digest and the digest in the pulled reference match.
        assert_eq!(image.digest().unwrap(), hex);
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_mount() {
        // initialize the registry
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
            ..Default::default()
        });

        // Create a dummy layer and push it to `layer-repository`
        let layer_reference: Reference = format!("localhost:{port}/layer-repository")
            .parse()
            .unwrap();
        let layer_data = vec![1u8, 2, 3, 4];
        let layer = OciDescriptor {
            digest: sha256_digest(&layer_data),
            ..Default::default()
        };
        c.push_blob(
            &layer_reference,
            Bytes::copy_from_slice(&layer_data),
            &layer.digest,
        )
        .await
        .expect("Failed to push");

        // Mount the layer at `image-repository`
        let image_reference: Reference = format!("localhost:{port}/image-repository")
            .parse()
            .unwrap();
        let response = c
            .mount_blob(&image_reference, &layer_reference, &layer.digest)
            .await
            .expect("Failed to mount");
        assert_eq!(response, BlobMountResponse::Mounted);

        // Pull the layer from `image-repository`
        let mut buf = Vec::new();
        c.pull_blob(&image_reference, &layer, &mut buf)
            .await
            .expect("Failed to pull");

        assert_eq!(layer_data, buf);
    }

    /// A mount for a digest absent from the source repository is a
    /// spec-legal miss: the registry opens a regular upload session (202)
    /// instead of erroring. A normal `push_blob` against the same digest
    /// must still land the blob afterward.
    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_mount_miss_opens_upload_session() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", port)]),
            ..Default::default()
        });

        // `source-repository` never receives this blob, so the digest is
        // absent from it - the mount attempt is guaranteed to miss.
        let source_reference: Reference = format!("localhost:{port}/source-repository")
            .parse()
            .unwrap();
        let layer_data = vec![5u8, 6, 7, 8];
        let layer = OciDescriptor {
            digest: sha256_digest(&layer_data),
            ..Default::default()
        };

        let image_reference: Reference = format!("localhost:{port}/image-repository-miss")
            .parse()
            .unwrap();
        let response = c
            .mount_blob(&image_reference, &source_reference, &layer.digest)
            .await
            .expect("mount miss must not error");
        assert!(
            matches!(response, BlobMountResponse::UploadSessionOpened(_)),
            "expected UploadSessionOpened, got {response:?}"
        );

        // A normal push_blob still lands the blob despite the prior mount miss.
        c.push_blob(
            &image_reference,
            Bytes::copy_from_slice(&layer_data),
            &layer.digest,
        )
        .await
        .expect("push_blob must still succeed after a mount miss");

        let mut buf = Vec::new();
        c.pull_blob(&image_reference, &layer, &mut buf)
            .await
            .expect("Failed to pull");
        assert_eq!(layer_data, buf);
    }

    #[tokio::test]
    async fn test_platform_resolution() {
        // test that we get an error when we pull a manifest list
        let reference = Reference::try_from(DOCKER_IO_IMAGE).expect("failed to parse reference");
        let mut c = Client::new(ClientConfig {
            platform_resolver: None,
            ..Default::default()
        });
        let err = c
            .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
            .await
            .unwrap_err();
        assert_eq!(
            format!("{err}"),
            "Received Image Index/Manifest List, but platform_resolver was not defined on the client config. Consider setting platform_resolver"
        );

        c = Client::new(ClientConfig {
            platform_resolver: Some(Box::new(linux_amd64_resolver)),
            ..Default::default()
        });
        let (_manifest, digest) = c
            .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
            .await
            .expect("Couldn't pull manifest");
        assert_eq!(
            digest,
            "sha256:f54a58bc1aac5ea1a25d796ae155dc228b3f0e11d046ae276b39c4bf2f13d8c4"
        );
    }

    #[tokio::test]
    async fn test_pull_ghcr_io() {
        let reference = Reference::try_from(GHCR_IO_IMAGE).expect("failed to parse reference");
        let c = Client::default();
        let (manifest, _manifest_str) = c
            .pull_image_manifest(&reference, &RegistryAuth::Anonymous)
            .await
            .unwrap();
        assert_eq!(manifest.config.media_type, manifest::WASM_CONFIG_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn test_list_all_tags_ghcr_io() {
        const MAX_TAGS_PER_LIST: usize = 100;
        const MAX_TAG_REQUESTS: usize = 10;

        let reference = Reference::try_from(GHCR_IO_IMAGE).expect("failed to parse reference");
        let c = Client::default();

        // When listing beyond the last tag in the repository, ghcr.io has been observed to emit
        // a JSON `null` for the "tags" field rather than an empty array. This must be handled
        // to paginate through tags using the `last` parameter.
        let mut last_tag = None;
        for _ in 0..MAX_TAG_REQUESTS {
            let mut response = c
                .list_tags(
                    &reference,
                    &RegistryAuth::Anonymous,
                    Some(MAX_TAGS_PER_LIST),
                    last_tag.as_deref(),
                )
                .await
                .expect("failed to list tags in registry");

            if let Some(tag) = response.tags.pop() {
                last_tag = Some(tag);
            } else {
                return;
            }
        }

        panic!("failed to list all tags for {GHCR_IO_IMAGE} in {MAX_TAG_REQUESTS} requests");
    }

    #[tokio::test]
    #[ignore]
    async fn test_roundtrip_multiple_layers() {
        let _ = tracing_subscriber::fmt::try_init();
        let c = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec!["oci.registry.local".to_string()]),
            ..Default::default()
        });
        let src_image = Reference::try_from("registry:2.7.1").expect("failed to parse reference");
        let dest_image = Reference::try_from("oci.registry.local/registry:roundtrip-test")
            .expect("failed to parse reference");

        let image = c
            .pull(
                &src_image,
                &RegistryAuth::Anonymous,
                vec![IMAGE_DOCKER_LAYER_GZIP_MEDIA_TYPE],
            )
            .await
            .expect("Failed to pull manifest");
        assert!(image.layers.len() > 1);

        let ImageData {
            layers,
            config,
            manifest,
            ..
        } = image;
        c.push(
            &dest_image,
            &layers,
            config,
            &RegistryAuth::Anonymous,
            manifest,
        )
        .await
        .expect("Failed to pull manifest");

        c.pull_image_manifest(&dest_image, &RegistryAuth::Anonymous)
            .await
            .expect("Failed to pull manifest");
    }

    #[tokio::test]
    async fn test_hashable_image_layer() {
        use itertools::Itertools;

        // First two should be identical; others differ
        let image_layers = Vec::from([
            ImageLayer {
                data: Bytes::from_static(&[0, 1, 2, 3]),
                media_type: "media_type".to_owned(),
                annotations: Some(BTreeMap::from([
                    ("0".to_owned(), "1".to_owned()),
                    ("2".to_owned(), "3".to_owned()),
                ])),
            },
            ImageLayer {
                data: Bytes::from_static(&[0, 1, 2, 3]),
                media_type: "media_type".to_owned(),
                annotations: Some(BTreeMap::from([
                    ("2".to_owned(), "3".to_owned()),
                    ("0".to_owned(), "1".to_owned()),
                ])),
            },
            ImageLayer {
                data: Bytes::from_static(&[0, 1, 2, 3]),
                media_type: "different_media_type".to_owned(),
                annotations: Some(BTreeMap::from([
                    ("0".to_owned(), "1".to_owned()),
                    ("2".to_owned(), "3".to_owned()),
                ])),
            },
            ImageLayer {
                data: Bytes::from_static(&[0, 1, 2]),
                media_type: "media_type".to_owned(),
                annotations: Some(BTreeMap::from([
                    ("0".to_owned(), "1".to_owned()),
                    ("2".to_owned(), "3".to_owned()),
                ])),
            },
            ImageLayer {
                data: Bytes::from_static(&[0, 1, 2, 3]),
                media_type: "media_type".to_owned(),
                annotations: Some(BTreeMap::from([
                    ("1".to_owned(), "0".to_owned()),
                    ("2".to_owned(), "3".to_owned()),
                ])),
            },
        ]);

        assert_eq!(
            &image_layers[0], &image_layers[1],
            "image_layers[0] should equal image_layers[1]"
        );
        assert_ne!(
            &image_layers[0], &image_layers[2],
            "image_layers[0] should not equal image_layers[2]"
        );
        assert_ne!(
            &image_layers[0], &image_layers[3],
            "image_layers[0] should not equal image_layers[3]"
        );
        assert_ne!(
            &image_layers[0], &image_layers[4],
            "image_layers[0] should not equal image_layers[4]"
        );
        assert_ne!(
            &image_layers[2], &image_layers[3],
            "image_layers[2] should not equal image_layers[3]"
        );
        assert_ne!(
            &image_layers[2], &image_layers[4],
            "image_layers[2] should not equal image_layers[4]"
        );
        assert_ne!(
            &image_layers[3], &image_layers[4],
            "image_layers[3] should not equal image_layers[4]"
        );

        let deduped: Vec<ImageLayer> = image_layers.clone().into_iter().unique().collect();
        assert_eq!(
            image_layers.len() - 1,
            deduped.len(),
            "after deduplication, there should be one less image layer"
        );
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_blob_exists() {
        let real_registry = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");

        let server_port = real_registry
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", server_port)]),
            ..Default::default()
        });

        let reference = Reference::try_from(format!("localhost:{server_port}/empty"))
            .expect("failed to parse reference");

        assert!(!client
            .blob_exists(&reference, EMPTY_JSON_DIGEST)
            .await
            .expect("failed to check blob existence"));
        client
            .push_blob(&reference, EMPTY_JSON_BLOB.as_bytes(), EMPTY_JSON_DIGEST)
            .await
            .expect("failed to push empty json blob");
        assert!(client
            .blob_exists(&reference, EMPTY_JSON_DIGEST)
            .await
            .expect("failed to check blob existence"));
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_fetch_blob_size() {
        let real_registry = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");

        let server_port = real_registry
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", server_port)]),
            ..Default::default()
        });

        let reference = Reference::try_from(format!("localhost:{server_port}/empty"))
            .expect("failed to parse reference");

        // Absent blob must report None, not an error.
        let missing = client
            .fetch_blob_size(&reference, EMPTY_JSON_DIGEST)
            .await
            .expect("fetch_blob_size should not error on a missing blob");
        assert_eq!(
            missing, None,
            "fetch_blob_size must return None for a blob the registry does not have"
        );

        // After upload, HEAD + Content-Length must round-trip the byte length.
        client
            .push_blob(&reference, EMPTY_JSON_BLOB.as_bytes(), EMPTY_JSON_DIGEST)
            .await
            .expect("failed to push empty json blob");
        let present = client
            .fetch_blob_size(&reference, EMPTY_JSON_DIGEST)
            .await
            .expect("failed to fetch blob size after push");
        assert_eq!(
            present,
            Some(EMPTY_JSON_BLOB.len() as u64),
            "fetch_blob_size must report the pushed blob's length, not zero or the wrong figure"
        );
    }

    #[rstest]
    #[case::chunked(false)]
    #[case::monolithic(true)]
    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_push_stream(#[case] use_monolithic_push: bool) {
        let real_registry = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");

        let server_port = real_registry
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let mut client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", server_port)]),
            use_monolithic_push,
            ..Default::default()
        });
        client.push_chunk_size = 253;

        // hash for a byte array counting 16 times from 0 to 255 ([0, 1, 2, ..., 255] * 16)
        let data_hash = "sha256:c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193";
        let repeat = 16usize;
        let chunk_size = 256usize; // Bytes::from_iter(0u8..=255)
        let data_stream = |n| {
            futures_util::stream::repeat(Bytes::from_iter(0u8..=255))
                .take(n)
                .map(Ok)
        };
        let size = Some(repeat * chunk_size);

        let reference = Reference::try_from(format!("localhost:{server_port}/test-push-stream"))
            .expect("failed to parse reference");

        // Sanity check: verify that the server rejects the push if the blob has a mismatched digest
        client
            .push_blob_stream(&reference, data_stream(1), data_hash, None)
            .await
            .expect_err("expected push to fail with mismatched digest");

        // Now push the stream with the correct digest
        client
            .push_blob_stream(&reference, data_stream(repeat), data_hash, size)
            .await
            .expect("failed to push stream");

        assert!(client
            .blob_exists(&reference, data_hash)
            .await
            .expect("failed to check blob existence"));
    }

    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_push_stream_monolithic_requires_size() {
        let real_registry = registry_image_edge()
            .start()
            .await
            .expect("Failed to start registry container");

        let server_port = real_registry
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{}", server_port)]),
            use_monolithic_push: true,
            ..Default::default()
        });

        let data_hash = "sha256:c8f5d0341d54d951a71b136e6e2afcb14d11ed8489a7ae126a8fee0df6ecf193";
        let data_stream = futures_util::stream::repeat(Bytes::from_iter(0u8..=255))
            .take(16)
            .map(Ok);

        let reference = Reference::try_from(format!("localhost:{server_port}/test-push-stream"))
            .expect("failed to parse reference");

        client
            .push_blob_stream(&reference, data_stream, data_hash, None)
            .await
            .expect_err("expected error when use_monolithic_push is true but size is None");
    }

    /// Push a minimal OCI image manifest (empty config blob, no layers) to the registry and
    /// return its digest.
    ///
    /// The manifest is pushed under the given `reference`.  The caller is responsible for
    /// authenticating the client for push operations beforehand.
    #[cfg(feature = "test-registry")]
    async fn push_minimal_manifest(
        client: &Client,
        reference: &Reference,
        artifact_type: Option<&str>,
    ) -> String {
        // Empty config blob.
        let config_data = b"{}";
        let config_digest = sha256_digest(config_data);
        client
            .push_blob(reference, config_data.as_slice(), &config_digest)
            .await
            .expect("failed to push config blob");

        let manifest = OciImageManifest {
            schema_version: 2,
            media_type: Some(manifest::OCI_IMAGE_MEDIA_TYPE.to_string()),
            artifact_type: artifact_type.map(str::to_string),
            config: OciDescriptor {
                media_type: manifest::IMAGE_CONFIG_MEDIA_TYPE.to_string(),
                digest: config_digest.clone(),
                size: config_data.len() as i64,
                ..Default::default()
            },
            layers: vec![],
            subject: None,
            annotations: None,
        };

        let oci_manifest = OciManifest::Image(manifest);
        client
            .push_manifest(reference, &oci_manifest)
            .await
            .expect("failed to push manifest")
            // push_manifest returns the URL; extract the digest from the end
            .rsplit('/')
            .next()
            .expect("manifest URL has no digest component")
            .to_string()
    }

    /// `distribution/distribution` does not implement the native OCI referrers API — it returns 404 for
    /// `/v2/<name>/referrers/<digest>`.  These tests verify that `pull_referrers` correctly
    /// falls back to the referrers tag schema in that situation.
    ///
    /// Referrers support is being tracked upstream by this issue: https://github.com/distribution/distribution/issues/3716
    ///
    /// Setup overview:
    ///   1. Push a "target" image manifest to get its digest.
    ///   2. Manually build and push an `OciImageIndex` as the referrers tag
    ///      (`sha256-<target-digest>`), containing descriptor entries for two
    ///      hypothetical referrers with different `artifact_type` values.
    ///   3. Call `pull_referrers` and verify that the fallback is used and the
    ///      returned index contains the expected entries (both unfiltered and filtered).
    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_pull_referrers_with_tag_schema_fallback() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{port}")]),
            ..Default::default()
        });

        let repo = format!("localhost:{port}/referrers-test");

        // --- Step 1: push the target manifest ---
        let target_ref: Reference = format!("{repo}:target").parse().unwrap();
        client
            .auth(
                &target_ref,
                &RegistryAuth::Anonymous,
                RegistryOperation::Push,
            )
            .await
            .expect("failed to authenticate for push");
        let target_digest = push_minimal_manifest(&client, &target_ref, None).await;

        // --- Step 2: push a referrers tag index ---
        //
        // The tag is the target digest with ':' replaced by '-'.
        // We include two descriptors so we can also test artifact_type filtering:
        //   - one with artifact_type "application/vnd.test.sig"
        //   - one with artifact_type "application/vnd.test.sbom"
        const SIG_ARTIFACT_TYPE: &str = "application/vnd.test.sig";
        const SBOM_ARTIFACT_TYPE: &str = "application/vnd.test.sbom";

        // Push two real minimal manifests to use as referrer entries.
        let sig_ref: Reference = format!("{repo}:sig").parse().unwrap();
        let sig_digest = push_minimal_manifest(&client, &sig_ref, Some(SIG_ARTIFACT_TYPE)).await;

        let sbom_ref: Reference = format!("{repo}:sbom").parse().unwrap();
        let sbom_digest = push_minimal_manifest(&client, &sbom_ref, Some(SBOM_ARTIFACT_TYPE)).await;

        // Pull the manifests back to get the accurate serialised sizes.
        let (sig_raw, _) = client
            .pull_manifest_raw(
                &sig_ref,
                &RegistryAuth::Anonymous,
                MIME_TYPES_DISTRIBUTION_MANIFEST,
            )
            .await
            .expect("failed to pull sig manifest raw");
        let sig_size = sig_raw.len() as i64;

        let (sbom_raw, _) = client
            .pull_manifest_raw(
                &sbom_ref,
                &RegistryAuth::Anonymous,
                MIME_TYPES_DISTRIBUTION_MANIFEST,
            )
            .await
            .expect("failed to pull sbom manifest raw");
        let sbom_size = sbom_raw.len() as i64;

        let referrers_index = OciImageIndex {
            schema_version: 2,
            media_type: Some(manifest::OCI_IMAGE_INDEX_MEDIA_TYPE.to_string()),
            artifact_type: None,
            annotations: None,
            manifests: vec![
                ImageIndexEntry {
                    media_type: manifest::OCI_IMAGE_MEDIA_TYPE.to_string(),
                    digest: sig_digest,
                    size: sig_size,
                    artifact_type: Some(SIG_ARTIFACT_TYPE.to_string()),
                    platform: None,
                    annotations: None,
                },
                ImageIndexEntry {
                    media_type: manifest::OCI_IMAGE_MEDIA_TYPE.to_string(),
                    digest: sbom_digest,
                    size: sbom_size,
                    artifact_type: Some(SBOM_ARTIFACT_TYPE.to_string()),
                    platform: None,
                    annotations: None,
                },
            ],
        };

        let fallback_tag = target_digest.replace(':', "-");
        let tag_ref: Reference = format!("{repo}:{fallback_tag}").parse().unwrap();
        client
            .push_manifest(&tag_ref, &OciManifest::ImageIndex(referrers_index))
            .await
            .expect("failed to push referrers tag index");

        // --- Step 3: pull_referrers — no filter, expect both entries ---
        let digest_ref = Reference::with_digest(
            format!("localhost:{port}"),
            "referrers-test".to_string(),
            target_digest.clone(),
        );
        client
            .auth(
                &digest_ref,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("failed to authenticate for pull");

        let index = client
            .pull_referrers(&digest_ref, None)
            .await
            .expect("pull_referrers failed");
        assert_eq!(
            index.manifests.len(),
            2,
            "expected 2 referrers (unfiltered), got {:?}",
            index.manifests
        );

        // --- Step 4: pull_referrers — filtered by SIG_ARTIFACT_TYPE ---
        let index_filtered = client
            .pull_referrers(&digest_ref, Some(SIG_ARTIFACT_TYPE))
            .await
            .expect("pull_referrers with artifact_type filter failed");
        assert_eq!(
            index_filtered.manifests.len(),
            1,
            "expected 1 referrer after filtering by {SIG_ARTIFACT_TYPE}, got {:?}",
            index_filtered.manifests
        );
        assert_eq!(
            index_filtered.manifests[0].artifact_type.as_deref(),
            Some(SIG_ARTIFACT_TYPE),
        );
    }

    /// Verify that `pull_referrers` returns an empty index when neither the native referrers
    /// API nor the referrers tag schema returns anything — i.e. the target image exists but
    /// has no referrers at all.
    #[tokio::test]
    #[cfg(feature = "test-registry")]
    async fn test_pull_referrers_no_tag_schema() {
        let test_container = registry_image()
            .start()
            .await
            .expect("Failed to start registry container");
        let port = test_container
            .get_host_port_ipv4(5000)
            .await
            .expect("Failed to get port");

        let client = Client::new(ClientConfig {
            protocol: ClientProtocol::HttpsExcept(vec![format!("localhost:{port}")]),
            ..Default::default()
        });

        let repo = format!("localhost:{port}/referrers-none-test");

        // Push a target manifest — but do NOT push any referrers tag.
        let target_ref: Reference = format!("{repo}:target").parse().unwrap();
        client
            .auth(
                &target_ref,
                &RegistryAuth::Anonymous,
                RegistryOperation::Push,
            )
            .await
            .expect("failed to authenticate for push");
        let target_digest = push_minimal_manifest(&client, &target_ref, None).await;

        let digest_ref = Reference::with_digest(
            format!("localhost:{port}"),
            "referrers-none-test".to_string(),
            target_digest,
        );
        client
            .auth(
                &digest_ref,
                &RegistryAuth::Anonymous,
                RegistryOperation::Pull,
            )
            .await
            .expect("failed to authenticate for pull");

        let index = client
            .pull_referrers(&digest_ref, None)
            .await
            .expect("pull_referrers should succeed (returning empty index)");
        assert!(
            index.manifests.is_empty(),
            "expected empty referrers index, got {:?}",
            index.manifests
        );
    }
}
