//! Token cache for OCI registry authentication

use oci_spec::distribution::Reference;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fmt;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{debug, warn};

/// A token granted during the OAuth2-like workflow for OCI registries.
#[derive(Deserialize, Clone)]
#[serde(untagged)]
#[serde(rename_all = "snake_case")]
pub enum RegistryToken {
    /// Token value
    Token {
        /// The string value of the token
        token: String,
    },
    /// AccessToken value
    AccessToken {
        /// The string value of the access_token
        access_token: String,
    },
}

impl fmt::Debug for RegistryToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let redacted = String::from("<redacted>");
        match self {
            RegistryToken::Token { .. } => {
                f.debug_struct("Token").field("token", &redacted).finish()
            }
            RegistryToken::AccessToken { .. } => f
                .debug_struct("AccessToken")
                .field("access_token", &redacted)
                .finish(),
        }
    }
}

#[derive(Debug, Clone)]
/// Type of registry auth token
pub enum RegistryTokenType {
    /// Bearer auth token type
    Bearer(RegistryToken),
    /// Basic auth token type
    Basic(String, String),
}

impl RegistryToken {
    /// Returns the bearer token in a form suitable to use for an Authorization header
    pub fn bearer_token(&self) -> String {
        format!("Bearer {}", self.token())
    }

    /// Returns the token value
    pub fn token(&self) -> &str {
        match self {
            RegistryToken::Token { token } => token,
            RegistryToken::AccessToken { access_token } => access_token,
        }
    }
}

/// Desired operation for registry authentication
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum RegistryOperation {
    /// Authenticate for push operations
    Push,
    /// Authenticate for pull operations
    Pull,
}

#[derive(Debug, Deserialize)]
struct BearerTokenClaims {
    exp: Option<u64>,
}

/// Identity of one cached token: a registry, a repository under it, and the
/// operation the token was scoped for.
///
/// # The key carries no credential identity, and that is only safe by accident
///
/// If two different [`RegistryAuth`](crate::secrets::RegistryAuth) values were
/// ever live for one key concurrently, a coalesced waiter could receive a token
/// minted for someone else's credentials. It cannot happen today because
/// `Client::store_auth_if_needed` is first-write-wins per registry and never
/// overwrites for the life of a `Client`, so one client holds at most one
/// identity per registry. A change to `store_auth` that allowed credential
/// rotation would reopen this, and nothing else in the crate would catch it —
/// such a change must add the credential to this key.
///
/// # The scope must stay in the key
///
/// Registry **and** repository **and** verb set. Keying on the registry alone
/// is the `insufficient_scope` bug class (moby/buildkit#5883): a token minted
/// for one repository is served for another the registry never granted.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct TokenCacheKey {
    registry: String,
    repository: String,
    operation: RegistryOperation,
}

impl TokenCacheKey {
    pub(crate) fn new(reference: &Reference, operation: RegistryOperation) -> Self {
        TokenCacheKey {
            registry: reference.resolve_registry().to_string(),
            repository: reference.repository().to_string(),
            operation,
        }
    }
}

struct TokenCacheValue {
    token: RegistryTokenType,
    expiration: u64,
}

#[derive(Clone)]
/// A cache to hold authentication tokens
pub struct TokenCache {
    // (registry, repository, scope) -> (token, expiration)
    tokens: Arc<RwLock<BTreeMap<TokenCacheKey, TokenCacheValue>>>,
    /// Default token expiration in seconds, to use when claim doesn't specify a value
    pub default_expiration_secs: usize,
}

impl TokenCache {
    pub(crate) fn new(default_expiration_secs: usize) -> Self {
        TokenCache {
            tokens: Arc::new(RwLock::new(BTreeMap::new())),
            default_expiration_secs,
        }
    }

    /// Insert a token corresponding to reference and operation keys
    pub async fn insert(
        &self,
        reference: &Reference,
        op: RegistryOperation,
        token: RegistryTokenType,
    ) {
        let expiration = match token {
            // A Basic entry is the caller's own username and password, which
            // `Client::_auth` hands back verbatim from its `authentication`
            // argument. This key carries no credential identity, so retaining
            // one serves it to whoever asks next whatever secret *they* passed:
            // authenticate with one identity, call again with another, and the
            // second call keeps using the first. It is also pure liability —
            // the header-attach path falls back to the client's own credential
            // store, and re-deriving costs no request once the challenge probe
            // is cached.
            RegistryTokenType::Basic(_, _) => return,
            RegistryTokenType::Bearer(ref t) => {
                match parse_expiration_from_jwt(t.token(), self.default_expiration_secs) {
                    Some(value) => value,
                    None => return,
                }
            }
        };
        let key = TokenCacheKey::new(reference, op);
        debug!(%key.registry, %key.repository, ?op, %expiration, "Inserting token");
        self.tokens
            .write()
            .await
            .insert(key, TokenCacheValue { token, expiration });
    }

    /// Drops the one entry for `reference`'s registry, repository and `op`.
    ///
    /// The scope named by a `401` is the only one the rejection is evidence
    /// about. Dropping the host with it costs a fresh token exchange for every
    /// sibling scope in flight — inside a wide index fan-out, one forbidden
    /// repository would re-mint every authorised one — so the wide purge waits
    /// for evidence the credential itself is dead. See
    /// [`purge_registry`](Self::purge_registry).
    pub(crate) async fn purge_scope(&self, reference: &Reference, op: RegistryOperation) {
        let key = TokenCacheKey::new(reference, op);
        debug!(%key.registry, %key.repository, ?op, "Purging token");
        self.tokens.write().await.remove(&key);
    }

    /// Drops every entry belonging to `registry`, whatever the repository or
    /// operation.
    ///
    /// The token half of containerd's `invalidAuthorization`, reached once a
    /// *freshly minted* token has been refused as well: at that point what is
    /// dead is the credential every scope under the host was minted from, not
    /// the one scope that was rejected, and a sibling still holding such a
    /// token would go on sending it until expiry.
    ///
    /// A plain `Bearer` challenge is why this cannot fire on the first `401`:
    /// it carries no `error` parameter, so the rejection alone does not
    /// separate a refused scope from a revoked credential. Surviving a retry
    /// with a new token does.
    pub(crate) async fn purge_registry(&self, registry: &str) {
        self.tokens
            .write()
            .await
            .retain(|key, _| key.registry != registry);
    }

    pub(crate) async fn get(
        &self,
        reference: &Reference,
        op: RegistryOperation,
    ) -> Option<RegistryTokenType> {
        let key = TokenCacheKey::new(reference, op);
        match self.tokens.read().await.get(&key) {
            Some(TokenCacheValue {
                ref token,
                expiration,
            }) => {
                if !is_live(*expiration, now_epoch_secs()) {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=true, "Fetching token");
                    None
                } else {
                    debug!(%key.registry, %key.repository, ?key.operation, %expiration, miss=false, expired=false, "Fetching token");
                    Some(token.clone())
                }
            }
            None => {
                debug!(%key.registry, %key.repository, ?key.operation, miss = true, "Fetching token");
                None
            }
        }
    }
}

/// Seconds since the Unix epoch, or `None` when the wall clock reads behind it.
///
/// A backwards clock step is precisely the condition an expiry cache is exposed
/// to, and library code must not panic on it. Every caller reads `None` as
/// "expired" or "do not cache", which re-authenticates — the fail-safe
/// direction.
fn now_epoch_secs() -> Option<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|since| since.as_secs())
}

/// Whether a cached entry is still usable at `now`.
///
/// Inside the renewal margin counts as expired, and so does a `now` of `None` —
/// a clock that has stepped behind the epoch. Both resolve to
/// "re-authenticate", which is the safe direction: the cost of a spurious miss
/// is one handshake, the cost of a spurious hit is a request that arrives with
/// a token the registry has already stopped honouring.
fn is_live(expiration: u64, now: Option<u64>) -> bool {
    now.is_some_and(|epoch| epoch <= expiration.saturating_sub(RENEWAL_MARGIN_SECS))
}

/// Grace period subtracted from every cached token's recorded expiry.
///
/// The Docker token spec's floor is 60 s, and `DEFAULT_TOKEN_EXPIRATION_SECS`
/// takes it literally, so an entry can pass a bare `now <= expiration` check
/// with a fraction of a second of validity left and authorise a request that
/// arrives expired. That was masked while `Client::auth` minted a fresh token
/// on every call; the cache-first path removed the accidental refresh, so the
/// margin arrives with it.
const RENEWAL_MARGIN_SECS: u64 = 30;

fn parse_expiration_from_jwt(token_str: &str, default_expiration_secs: usize) -> Option<u64> {
    match jsonwebtoken::dangerous::insecure_decode::<BearerTokenClaims>(token_str) {
        Ok(token) => {
            let token_exp = match token.claims.exp {
                Some(exp) => exp,
                None => {
                    // the token doesn't have a claim that states a
                    // value for the expiration. We assume it has a 60
                    // seconds validity as indicated here:
                    // https://docs.docker.com/reference/api/registry/auth/#token-response-fields
                    // > (Optional) The duration in seconds since the token was issued
                    // > that it will remain valid. When omitted, this defaults to 60 seconds.
                    // > For compatibility with older clients, a token should never be returned
                    // > with less than 60 seconds to live.
                    let expiration = now_epoch_secs()? + default_expiration_secs as u64;
                    debug!("Cannot extract expiration from token's claims, assuming a {} seconds validity", default_expiration_secs);
                    expiration
                }
            };

            Some(token_exp)
        }
        Err(error) if error.kind() == &jsonwebtoken::errors::ErrorKind::InvalidToken => {
            // The token is not a JWT (e.g., an opaque token issued by registries
            // like GHCR). Use the default expiration as a best-effort assumption,
            // mirroring the behaviour for JWT tokens that carry no `exp` claim.
            let epoch = now_epoch_secs()?;
            debug!(
                "Bearer token is not a JWT, assuming a {} seconds validity",
                default_expiration_secs
            );
            Some(epoch + default_expiration_secs as u64)
        }
        Err(error) => {
            warn!(?error, "Invalid bearer token");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header};
    use oci_spec::distribution::Reference;
    use serde::Serialize;

    // An opaque token as issued by registries like GHCR — not a JWT.
    const OPAQUE_TOKEN: &str = "ghs_exampleOpaqueTokenFromGHCR1234567890";

    #[derive(Serialize)]
    struct ClaimsWithExp {
        exp: u64,
    }

    #[derive(Serialize)]
    struct ClaimsWithoutExp {
        sub: &'static str,
    }

    fn make_jwt_with_exp(exp: u64) -> String {
        jsonwebtoken::encode(
            &Header::default(),
            &ClaimsWithExp { exp },
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("failed to encode JWT with exp")
    }

    fn make_jwt_without_exp() -> String {
        jsonwebtoken::encode(
            &Header::default(),
            &ClaimsWithoutExp { sub: "test" },
            &EncodingKey::from_secret(b"secret"),
        )
        .expect("failed to encode JWT without exp")
    }

    #[test]
    fn jwt_with_exp_uses_claims_expiration() {
        crate::test_helpers::jsonwebtoken_install_default_crypto_provider();
        let token = make_jwt_with_exp(9999999999);
        let exp = parse_expiration_from_jwt(&token, 60)
            .expect("should return Some for valid JWT with exp");
        assert_eq!(exp, 9999999999);
    }

    #[test]
    fn jwt_without_exp_uses_default_expiration() {
        crate::test_helpers::jsonwebtoken_install_default_crypto_provider();
        let token = make_jwt_without_exp();
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp =
            parse_expiration_from_jwt(&token, 60).expect("should return Some for JWT without exp");
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(exp >= before + 60);
        assert!(exp <= after + 60);
    }

    #[test]
    fn opaque_token_uses_default_expiration() {
        let before = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let exp = parse_expiration_from_jwt(OPAQUE_TOKEN, 60)
            .expect("opaque token should return Some with default expiration");
        let after = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(exp >= before + 60);
        assert!(exp <= after + 60);
    }

    /// C-029, both halves. One alone cannot tell a working renewal margin from
    /// a cache that never hits at all.
    #[test]
    fn an_entry_inside_the_renewal_margin_is_a_miss() {
        let now = 1_000_000u64;

        assert!(
            !is_live(now + 1, Some(now)),
            "a token with one second of validity left must not authorise a request"
        );
        assert!(
            !is_live(now + RENEWAL_MARGIN_SECS - 1, Some(now)),
            "one second inside the margin is still a miss"
        );
        assert!(
            is_live(now + RENEWAL_MARGIN_SECS, Some(now)),
            "exactly the margin's worth of validity is the boundary, and it is live"
        );
        assert!(
            is_live(now + 600, Some(now)),
            "a token ten minutes from expiry must be served from the cache"
        );
        assert!(
            is_live(u64::MAX, Some(now)),
            "a maximal expiry saturates rather than wrapping the margin subtraction"
        );
    }

    /// A clock that has stepped behind the Unix epoch resolves to "expired" and
    /// re-authenticates. Before this it panicked — `.expect("Time went
    /// backwards")` — from library code, on the path every `auth()` now takes.
    #[test]
    fn a_backwards_clock_expires_rather_than_panics() {
        assert!(
            !is_live(u64::MAX, None),
            "an unreadable clock must fail safe to expired, even for a never-expiring entry"
        );
    }

    #[tokio::test]
    async fn opaque_token_is_cached() {
        let cache = TokenCache::new(60);
        let reference: Reference = "ghcr.io/kubewarden/policies/pod-privileged:v1.0.10"
            .parse()
            .unwrap();
        let token = RegistryTokenType::Bearer(RegistryToken::Token {
            token: OPAQUE_TOKEN.to_string(),
        });

        cache
            .insert(&reference, RegistryOperation::Pull, token)
            .await;

        assert!(
            cache
                .get(&reference, RegistryOperation::Pull)
                .await
                .is_some(),
            "opaque bearer token should be cached"
        );
    }
}
