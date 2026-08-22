//! Caching and coalescing for the registry authentication handshake.
//!
//! Two primitives, both aimed at the same waste: N callers each running the
//! full `GET /v2/` probe plus token-realm exchange for something one of them
//! already knows.
//!
//! * [`ChallengeCache`] — the `WWW-Authenticate` probe result, remembered **per
//!   host**. The probe URL carries no repository component, so its answer is
//!   host-invariant; without this cache every distinct repository's first touch
//!   pays the round trip again. containerd's `dockerAuthorizer.handlers` is
//!   keyed the same way, and so is its invalidation: [`purge`] drops the whole
//!   host entry, which is what keeps a cached challenge from suppressing a
//!   legitimate later `401` (containers/image#2754 is that bug with no purge).
//! * [`TokenFlights`] — a per-key flight so concurrent cold callers share one
//!   token exchange. Deliberately **transient**: it holds nothing once the
//!   flight ends, so the only durable record of a successful exchange is the
//!   [`TokenCache`](crate::token_cache::TokenCache), which knows about expiry —
//!   and a *failed* exchange leaves no record at all. A primitive that retained
//!   the leader's error would turn one token-endpoint 5xx into a permanent auth
//!   failure for that key for the life of the process.
//!
//! [`purge`]: ChallengeCache::purge

use std::collections::HashMap;
use std::future::Future;
use std::sync::{Arc, Mutex, Weak};

use tokio::sync::OnceCell;

use crate::client::BearerChallenge;
use crate::errors::Result;
use crate::token_cache::{RegistryTokenType, TokenCacheKey};

/// What `GET /v2/` said about how a host wants to be authenticated.
#[derive(Clone, Debug)]
pub(crate) enum ChallengeInfo {
    /// No `WWW-Authenticate` header — the host asked for nothing.
    Unchallenged,
    /// A `WWW-Authenticate` header that is not a bearer challenge this client
    /// can satisfy. The caller falls back to HTTP Basic if it holds any.
    Unsupported,
    /// A parsed bearer challenge.
    Bearer(BearerChallenge),
}

/// Per-host cache of the `GET /v2/` challenge probe.
#[derive(Default)]
pub(crate) struct ChallengeCache {
    hosts: Mutex<HashMap<String, Arc<OnceCell<ChallengeInfo>>>>,
}

impl ChallengeCache {
    /// Returns the challenge for `host`, running `probe` exactly once across
    /// concurrent cold callers.
    ///
    /// A failing probe caches nothing — [`OnceCell::get_or_try_init`] leaves the
    /// cell uninitialised and releases its permit, so the next caller probes
    /// again rather than inheriting a failure it never made.
    pub(crate) async fn get_or_probe<F, Fut>(&self, host: &str, probe: F) -> Result<ChallengeInfo>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<ChallengeInfo>>,
    {
        let cell = {
            let mut hosts = self.lock();
            match hosts.get(host) {
                Some(cell) => Arc::clone(cell),
                None => Arc::clone(hosts.entry(host.to_string()).or_default()),
            }
        };
        cell.get_or_try_init(probe).await.map(Clone::clone)
    }

    /// Forgets everything probed about `host`.
    ///
    /// containerd's `invalidAuthorization`, minus the token half (the caller
    /// purges [`TokenCache`](crate::token_cache::TokenCache) alongside): a `401`
    /// naming an `error` means what was cached for the host is stale, and the
    /// next request must rebuild it from a fresh probe.
    pub(crate) fn purge(&self, host: &str) {
        self.lock().remove(host);
    }

    /// A poisoned map is still a valid map — a panicking probe cannot corrupt
    /// it, because the map is never held across the probe's `await`.
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Arc<OnceCell<ChallengeInfo>>>> {
        self.hosts
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// In-flight token exchanges, one per `(registry, repository, operation)`.
#[derive(Default)]
pub(crate) struct TokenFlights {
    // `Weak`, not `Arc`: the flight exists only while somebody is waiting on
    // it. Retaining the value here would shadow the token cache's expiry
    // handling with an entry that never renews.
    in_flight: Mutex<HashMap<TokenCacheKey, Weak<OnceCell<Option<RegistryTokenType>>>>>,
}

impl TokenFlights {
    /// Runs `exchange` for `key`, or joins the one already running.
    ///
    /// Every waiter observes the leader's outcome. A leader that fails — or is
    /// cancelled mid-flight — hands the flight to a waiter, which runs the
    /// exchange itself: correct for a token fetch, where the right answer to a
    /// transient failure is another attempt rather than an inherited error.
    pub(crate) async fn acquire<F, Fut>(
        &self,
        key: TokenCacheKey,
        exchange: F,
    ) -> Result<Option<RegistryTokenType>>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<Option<RegistryTokenType>>>,
    {
        let cell = {
            let mut in_flight = self
                .in_flight
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            match in_flight.get(&key).and_then(Weak::upgrade) {
                Some(cell) => cell,
                None => {
                    // Reap keys whose flight has finished. Only reached on a
                    // miss, which is already about to pay for a handshake.
                    in_flight.retain(|_, flight| flight.strong_count() > 0);
                    let cell = Arc::new(OnceCell::new());
                    in_flight.insert(key, Arc::downgrade(&cell));
                    cell
                }
            }
        };
        cell.get_or_try_init(exchange).await.map(Clone::clone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use crate::errors::OciDistributionError;
    use crate::token_cache::{RegistryOperation, RegistryToken};
    use crate::Reference;

    fn key(repository: &str) -> TokenCacheKey {
        let reference: Reference = format!("registry.example.com/{repository}:latest")
            .parse()
            .unwrap();
        TokenCacheKey::new(&reference, RegistryOperation::Pull)
    }

    fn token(value: &str) -> Option<RegistryTokenType> {
        Some(RegistryTokenType::Bearer(RegistryToken::Token {
            token: value.to_string(),
        }))
    }

    /// A failed flight leaves nothing behind: the next caller runs the exchange
    /// again rather than inheriting the error.
    #[tokio::test]
    async fn a_failed_flight_is_not_retained() {
        let flights = TokenFlights::default();
        let runs = AtomicUsize::new(0);

        let first = flights
            .acquire(key("failing"), || async {
                runs.fetch_add(1, Ordering::SeqCst);
                Err(OciDistributionError::AuthenticationFailure("nope".into()))
            })
            .await;
        assert!(first.is_err(), "the leader's failure must surface");

        let second = flights
            .acquire(key("failing"), || async {
                runs.fetch_add(1, Ordering::SeqCst);
                Ok(token("recovered"))
            })
            .await;
        assert!(second.is_ok(), "a later caller must be able to succeed");
        assert_eq!(
            runs.load(Ordering::SeqCst),
            2,
            "the second call must run its own exchange, not replay a cached failure"
        );
    }

    /// Nothing survives a completed flight, so a second sequential call runs a
    /// fresh exchange — expiry is the token cache's job, not this map's.
    #[tokio::test]
    async fn a_finished_flight_holds_no_result() {
        let flights = TokenFlights::default();
        let runs = AtomicUsize::new(0);

        for _ in 0..2 {
            flights
                .acquire(key("done"), || async {
                    runs.fetch_add(1, Ordering::SeqCst);
                    Ok(token("t"))
                })
                .await
                .unwrap();
        }

        assert_eq!(runs.load(Ordering::SeqCst), 2);
    }

    /// A purged host is re-probed; an unpurged one is not.
    #[tokio::test]
    async fn purge_drops_only_the_named_host() {
        let cache = ChallengeCache::default();
        let probes = AtomicUsize::new(0);
        let probe = || async {
            probes.fetch_add(1, Ordering::SeqCst);
            Ok(ChallengeInfo::Unchallenged)
        };

        cache.get_or_probe("a.example.com", probe).await.unwrap();
        cache.get_or_probe("b.example.com", probe).await.unwrap();
        cache.get_or_probe("a.example.com", probe).await.unwrap();
        assert_eq!(
            probes.load(Ordering::SeqCst),
            2,
            "a warm host must not re-probe"
        );

        cache.purge("a.example.com");
        cache.get_or_probe("b.example.com", probe).await.unwrap();
        assert_eq!(
            probes.load(Ordering::SeqCst),
            2,
            "purging one host must not evict another"
        );
        cache.get_or_probe("a.example.com", probe).await.unwrap();
        assert_eq!(
            probes.load(Ordering::SeqCst),
            3,
            "the purged host must re-probe"
        );
    }
}
