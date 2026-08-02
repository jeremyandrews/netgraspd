//! Reverse DNS lookups, the one place the daemon puts packets on a wire.
//!
//! The queries go to the system resolver, never to the monitored device, so
//! they do not announce Netgrasp's presence on the LAN segment being watched.
//! Even so the feature is opt-in (`identity.reverse_dns`), because "passive"
//! should mean passive unless a human said otherwise.
//!
//! Failures are not errors. A device with no PTR record is the common case, and
//! a resolver timeout must never stall the observation pipeline, so every
//! failure is logged at debug and cached as a negative result.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_resolver::TokioResolver;
use hickory_resolver::proto::rr::RData;
use tokio::sync::Mutex;

/// A caching reverse resolver.
///
/// Cloning shares the cache and the underlying resolver.
#[derive(Clone)]
pub struct ReverseResolver {
    inner: Arc<Inner>,
}

struct Inner {
    resolver: TokioResolver,
    ttl: Duration,
    cache: Mutex<HashMap<IpAddr, CacheEntry>>,
}

#[derive(Clone)]
struct CacheEntry {
    /// `None` records a negative result, which is cached exactly as long as a
    /// positive one so that a chatty device with no PTR record does not produce
    /// a query per packet.
    name: Option<String>,
    stored_at: Instant,
}

impl ReverseResolver {
    /// Builds a resolver from the system configuration.
    ///
    /// # Errors
    ///
    /// Returns an error when the system resolver configuration cannot be read.
    pub fn from_system(ttl: Duration) -> anyhow::Result<Self> {
        let resolver = TokioResolver::builder_tokio()?.build()?;
        Ok(ReverseResolver {
            inner: Arc::new(Inner {
                resolver,
                ttl,
                cache: Mutex::new(HashMap::new()),
            }),
        })
    }

    /// Looks up the PTR record for an address, consulting the cache first.
    ///
    /// Returns `None` when there is no record, when the lookup fails, or when
    /// the name is not worth using as an identity.
    pub async fn lookup(&self, ip: IpAddr) -> Option<String> {
        {
            let cache = self.inner.cache.lock().await;
            if let Some(entry) = cache.get(&ip)
                && entry.stored_at.elapsed() < self.inner.ttl
            {
                return entry.name.clone();
            }
        }

        let resolved = match self.inner.resolver.reverse_lookup(arpa_name(ip)).await {
            Ok(answer) => answer
                .answers()
                .iter()
                .find_map(|record| match &record.data {
                    RData::PTR(ptr) => clean_ptr(&ptr.to_string()),
                    _ => None,
                }),
            Err(err) => {
                tracing::debug!(%ip, %err, "reverse lookup failed");
                None
            }
        };

        let mut cache = self.inner.cache.lock().await;
        cache.insert(
            ip,
            CacheEntry {
                name: resolved.clone(),
                stored_at: Instant::now(),
            },
        );
        resolved
    }

    /// Number of cached answers, positive and negative. Exposed for the status
    /// line and for tests.
    pub async fn cache_len(&self) -> usize {
        self.inner.cache.lock().await.len()
    }
}

/// Builds the reverse-lookup name for an address.
///
/// IPv4 reverses the octets under `in-addr.arpa`; IPv6 reverses the nibbles
/// under `ip6.arpa`. Built here rather than left to the resolver so that the
/// shape is covered by a test that needs no network.
#[must_use]
pub fn arpa_name(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa.", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut out = String::with_capacity(72);
            for byte in v6.octets().iter().rev() {
                out.push_str(&format!("{:x}.{:x}.", byte & 0x0f, byte >> 4));
            }
            out.push_str("ip6.arpa.");
            out
        }
    }
}

/// Normalises a PTR answer into something worth showing a human.
///
/// Strips the trailing dot, rejects the empty name and the bare root, and
/// rejects the generated reverse names that some ISP and router firmware hand
/// out, which are just the address written backwards and carry no information a
/// human wants to read.
#[must_use]
pub fn clean_ptr(raw: &str) -> Option<String> {
    let name = raw.trim().trim_end_matches('.').trim();
    if name.is_empty() {
        return None;
    }
    let first_label = name.split('.').next().unwrap_or(name);
    if first_label.is_empty() {
        return None;
    }
    // A first label made only of digits and separators is an address in
    // disguise: `192-168-1-40.dyn.example.net` or `10.0.0.5.in-addr.arpa`.
    if first_label
        .chars()
        .all(|c| c.is_ascii_digit() || c == '-' || c == '_')
    {
        return None;
    }
    if name.ends_with("in-addr.arpa") || name.ends_with("ip6.arpa") {
        return None;
    }
    Some(name.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_the_trailing_dot() {
        assert_eq!(clean_ptr("printer.lan."), Some("printer.lan".into()));
        assert_eq!(clean_ptr("  nas.local.  "), Some("nas.local".into()));
    }

    #[test]
    fn rejects_empty_and_root() {
        assert_eq!(clean_ptr(""), None);
        assert_eq!(clean_ptr("   "), None);
        assert_eq!(clean_ptr("."), None);
    }

    #[test]
    fn rejects_addresses_wearing_a_hostname_costume() {
        assert_eq!(clean_ptr("192-168-1-40.dyn.example.net."), None);
        assert_eq!(clean_ptr("40.1.168.192.in-addr.arpa."), None);
        assert_eq!(clean_ptr("1.0.0.0.ip6.arpa"), None);
        assert_eq!(clean_ptr("10_0_0_5.isp.example."), None);
    }

    #[test]
    fn keeps_names_with_digits_that_are_still_names() {
        assert_eq!(clean_ptr("hp1234.lan."), Some("hp1234.lan".into()));
        assert_eq!(clean_ptr("pi4.local."), Some("pi4.local".into()));
    }

    #[test]
    fn builds_the_ipv4_arpa_name_in_reverse_octet_order() {
        assert_eq!(
            arpa_name("192.168.1.40".parse().expect("ip")),
            "40.1.168.192.in-addr.arpa."
        );
        assert_eq!(
            arpa_name("0.0.0.0".parse().expect("ip")),
            "0.0.0.0.in-addr.arpa."
        );
    }

    #[test]
    fn builds_the_ipv6_arpa_name_in_reverse_nibble_order() {
        // 2001:db8::1 expands to 32 nibbles, least significant first.
        let name = arpa_name("2001:db8::1".parse().expect("ip"));
        assert!(name.ends_with("ip6.arpa."), "{name}");
        assert!(name.starts_with("1.0.0.0."), "{name}");
        assert_eq!(
            name.matches('.').count(),
            32 + 2,
            "32 nibbles plus ip6.arpa."
        );
    }
}
