//! The UniFi controller enricher.
//!
//! Reads the connected-client list from a UniFi controller and reports which
//! access point each device is associated with. That is the single fact the
//! location model needs; everything else here exists to get it reliably from a
//! controller that comes in two API shapes and expires sessions without warning.
//!
//! ## Two controller shapes
//!
//! A classic self-hosted controller answers at `/api/login` and
//! `/api/s/{site}/…`. A UniFi OS console (a UDM, a Cloud Key running UniFi OS)
//! answers at `/api/auth/login` and puts the network application behind
//! `/proxy/network/api/s/{site}/…`. Which one is in front of you is not knowable
//! from configuration a human would enjoy writing, so [`UnifiEnricher`] finds
//! out once and remembers.
//!
//! ## Why the AP device list is fetched too
//!
//! `stat/sta` reports the access point a client is on as `ap_mac`, not as a
//! name. The operator's location map is keyed on names, because `Living Room AP`
//! is what they typed into the controller and `f4:e2:c6:…` is not something
//! anybody wants in a config file. So each poll also reads `stat/device`, which
//! is the AP inventory, and resolves the MAC to its name. An AP that cannot be
//! resolved falls back to its MAC, which the location map will then pass through
//! as the location: ugly, visible, and never silently absent.
//!
//! ## Failure is expected, not exceptional
//!
//! A home controller reboots for firmware, loses power, and expires sessions.
//! Every one of those produces a logged warning and no enrichments. The
//! orchestrator keeps every device's last known location, so a controller that
//! is down for an hour means locations go stale, never that they vanish.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value as Json;
use tokio::sync::Mutex;

use crate::config::UnifiConfig;
use crate::device::DeviceSnapshot;
use crate::enrich::{Enricher, Enrichment};
use crate::types::MacAddr;

/// Short stable name for this enricher.
pub const SOURCE: &str = "unifi";

/// How long any single request may take.
///
/// Comfortably longer than a healthy controller needs and comfortably shorter
/// than the default poll interval, so a hung controller cannot make polls pile
/// up behind each other.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// The path prefix a UniFi OS console puts the network application behind.
const UNIFI_OS_PREFIX: &str = "/proxy/network";

/// How the enricher proves who it is.
#[derive(Debug, Clone)]
enum Auth {
    /// A controller API key, sent on every request. Preferred, because it cannot
    /// expire in the middle of a poll.
    ApiKey(String),
    /// A local account, exchanged for a session cookie.
    Login {
        /// Account name.
        username: String,
        /// Account password.
        password: String,
    },
}

/// What the enricher has worked out about the controller so far.
#[derive(Debug, Default)]
struct Session {
    /// `""` for a classic controller, `/proxy/network` for UniFi OS. `None`
    /// until the first successful request settles it.
    prefix: Option<String>,
    /// Whether a login has succeeded since the last authentication failure.
    /// Always false for [`Auth::ApiKey`], which needs no session.
    logged_in: bool,
}

/// Reads client associations from a UniFi controller.
pub struct UnifiEnricher {
    client: reqwest::Client,
    base: String,
    site: String,
    auth: Auth,
    poll_interval: Duration,
    session: Mutex<Session>,
}

impl UnifiEnricher {
    /// Builds the enricher.
    ///
    /// Does not connect: the first poll does, so an unreachable controller at
    /// startup is a warning on the first poll rather than a daemon that refuses
    /// to watch the network.
    ///
    /// # Errors
    ///
    /// Returns an error when the HTTP client cannot be constructed, which in
    /// practice means the TLS backend failed to initialise.
    pub fn new(cfg: &UnifiConfig) -> Result<Self> {
        let auth = if cfg.api_key.trim().is_empty() {
            Auth::Login {
                username: cfg.username.trim().to_string(),
                password: cfg.password.clone(),
            }
        } else {
            Auth::ApiKey(cfg.api_key.trim().to_string())
        };
        if !cfg.verify_tls {
            tracing::warn!(
                controller = %cfg.controller_url,
                "TLS verification is off for the UniFi controller: the connection is \
                 encrypted but the controller's identity is not checked"
            );
        }
        let client = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("netgraspd/", env!("CARGO_PKG_VERSION")))
            .cookie_store(true)
            .danger_accept_invalid_certs(!cfg.verify_tls)
            .build()
            .context("could not build the HTTP client for the UniFi enricher")?;
        Ok(UnifiEnricher {
            client,
            base: cfg.controller_url.trim().trim_end_matches('/').to_string(),
            site: cfg.site.trim().to_string(),
            auth,
            poll_interval: cfg.poll_interval.get(),
            session: Mutex::new(Session::default()),
        })
    }

    /// Builds a URL under the discovered prefix.
    fn url(&self, prefix: &str, path: &str) -> String {
        format!("{}{prefix}{path}", self.base)
    }

    /// Logs in, discovering which controller shape this is on the way.
    ///
    /// Tries the UniFi OS endpoint first and falls back to the classic one. The
    /// order matters only for speed; both are tried before giving up.
    async fn login(&self) -> Result<String> {
        let Auth::Login { username, password } = &self.auth else {
            // An API key needs no session, so discovery is the only thing left
            // to do and a probe of the client list does it.
            return self.discover_prefix().await;
        };
        let body = serde_json::json!({ "username": username, "password": password });
        let mut failures = Vec::new();
        for (prefix, path) in [("", "/api/auth/login"), ("", "/api/login")] {
            let url = self.url(prefix, path);
            let response = match self.client.post(&url).json(&body).send().await {
                Ok(response) => response,
                Err(err) => {
                    failures.push(format!("{url}: {err}"));
                    continue;
                }
            };
            let status = response.status();
            if status.is_success() {
                // A UniFi OS console accepts /api/auth/login and then serves the
                // network application behind /proxy/network. A classic
                // controller accepts /api/login and serves it at the root.
                let prefix = if path == "/api/auth/login" {
                    UNIFI_OS_PREFIX
                } else {
                    ""
                };
                tracing::info!(
                    controller = %self.base,
                    endpoint = path,
                    "authenticated to the UniFi controller"
                );
                return Ok(prefix.to_string());
            }
            if status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN
            {
                // Credentials reached a real login endpoint and were refused.
                // Trying the other shape would only produce a worse message.
                bail!("the UniFi controller rejected the configured credentials ({status})");
            }
            failures.push(format!("{url}: {status}"));
        }
        bail!(
            "could not log in to the UniFi controller at {}: {}",
            self.base,
            failures.join("; ")
        )
    }

    /// Works out which controller shape this is by asking for the client list.
    async fn discover_prefix(&self) -> Result<String> {
        let mut failures = Vec::new();
        for prefix in ["", UNIFI_OS_PREFIX] {
            let url = self.url(prefix, &format!("/api/s/{}/stat/sta", self.site));
            match self.authorised(self.client.get(&url)).send().await {
                Ok(response) if response.status().is_success() => return Ok(prefix.to_string()),
                Ok(response) => failures.push(format!("{url}: {}", response.status())),
                Err(err) => failures.push(format!("{url}: {err}")),
            }
        }
        bail!(
            "could not reach the UniFi network API at {}: {}",
            self.base,
            failures.join("; ")
        )
    }

    /// Attaches the API key, when that is how this enricher authenticates.
    fn authorised(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match &self.auth {
            Auth::ApiKey(key) => request.header("X-API-KEY", key),
            Auth::Login { .. } => request,
        }
    }

    /// Ensures there is a usable session and returns the path prefix to use.
    async fn ensure_session(&self) -> Result<String> {
        let mut session = self.session.lock().await;
        let needs_login = matches!(self.auth, Auth::Login { .. }) && !session.logged_in;
        if let Some(prefix) = &session.prefix
            && !needs_login
        {
            return Ok(prefix.clone());
        }
        let prefix = self.login().await?;
        session.prefix = Some(prefix.clone());
        session.logged_in = true;
        Ok(prefix)
    }

    /// Forgets the session so the next request logs in again.
    async fn invalidate_session(&self) {
        let mut session = self.session.lock().await;
        session.logged_in = false;
    }

    /// Fetches one API path, logging in again once if the session expired.
    ///
    /// A controller expires sessions on its own schedule, so an authentication
    /// failure mid-poll is an ordinary event and not an error. It is retried
    /// exactly once: a second failure means the credentials are wrong rather
    /// than stale, and retrying a wrong password in a loop is how accounts get
    /// locked.
    async fn get(&self, path: &str) -> Result<Json> {
        let mut prefix = self.ensure_session().await?;
        for attempt in 0..2 {
            let url = self.url(&prefix, path);
            let response = self
                .authorised(self.client.get(&url))
                .send()
                .await
                .with_context(|| format!("could not reach {url}"))?;
            let status = response.status();
            if status.is_success() {
                return response
                    .json::<Json>()
                    .await
                    .with_context(|| format!("{url} did not answer with JSON"));
            }
            let recoverable = status == reqwest::StatusCode::UNAUTHORIZED
                || status == reqwest::StatusCode::FORBIDDEN;
            if !recoverable || attempt == 1 {
                bail!("{url} returned {status}");
            }
            tracing::info!(
                controller = %self.base,
                %status,
                "the UniFi session expired mid-poll; logging in again"
            );
            self.invalidate_session().await;
            prefix = self.ensure_session().await?;
        }
        unreachable!("the loop returns or bails on both attempts")
    }

    /// Reads the access point inventory, as a MAC-to-name map.
    ///
    /// A failure here is not fatal to the poll: without it every AP falls back
    /// to its MAC, which is worse to read but still places the device.
    async fn access_points(&self) -> HashMap<String, String> {
        let path = format!("/api/s/{}/stat/device", self.site);
        let body = match self.get(&path).await {
            Ok(body) => body,
            Err(err) => {
                tracing::warn!(%err, "could not read the UniFi access point list; falling back to AP MACs");
                return HashMap::new();
            }
        };
        let mut out = HashMap::new();
        for device in body
            .get("data")
            .and_then(Json::as_array)
            .into_iter()
            .flatten()
        {
            let (Some(mac), Some(name)) = (
                device.get("mac").and_then(Json::as_str),
                device
                    .get("name")
                    .and_then(Json::as_str)
                    .filter(|n| !n.trim().is_empty()),
            ) else {
                continue;
            };
            out.insert(mac.to_ascii_lowercase(), name.trim().to_string());
        }
        out
    }
}

/// One entry of the controller's connected-client list.
///
/// Only the fields Netgrasp uses are named; a controller sends dozens more and
/// serde ignores them.
#[derive(Debug, Clone, Deserialize)]
struct Station {
    mac: String,
    #[serde(default)]
    ap_mac: Option<String>,
    /// Some controller versions do name the AP inline. When they do it is used
    /// directly and the inventory lookup is skipped.
    #[serde(default)]
    ap_name: Option<String>,
    #[serde(default)]
    essid: Option<String>,
    #[serde(default)]
    vlan: Option<i64>,
    #[serde(default)]
    rx_bytes: Option<i64>,
    #[serde(default)]
    tx_bytes: Option<i64>,
    #[serde(default)]
    is_wired: Option<bool>,
}

#[async_trait]
impl Enricher for UnifiEnricher {
    fn name(&self) -> &str {
        SOURCE
    }

    fn poll_interval(&self) -> Option<Duration> {
        Some(self.poll_interval)
    }

    async fn enrich(&self, devices: &[DeviceSnapshot]) -> Result<Vec<Enrichment>> {
        let body = self
            .get(&format!("/api/s/{}/stat/sta", self.site))
            .await
            .context("reading the UniFi client list")?;
        let stations: Vec<Station> =
            serde_json::from_value(body.get("data").cloned().unwrap_or(Json::Null))
                .context("the UniFi client list was not in the expected shape")?;

        // Only look up AP names if at least one station needs one.
        let needs_inventory = stations
            .iter()
            .any(|s| s.ap_name.is_none() && s.ap_mac.is_some());
        let inventory = if needs_inventory {
            self.access_points().await
        } else {
            HashMap::new()
        };

        // Devices Netgrasp has never seen are ignored: the controller knows
        // about guests on VLANs this daemon does not watch, and inventing device
        // rows from an API would break the rule that a device exists because a
        // packet from it was seen.
        let known: std::collections::HashSet<MacAddr> = devices.iter().map(|d| d.mac).collect();

        let mut out = Vec::with_capacity(stations.len());
        let mut unknown = 0usize;
        for station in stations {
            let Ok(mac) = station.mac.parse::<MacAddr>() else {
                tracing::debug!(mac = %station.mac, "the controller reported an unparseable MAC");
                continue;
            };
            if !known.is_empty() && !known.contains(&mac) {
                unknown += 1;
                continue;
            }
            let ap_name = station
                .ap_name
                .as_deref()
                .map(str::trim)
                .filter(|n| !n.is_empty())
                .map(str::to_string)
                .or_else(|| {
                    station.ap_mac.as_ref().map(|ap_mac| {
                        let key = ap_mac.to_ascii_lowercase();
                        inventory.get(&key).cloned().unwrap_or(key)
                    })
                });

            let mut extra = serde_json::Map::new();
            if let Some(essid) = station.essid.filter(|e| !e.trim().is_empty()) {
                extra.insert("essid".into(), Json::from(essid));
            }
            if let Some(wired) = station.is_wired {
                extra.insert("wired".into(), Json::from(wired));
            }

            out.push(Enrichment {
                mac,
                ap_name,
                ap_location: None,
                vlan: station.vlan,
                bandwidth_rx: station.rx_bytes,
                bandwidth_tx: station.tx_bytes,
                extra: if extra.is_empty() {
                    Json::Null
                } else {
                    Json::Object(extra)
                },
            });
        }
        if unknown > 0 {
            tracing::debug!(
                unknown,
                "the controller reported clients netgraspd has never seen; ignoring them"
            );
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> UnifiConfig {
        UnifiConfig {
            enabled: true,
            controller_url: "https://192.168.1.1/".into(),
            api_key: "secret".into(),
            site: "default".into(),
            ..UnifiConfig::default()
        }
    }

    #[test]
    fn the_trailing_slash_on_a_controller_url_does_not_double_up() {
        let e = UnifiEnricher::new(&cfg()).expect("builds");
        assert_eq!(
            e.url("", "/api/s/default/stat/sta"),
            "https://192.168.1.1/api/s/default/stat/sta"
        );
        assert_eq!(
            e.url(UNIFI_OS_PREFIX, "/api/s/default/stat/sta"),
            "https://192.168.1.1/proxy/network/api/s/default/stat/sta"
        );
    }

    #[test]
    fn an_api_key_is_preferred_over_a_username_and_password() {
        let cfg = UnifiConfig {
            username: "admin".into(),
            password: "hunter2".into(),
            ..cfg()
        };
        let e = UnifiEnricher::new(&cfg).expect("builds");
        assert!(
            matches!(e.auth, Auth::ApiKey(_)),
            "a key that cannot expire mid-poll wins"
        );
    }

    #[test]
    fn credentials_are_used_when_no_api_key_is_set() {
        let cfg = UnifiConfig {
            api_key: String::new(),
            username: "admin".into(),
            password: "hunter2".into(),
            ..cfg()
        };
        let e = UnifiEnricher::new(&cfg).expect("builds");
        assert!(matches!(e.auth, Auth::Login { .. }));
    }

    #[test]
    fn the_enricher_reports_its_name_and_interval() {
        let e = UnifiEnricher::new(&cfg()).expect("builds");
        assert_eq!(e.name(), "unifi");
        assert_eq!(e.poll_interval(), Some(Duration::from_secs(30)));
    }

    #[test]
    fn a_station_decodes_from_the_fields_a_controller_actually_sends() {
        // Trimmed from a real stat/sta response. The point is that the dozens of
        // fields not named here are ignored rather than rejected.
        let raw = serde_json::json!({
            "mac": "3c:22:fb:9a:1b:2c",
            "ap_mac": "F4:E2:C6:11:22:33",
            "essid": "Casa",
            "vlan": 20,
            "rx_bytes": 1_234_567,
            "tx_bytes": 7_654_321,
            "is_wired": false,
            "uptime": 4021,
            "signal": -58,
            "something_new_in_the_next_firmware": true
        });
        let station: Station = serde_json::from_value(raw).expect("decodes");
        assert_eq!(station.mac, "3c:22:fb:9a:1b:2c");
        assert_eq!(station.ap_mac.as_deref(), Some("F4:E2:C6:11:22:33"));
        assert_eq!(station.vlan, Some(20));
        assert_eq!(station.is_wired, Some(false));
        assert!(station.ap_name.is_none());
    }

    #[test]
    fn a_wired_station_with_no_access_point_still_decodes() {
        let station: Station =
            serde_json::from_value(serde_json::json!({ "mac": "b8:27:eb:00:00:01" }))
                .expect("decodes");
        assert!(station.ap_mac.is_none());
        assert!(station.vlan.is_none());
    }
}
