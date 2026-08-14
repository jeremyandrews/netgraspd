//! The UniFi enricher, driven through the full enrichment pipeline against a
//! mock controller.
//!
//! There is no real controller in CI and there was none on the machine this was
//! written on, so the mock is the evidence. It is a real HTTP server on a real
//! socket rather than an injected fake client, which means the code under test
//! is the code that ships: the login negotiation, the header, the JSON decoding
//! and the retry after an expired session all run for real.
//!
//! The mock is deliberately hand-rolled rather than a crate. It has to script
//! per-request behaviour ("answer 401 to exactly the second `stat/sta` call"),
//! which is easier to express in eighty lines of TCP than to configure.

mod common;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use chrono::{DateTime, TimeZone, Utc};
use netgraspd::config::UnifiConfig;
use netgraspd::db::queries;
use netgraspd::device::Manager;
use netgraspd::device::persist::Persister;
use netgraspd::enrich::{Enricher, Orchestrator};
use netgraspd::location::LocationMap;
use netgraspd::types::{MacAddr, Observation, ObservationKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

const PHONE: &str = "3c:22:fb:9a:1b:2c";
const LAPTOP: &str = "b8:27:eb:00:00:02";
const STRANGER: &str = "02:aa:bb:cc:dd:ee";
const KITCHEN_AP_MAC: &str = "f4:e2:c6:11:22:33";

fn base() -> DateTime<Utc> {
    Utc.with_ymd_and_hms(2026, 8, 14, 17, 0, 0)
        .single()
        .expect("valid time")
}

fn mac(s: &str) -> MacAddr {
    s.parse().expect("test mac")
}

/// How the mock controller should behave.
#[derive(Debug, Default)]
struct Script {
    /// Answer `/api/auth/login` rather than 404ing it, and serve the network
    /// application behind `/proxy/network`.
    unifi_os: bool,
    /// Answer this many `stat/sta` requests with 401 before succeeding, to
    /// simulate a session expiring mid-poll.
    expire_next: usize,
    /// Answer `stat/sta` with a transport-level failure by closing the socket.
    hang_up: bool,
    /// Answer the login endpoint with 401: the password reached a real login
    /// and was refused.
    reject_login: bool,
    /// Whether `stat/device` answers at all.
    serve_inventory: bool,
    /// Every `X-API-KEY` header value the server has seen.
    api_keys: Vec<String>,
    /// Request paths the server has seen, in order.
    seen: Vec<String>,
}

/// A mock UniFi controller on a real socket.
struct MockController {
    addr: SocketAddr,
    script: Arc<Mutex<Script>>,
    logins: Arc<AtomicUsize>,
}

impl MockController {
    /// Starts a controller. It stops when the test ends and the task is dropped.
    async fn start(script: Script) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("addr");
        let script = Arc::new(Mutex::new(script));
        let logins = Arc::new(AtomicUsize::new(0));

        let task_script = Arc::clone(&script);
        let task_logins = Arc::clone(&logins);
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    return;
                };
                let script = Arc::clone(&task_script);
                let logins = Arc::clone(&task_logins);
                tokio::spawn(async move {
                    let _ = serve(stream, script, logins).await;
                });
            }
        });

        MockController {
            addr,
            script,
            logins,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn config(&self) -> UnifiConfig {
        let mut cfg = UnifiConfig {
            enabled: true,
            controller_url: self.url(),
            api_key: "test-key".into(),
            site: "default".into(),
            ..UnifiConfig::default()
        };
        cfg.locations.insert("Kitchen AP".into(), "Kitchen".into());
        cfg.locations
            .insert("Driveway AP".into(), "Driveway".into());
        cfg.edge_aps = vec!["Driveway AP".into()];
        cfg
    }

    async fn seen(&self) -> Vec<String> {
        self.script.lock().await.seen.clone()
    }

    async fn api_keys(&self) -> Vec<String> {
        self.script.lock().await.api_keys.clone()
    }
}

/// Serves one connection, one request at a time.
async fn serve(
    mut stream: TcpStream,
    script: Arc<Mutex<Script>>,
    logins: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    // One request per connection: every response carries `Connection: close`,
    // which keeps the mock to the part of HTTP/1.1 that is worth hand-rolling.
    {
        let Some(request) = read_request(&mut stream).await? else {
            return Ok(());
        };
        let mut script = script.lock().await;
        script.seen.push(request.path.clone());
        if let Some(key) = request.headers.get("x-api-key") {
            script.api_keys.push(key.clone());
        }

        let prefix = if script.unifi_os {
            "/proxy/network"
        } else {
            ""
        };
        let sta = format!("{prefix}/api/s/default/stat/sta");
        let device = format!("{prefix}/api/s/default/stat/device");

        let (status, body) = if request.path == "/api/auth/login" {
            if script.reject_login {
                logins.fetch_add(1, Ordering::SeqCst);
                (
                    401,
                    "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.Invalid\"}}".into(),
                )
            } else if script.unifi_os {
                logins.fetch_add(1, Ordering::SeqCst);
                (200, ok_body())
            } else {
                (404, "not found".to_string())
            }
        } else if request.path == "/api/login" {
            if script.reject_login {
                logins.fetch_add(1, Ordering::SeqCst);
                (
                    401,
                    "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.Invalid\"}}".into(),
                )
            } else if script.unifi_os {
                (404, "not found".to_string())
            } else {
                logins.fetch_add(1, Ordering::SeqCst);
                (200, ok_body())
            }
        } else if request.path == sta {
            if script.hang_up {
                // Close without answering: the transport failure a controller
                // that is rebooting produces.
                return Ok(());
            }
            if script.expire_next > 0 {
                script.expire_next -= 1;
                (
                    401,
                    "{\"meta\":{\"rc\":\"error\",\"msg\":\"api.err.LoginRequired\"}}".into(),
                )
            } else {
                (200, stations_body())
            }
        } else if request.path == device {
            if script.serve_inventory {
                (200, inventory_body())
            } else {
                (500, "inventory is unavailable".to_string())
            }
        } else {
            (404, "not found".to_string())
        };
        drop(script);

        let reason = if status == 200 { "OK" } else { "Error" };
        let response = format!(
            "HTTP/1.1 {status} {reason}\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n{body}",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.flush().await?;
    }
    Ok(())
}

/// One parsed request.
struct Request {
    path: String,
    headers: HashMap<String, String>,
}

/// Reads one HTTP request, returning `None` at end of stream.
async fn read_request(stream: &mut TcpStream) -> std::io::Result<Option<Request>> {
    let mut buffer = Vec::new();
    let mut byte = [0u8; 1];
    while !buffer.ends_with(b"\r\n\r\n") {
        let read = stream.read(&mut byte).await?;
        if read == 0 {
            return Ok(None);
        }
        buffer.push(byte[0]);
    }
    let text = String::from_utf8_lossy(&buffer).into_owned();
    let mut lines = text.lines();
    let request_line = lines.next().unwrap_or_default();
    let path = request_line
        .split_whitespace()
        .nth(1)
        .unwrap_or("/")
        .to_string();

    let mut headers = HashMap::new();
    let mut content_length = 0usize;
    for line in lines {
        if let Some((name, value)) = line.split_once(':') {
            let name = name.trim().to_lowercase();
            let value = value.trim().to_string();
            if name == "content-length" {
                content_length = value.parse().unwrap_or(0);
            }
            headers.insert(name, value);
        }
    }
    if content_length > 0 {
        let mut body = vec![0u8; content_length];
        stream.read_exact(&mut body).await?;
    }
    Ok(Some(Request { path, headers }))
}

fn ok_body() -> String {
    "{\"meta\":{\"rc\":\"ok\"},\"data\":[]}".to_string()
}

/// A `stat/sta` response, trimmed from a real one.
///
/// The phone reports only `ap_mac`, so its AP name has to come from the
/// inventory. The laptop is wired and reports no access point at all. The
/// stranger is a guest netgraspd has never seen.
fn stations_body() -> String {
    serde_json::json!({
        "meta": { "rc": "ok" },
        "data": [
            {
                "mac": PHONE,
                "ap_mac": KITCHEN_AP_MAC,
                "essid": "Casa",
                "vlan": 20,
                "rx_bytes": 1_234_567,
                "tx_bytes": 7_654_321,
                "is_wired": false,
                "uptime": 4021,
                "signal": -58,
                "a_field_from_a_later_firmware": true
            },
            {
                "mac": LAPTOP,
                "is_wired": true,
                "rx_bytes": 42
            },
            {
                "mac": STRANGER,
                "ap_mac": KITCHEN_AP_MAC,
                "is_wired": false
            }
        ]
    })
    .to_string()
}

/// A `stat/device` response: the access point inventory.
fn inventory_body() -> String {
    serde_json::json!({
        "meta": { "rc": "ok" },
        "data": [
            { "mac": KITCHEN_AP_MAC.to_uppercase(), "name": "Kitchen AP", "model": "U6LR" },
            { "mac": "f4:e2:c6:44:55:66", "name": "Driveway AP", "model": "U6M" }
        ]
    })
    .to_string()
}

/// Manager, persister and database, with the enrichment step wired the way the
/// daemon wires it.
struct Pipeline {
    manager: Manager,
    persister: Persister,
    map: LocationMap,
}

impl Pipeline {
    fn new(cfg: &UnifiConfig) -> Self {
        Pipeline {
            manager: Manager::new(netgraspd::config::StateConfig::default(), false),
            persister: Persister::new(),
            map: LocationMap::from_unifi(cfg),
        }
    }

    /// Creates a device by observing it.
    async fn see(&mut self, db: &common::TestDb, m: &str) {
        let observation = Observation::new(
            mac(m),
            None,
            "eth0",
            "arp",
            ObservationKind::Request,
            base(),
        );
        let effects = self.manager.observe(&observation);
        let client = db.client().await;
        self.persister
            .apply(&client, &effects)
            .await
            .expect("applying");
    }

    /// Runs one enrichment round, as `daemon::apply_enrichments` does.
    async fn enrich(&mut self, db: &common::TestDb, orchestrator: &mut Orchestrator) -> usize {
        let devices = self.manager.snapshot();
        let enrichments = orchestrator
            .poll_due(tokio::time::Instant::now(), &devices)
            .await;
        let mut applied = 0;
        for enrichment in &enrichments {
            let Some(ap) = enrichment.ap_name.as_deref() else {
                continue;
            };
            let place = self.map.place(ap);
            let previous = self.manager.current_ap(enrichment.mac);
            let movement = self.map.movement(previous.as_deref(), &place.ap_name);
            let effects = self.manager.set_location(
                enrichment.mac,
                &place,
                movement,
                enrichment.telemetry(),
                base(),
            );
            if effects.is_empty() {
                continue;
            }
            applied += 1;
            let client = db.client().await;
            self.persister
                .apply(&client, &effects)
                .await
                .expect("applying");
        }
        // The denormalised columns land on the ordinary flush.
        let dirty = self.manager.take_dirty();
        let client = db.client().await;
        self.persister.flush(&client, &dirty).await.expect("flush");
        applied
    }
}

async fn orchestrator_for(cfg: &UnifiConfig) -> Orchestrator {
    Orchestrator::from_config(&netgraspd::config::EnrichmentConfig {
        enabled: true,
        unifi: cfg.clone(),
    })
    .expect("builds")
}

#[tokio::test]
async fn a_poll_places_known_devices_and_ignores_clients_it_has_never_seen() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: true,
        ..Script::default()
    })
    .await;
    let cfg = controller.config();
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;
    pipeline.see(&db, LAPTOP).await;

    let mut orchestrator = orchestrator_for(&cfg).await;
    assert_eq!(pipeline.enrich(&db, &mut orchestrator).await, 1);

    let client = db.client().await;
    let phone = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the phone");
    assert_eq!(
        phone.current_ap.as_deref(),
        Some("Kitchen AP"),
        "the ap_mac was resolved to its name from the device inventory"
    );
    assert_eq!(phone.current_location.as_deref(), Some("Kitchen"));

    // The wired laptop reports no access point, so it is placed nowhere rather
    // than somewhere invented.
    let laptop = queries::find_device_by_mac(&client, mac(LAPTOP))
        .await
        .expect("lookup")
        .expect("the laptop");
    assert_eq!(laptop.current_ap, None);

    // The guest netgraspd has never seen did not become a device.
    assert!(
        queries::find_device_by_mac(&client, mac(STRANGER))
            .await
            .expect("lookup")
            .is_none(),
        "a device exists because a packet from it was seen, never because an API mentioned it"
    );
    assert_eq!(db.count("ng_devices").await, 2);
}

#[tokio::test]
async fn the_controllers_telemetry_rides_in_the_event_rather_than_in_a_column() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: true,
        ..Script::default()
    })
    .await;
    let cfg = controller.config();
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;
    let mut orchestrator = orchestrator_for(&cfg).await;
    pipeline.enrich(&db, &mut orchestrator).await;

    let details: serde_json::Value = db
        .client()
        .await
        .query_one(
            "SELECT details FROM ng_events WHERE event_type = 'device_location_changed'",
            &[],
        )
        .await
        .expect("the location event")
        .get("details");

    assert_eq!(details["ap"], "Kitchen AP");
    assert_eq!(details["location"], "Kitchen");
    assert_eq!(details["telemetry"]["vlan"], 20);
    assert_eq!(details["telemetry"]["bandwidth_rx"], 1_234_567);
    assert_eq!(details["telemetry"]["bandwidth_tx"], 7_654_321);
    assert_eq!(details["telemetry"]["extra"]["essid"], "Casa");
    assert_eq!(details["telemetry"]["extra"]["wired"], false);
}

#[tokio::test]
async fn a_session_that_expires_mid_poll_is_re_established_and_the_poll_succeeds() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Local credentials rather than an API key, because only a session can
    // expire. The controller answers the first stat/sta with 401.
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: true,
        expire_next: 1,
        ..Script::default()
    })
    .await;
    let cfg = UnifiConfig {
        api_key: String::new(),
        username: "admin".into(),
        password: "hunter2".into(),
        ..controller.config()
    };
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;

    let mut orchestrator = orchestrator_for(&cfg).await;
    assert_eq!(
        pipeline.enrich(&db, &mut orchestrator).await,
        1,
        "the poll must succeed despite the session expiring inside it"
    );

    assert!(
        controller.logins.load(Ordering::SeqCst) >= 2,
        "it logged in again rather than giving up: {} logins",
        controller.logins.load(Ordering::SeqCst)
    );
    let client = db.client().await;
    let phone = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the phone");
    assert_eq!(phone.current_ap.as_deref(), Some("Kitchen AP"));
}

#[tokio::test]
async fn an_unreachable_controller_keeps_the_last_known_values_and_stays_up() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: true,
        ..Script::default()
    })
    .await;
    let cfg = controller.config();
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;

    let mut orchestrator = orchestrator_for(&cfg).await;
    pipeline.enrich(&db, &mut orchestrator).await;
    assert_eq!(db.count("ng_location_history").await, 1);

    // The controller starts refusing to answer, as one does while it reboots.
    controller.script.lock().await.hang_up = true;
    for _ in 0..3 {
        // Due again: the orchestrator's interval is 30s, so drive it directly.
        let devices = pipeline.manager.snapshot();
        let enrichments = orchestrator
            .poll_due(
                tokio::time::Instant::now() + std::time::Duration::from_secs(3600),
                &devices,
            )
            .await;
        assert!(enrichments.is_empty(), "a failed poll yields nothing");
    }

    // Nothing was cleared, nothing was invented, and the pipeline is still
    // usable: the last known location is exactly where it was.
    let client = db.client().await;
    let phone = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the phone");
    assert_eq!(
        phone.current_ap.as_deref(),
        Some("Kitchen AP"),
        "a controller that is down must not make locations vanish"
    );
    assert_eq!(db.count("ng_location_history").await, 1);

    // ...and it recovers when the controller comes back.
    controller.script.lock().await.hang_up = false;
    let devices = pipeline.manager.snapshot();
    let enrichments = orchestrator
        .poll_due(
            tokio::time::Instant::now() + std::time::Duration::from_secs(7200),
            &devices,
        )
        .await;
    assert_eq!(enrichments.len(), 1, "it recovers on the next interval");
}

#[tokio::test]
async fn a_classic_controller_is_found_at_the_unprefixed_path() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // A self-hosted controller answers /api/login and serves the network
    // application at the root; a UniFi OS console does neither.
    let controller = MockController::start(Script {
        unifi_os: false,
        serve_inventory: true,
        ..Script::default()
    })
    .await;
    let cfg = UnifiConfig {
        api_key: String::new(),
        username: "admin".into(),
        password: "hunter2".into(),
        ..controller.config()
    };
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;

    let mut orchestrator = orchestrator_for(&cfg).await;
    assert_eq!(pipeline.enrich(&db, &mut orchestrator).await, 1);

    let seen = controller.seen().await;
    assert!(
        seen.contains(&"/api/auth/login".to_string()),
        "it tried UniFi OS first: {seen:?}"
    );
    assert!(
        seen.contains(&"/api/login".to_string()),
        "and fell back to the classic endpoint: {seen:?}"
    );
    assert!(
        seen.contains(&"/api/s/default/stat/sta".to_string()),
        "then read the client list at the root: {seen:?}"
    );
}

#[tokio::test]
async fn an_api_key_is_sent_on_every_request_and_no_login_is_attempted() {
    let Some(db) = common::test_db().await else {
        return;
    };
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: true,
        ..Script::default()
    })
    .await;
    let cfg = controller.config();
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;
    let mut orchestrator = orchestrator_for(&cfg).await;
    pipeline.enrich(&db, &mut orchestrator).await;

    let keys = controller.api_keys().await;
    assert!(!keys.is_empty(), "the key was sent");
    assert!(keys.iter().all(|k| k == "test-key"), "{keys:?}");
    assert_eq!(
        controller.logins.load(Ordering::SeqCst),
        0,
        "a key needs no session, which is why it cannot expire mid-poll"
    );
}

#[tokio::test]
async fn an_unavailable_access_point_inventory_falls_back_to_the_ap_mac() {
    let Some(db) = common::test_db().await else {
        return;
    };
    // Ugly but visible, which is the point: a device is still placed, and the
    // location it is placed in is something an operator can search the
    // controller for.
    let controller = MockController::start(Script {
        unifi_os: true,
        serve_inventory: false,
        ..Script::default()
    })
    .await;
    let cfg = controller.config();
    let mut pipeline = Pipeline::new(&cfg);
    pipeline.see(&db, PHONE).await;
    let mut orchestrator = orchestrator_for(&cfg).await;
    assert_eq!(pipeline.enrich(&db, &mut orchestrator).await, 1);

    let client = db.client().await;
    let phone = queries::find_device_by_mac(&client, mac(PHONE))
        .await
        .expect("lookup")
        .expect("the phone");
    assert_eq!(phone.current_ap.as_deref(), Some(KITCHEN_AP_MAC));
    assert_eq!(
        phone.current_location.as_deref(),
        Some(KITCHEN_AP_MAC),
        "an unmapped access point falls back to its own name, never to nothing"
    );
}

#[tokio::test]
async fn wrong_credentials_are_reported_once_rather_than_retried_in_a_loop() {
    // A controller that answers the login endpoint with 401 has seen the
    // password and refused it. Trying the other endpoint shape as well, or
    // trying again, is how accounts get locked out.
    let controller = MockController::start(Script {
        unifi_os: true,
        reject_login: true,
        ..Script::default()
    })
    .await;
    let cfg = UnifiConfig {
        api_key: String::new(),
        username: "admin".into(),
        password: "wrong".into(),
        ..controller.config()
    };
    let enricher = netgraspd::enrich::unifi::UnifiEnricher::new(&cfg).expect("builds");

    let err = enricher
        .enrich(&[])
        .await
        .expect_err("refused credentials must be an error");
    assert!(
        format!("{err:#}").contains("rejected the configured credentials"),
        "{err:#}"
    );
    assert_eq!(
        controller.logins.load(Ordering::SeqCst),
        1,
        "exactly one attempt: a refused password is not retried against the other \
         endpoint shape"
    );
}

#[tokio::test]
async fn an_unreachable_network_api_is_an_error_rather_than_silence() {
    // The other failure shape: nothing answers at all. It must surface as an
    // error the orchestrator can log, not as an empty successful poll that
    // would look like "no devices are anywhere".
    let dead = MockController::start(Script {
        unifi_os: true,
        hang_up: true,
        ..Script::default()
    })
    .await;
    let cfg = UnifiConfig {
        api_key: "k".into(),
        ..dead.config()
    };
    let enricher = netgraspd::enrich::unifi::UnifiEnricher::new(&cfg).expect("builds");
    let err = enricher
        .enrich(&[])
        .await
        .expect_err("an unreachable network API must be an error, not silence");
    assert!(
        format!("{err:#}").contains("could not reach the UniFi network API"),
        "{err:#}"
    );
}
