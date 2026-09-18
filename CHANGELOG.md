# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Versioning rule:** one minor version per shipped milestone, starting at 0.1.0
for milestone 1. A feature landing on top of milestone 3 is therefore 0.4.0.
There is no 1.0 until the daemon has run unattended on a real network for long
enough to earn it; see
[What has and has not been exercised](README.md#what-has-and-has-not-been-exercised).

The entries for 0.1.0 to 0.3.0 were written after the fact, from the README's
milestone sections and `ARCHITECTURE.md`. They describe what those milestones
shipped rather than a release that was tagged at the time.

## [0.4.1] - 2026-09-18

Four defects found in a live run on 2026-09-17, the first extended one on a
real home network with VLANs. A patch rather than a minor because no milestone
shipped: every entry is an existing feature that was wrong.

### Fixed

- **An mDNS responder's frames no longer name every host it answers for.** The
  walker attributed every name in a message to the frame's source MAC. That is
  wrong whenever a responder answers on somebody else's behalf, which is the
  ordinary case: a Bonjour Sleep Proxy answers for machines that are asleep. In
  the 2026-09-17 run one iPhone, `92:27:e6:9f:03:76`, was given the names of six
  other hosts, and `Jeremy's MacBook Pro (2)` was recorded as the name of six
  different MACs.

  The rule now is that a name belongs to whoever holds the address the record
  names, not to whoever transmitted it. An A or AAAA record gives its address
  directly and an instance name reaches one through its SRV target; the pair
  travels from the parser as a `NameClaim` and `device::Manager` resolves it
  against the ARP and DHCP evidence it already holds. A name proved for another
  known device is recorded against *that* device, so a sleep proxy's answer now
  names the sleeper, which is what it was always evidence about. A name proved
  for an address nobody known holds is counted rather than guessed at, and the
  count is published as `unattributed_names` in the runtime status. A record
  tied to no address still falls back to the sender, unless the same frame
  proved it was speaking for somebody else.

- **`name_updated` no longer fires on a name that is merely flapping.** A second
  and independent defect, which produced 385 events in thirty minutes in the
  same run. `improves_on` treated any equal-confidence change of text as an
  improvement, and `record_signals` re-inserts each frame's batch at the front of
  the signal list, so two mDNS names of equal weight take turns winning the
  scorer's same-kind tie-break and each turn was adopted.

  A candidate that wins on rank is still adopted immediately. A candidate of
  equal rank is now held until it has been the winner continuously for five
  minutes (`identity::SETTLE_WINDOW`), and a candidate that loses even once
  starts the clock again. An alternating pair therefore never settles and emits
  nothing, while a device somebody genuinely renamed settles once and emits one
  event. Nothing is lost by waiting: the name is stored as a signal on arrival
  and only the display identity and its event are held back.

- **Proxy ARP by the gateway is no longer read as an attack.** A router that
  routes between VLANs answers ARP for the far side with its own hardware
  address, so the same address is legitimately seen at the router's MAC and at
  its real owner's. `ip_conflict` reads that as two devices using one address and
  `arp_spoof` reads it as an address changing hands while its holder is still
  talking. On 2026-09-17 the Routerboard gateway `18:fd:74:39:e5:23` was the MAC
  or the conflicting holder in **all 34** alerts the two analyzers produced.

  `GatewayTracker::proxy_arp_for` now identifies such a frame and both analyzers
  return before touching their state. Returning early is the load-bearing part:
  had the router been recorded as holding the address, the real owner's next
  packet would have read as taking it back and alerted on the way past. The
  addresses are recorded for the operator, logged once each and published as
  `proxy_arp_addresses` in the runtime status.

  **Neither attack the analyzers exist for is weakened.** The exemption requires
  all three of a reply, the learned gateway MAC as the *Ethernet* source, and an
  address that is not the gateway's own. A stranger claiming the gateway's
  address is not the gateway and still alerts with no grace period; a second MAC
  claiming an address the gateway did not proxy still alerts; and because the
  router never becomes the recorded holder, a stranger taking a proxied address
  is still caught. Tests pin all three.

### Added

- `security.proxy_arp_gateway`, default true, which is the switch for the rule
  above. Documented in `netgrasp.toml.example` and the README.
- `unattributed_names` and `proxy_arp_addresses` in the runtime status file, both
  `#[serde(default)]` so a file written by an older build still parses.
- `mdns_sleep_proxy`, a built fixture: one source MAC carrying three hosts'
  records, two of them proxied. It is the 2026-09-17 shape reduced to one frame.

### Notes

- No schema change. The two new counters live in the runtime status JSON, which
  `runtime/mod.rs` already documents as the place for facts about the daemon
  rather than about the database, for exactly this reason. Recording proxied
  addresses as a column on `ng_ip_history` was considered and rejected: it is
  additive and therefore permitted, but `ng_ip_history` is shared with the
  Trovato plugin and an `ALTER` on it is a two-repository decision.
- `Observation` gains a `claims` field. Every capture source but mDNS leaves it
  empty, and `Observation::new` sets it so, so no other parser changed.

## [0.4.0] - 2026-09-18

### Added

- **The daemon notices what the web interface and the assistant change.** A
  reconcile tick, `state.reconcile_interval` (ten seconds by default), reads the
  user-owned columns of `ng_devices` and the whole `ng_people` mirror and merges
  them into the running device table and people registry. Renaming a device,
  muting it, or assigning it to somebody now takes effect while the daemon runs.
  Before this, those columns were read once at startup and a change made in
  Trovato did nothing at all until a restart: a joint run measured 33 of 35
  presence deliveries ignoring a `notify` set to false and a newly assigned
  owner.
- `Manager::apply_user_settings`, `Manager::state_of`, `Registry::reconcile`,
  `Registry::set_config_owner` and `queries::load_user_settings`, which are that
  tick's parts. The merge iterates a named list of user-owned columns rather than
  the whole record, mirroring the plugin's `USER_OWNED` list from this side.

### Changed

- `hidden` is documented as presentation only, in the README and in
  `db/queries.rs`. It hides a row from the Trovato listings and does nothing
  else: a hidden device is still captured, still recorded, still produces
  presence and still alerts. `notify` is the flag that silences alerts.
- Ownership that came from `[[people]]` in `netgrasp.toml` is remembered as
  such, so a reconcile reading a null `owner_item_id` falls back to it instead of
  clearing it. The database still wins wherever it says anything, which is the
  precedence the startup roster already applied.

### Fixed

Two failures that had accumulated on `main` since it last ran green on
2026-08-15. Neither was caused by the change above; both are here because a
branch cannot be merged red.

- `rustls` 0.23.43 to 0.23.45, for RUSTSEC-2026-0285 (TLS 1.3 handshake messages
  accepted across encryption level boundaries, medium), and `chacha20` 0.10.1 to
  0.10.2, the 0.10.1 release having been yanked. Both arrive through `reqwest`,
  which the UniFi enricher uses; nothing in this repository speaks TLS itself.
- The NetBIOS name decoder uses `as_chunks::<2>()` rather than
  `chunks_exact(2)`, which Rust 1.98's clippy flags. The pairs now arrive as
  arrays, so the two reads are checked at compile time instead of being indexing
  that happens never to be out of range.

### Notes

- No schema change. `ng_devices` and `ng_people` are shared with the Trovato
  plugin, so an `ALTER` on either is a two-repository decision and not something
  a daemon change makes on its own. The V3 `trovato_item_id` `ALTER`, which was
  destructive, is behind us.
- The tick polls rather than using `LISTEN`/`NOTIFY`, for two reasons: the plugin
  sends no `NOTIFY` today, and a pooled connection cannot receive one because
  deadpool drives the connection that would carry it. `ARCHITECTURE.md` records
  the `LISTEN` design for when the plugin can send one. The poll it would replace
  costs under a millisecond of server time for two thousand devices.

## [0.3.0] - milestone 3: enrichment, location, people, unattended operation

### Added

- **Enrichment.** A UniFi enricher reading which access point each device is
  associated with, behind a trait, polled off the select loop so an unreachable
  controller cannot stop packets being processed.
- **Location.** An operator's map from access points to rooms, a history of where
  each device has been, and edge access points that tell somebody arriving from
  somebody wandering between rooms.
- **People.** Who is home, inferred from which of their devices are online, with
  arrival and departure notifications and the edge evidence that names the way in.
- **Maintenance.** Nightly rollup, pruning and vacuum, which is what makes an
  unattended year on a Raspberry Pi survivable.
- **`netgraspd stats`.** Runtime counters published to a file, for the question
  you ask three months in.
- **Packaging.** Docker image, compose stack, systemd unit, and binaries for
  x86-64 and aarch64.
- **The schema as a checked contract.** The daemon refuses to start on tables the
  plugin created first, refuses to start on a divergence from the columns this
  build expects, and read-only commands refuse to answer on an under-migrated
  database.

## [0.2.0] - milestone 2: more protocols, fingerprints, analyzers

### Added

- DHCP, SSDP, NDP and NetBIOS capture sources, on top of ARP and mDNS.
- A DHCP fingerprint table, downloadable and embedded, feeding device-type and
  operating-system classification.
- Six security analyzers: ARP spoofing, rogue DHCP, MAC and hostname anomalies,
  scanning, and identity change.

## [0.1.0] - milestone 1: the daemon core

### Added

- Configuration, embedded refinery migrations, ARP and mDNS capture, the device
  state machine, identity resolution v1 (OUI, mDNS, reverse DNS), learning mode,
  the event bus, the ntfy notifier and the CLI live table.
- The rule the whole rewrite exists for: one row per presence session and one per
  state change, never one per packet.
