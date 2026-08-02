# Netgrasp on Trovato 1.0: Architecture

Living decision record for the Netgrasp rewrite. Adapted 2026-08-02 from the
vault design record of 2026-07-07, which itself superseded the original
"Trovato as Web Framework" design and its SQLite choice. The vault copy is
archived; this file is now the authority for the daemon.

Netgrasp is a passive network device monitor: it watches LAN broadcast and
multicast traffic without ever transmitting a packet, identifies devices by
combining signals from several protocols, maintains a per-device state machine,
and alerts on devices it has not seen before.

**The core architectural rule this rewrite exists to enforce: state changes are
stored, raw packet observations are not.** The predecessor wrote one row per ARP
packet and drowned in its own database. Nothing in this repo may store a row per
packet.

## Trovato 1.0 baseline (updated 2026-08-02)

The 2026-07-07 draft was written against assumed 1.0 behaviour. That baseline is
now frozen reality rather than assumption, and the relevant facts are:

- `KERNEL_API_VERSION (1,0)` with cargo-semver-checks gating the SDK.
- WASM-2 enforced: `db_tables` allowlist plus a `raw_sql` gate on the six
  database host functions. A plugin sees only the Postgres tables it declares,
  which is what makes the `ng_*` tables a usable contract surface.
- WASM-4 resource limits; Epic 3 access layer across all retrieval surfaces.
- The P11c..P11g platform program landed: background AI principal with
  configurable timeouts and cost accounting, queue v2 (retries, backoff,
  priority, DLQ, bounded concurrency, opt-in resident runner), streaming http
  with a manifest-declared ceiling up to 16 MB, **async auto-embed with per-type
  opt-out**, and lightweight records via manifest `[[record_types]]`.
- FR-24 proven: external plugins build against the published SDK.

Two consequences for this design:

1. **The events-as-Items caveat from the draft has dissolved.** It worried that
   every Item create fires a synchronous auto-embed when an AI provider is
   configured, making ~300 event Items/day silly on an instance that also runs
   Argus. Auto-embed is now async with a per-type opt-out, so events-as-Items is
   free on any instance. The fallback (events stay a plugin table rendered by a
   menu callback) is no longer needed and should not be built.
2. **Lightweight records are available** to the served-surface work as a third
   option between "kernel Item" and "daemon-private table". Where the draft's
   ownership table says Items, that call gets re-weighed in the plugin prompt,
   not here. The daemon is indifferent: it owns `ng_*` tables either way.

## Shape decision (CLOSE 04, ratified 2026-07-18)

The Argus architecture re-check ran after the platform program removed the
kernel gaps that had forced a hybrid, and it ratified **pure plugin** for Argus.
Netgrasp does not inherit that outcome, because Netgrasp's split is not a
judgement call:

**libpcap needs raw sockets and `CAP_NET_RAW`. No WASM plugin will ever hold
that.** Capture is native or it does not happen.

So Netgrasp stays a fork, but the fork line moves to the narrowest defensible
place. The daemon owns what the sandbox cannot hold:

- **Forced daemon-side:** packet capture, and therefore the fingerprinting and
  state machine that consume packets at packet rate.
- **Chosen daemon-side:** notifications. "New device on the network" is a
  seconds-matter alert; the plugin's cron-driven world adds minutes of latency,
  and the daemon already holds the event bus at the moment the event happens.
- **Plugin-side:** the entire served surface. Devices, people and events as
  kernel content, gathers, tiles, roles, admin editing. The daemon never links
  Trovato and never serves HTTP.

### Depending on Trovato is the point, not a limitation

Ruled 2026-08-02, after this was argued the wrong way round once.

The predecessor had a `--identify` labelling mode and `--custom-hide-filters`,
so it is tempting to read their absence here as a regression and to propose a
`netgraspd name <mac>` subcommand or a `--hidden` filter to close the gap. Do
not. Naming a device, hiding it, assigning an owner and toggling its
notifications are admin-UI work, and Trovato supplies the form, the roles, the
audit trail and the access checks for free. Rebuilding any of it daemon-side
means writing a second, worse copy of a surface that already exists, and then
owning the question of which copy wins.

The daemon owns what the sandbox cannot hold. That is the whole test. If a
feature does not need `CAP_NET_RAW` or seconds-matter latency, it is
plugin-side, and "but then it needs Trovato" is the intended outcome rather
than an objection.

Practical consequences, so they are not mistaken for oversights:

- `netgraspd devices` shows every device including hidden ones. It is an
  operator and debugging surface, not the dashboard; hiding is a display
  concern the plugin's gather applies.
- There is no daemon-side way to set `display_name`, `notes`, `hidden` or
  `notify`. The daemon reads them and never writes them.
- A daemon-only deployment is a deliberately reduced thing: capture, state,
  events and notifications, with a bare CLI over the top.

## Storage

**Postgres, not SQLite** (a deliberate divergence from the original design). One
database shared with the kernel, one backup story, and the plugin can only see
plugin-declared Postgres tables anyway. The Pi-class deployment survives:
Postgres runs fine on a Pi 4, and the sellable unit is docker-compose regardless.
If a truly embedded satellite mode ever matters it is a post-v1 fork of the
storage trait, not a reason to split the main line.

No ORM. Typed query building over `tokio-postgres`, refinery for migrations.

### Data ownership

The volume gradient decides what crosses into Trovato:

| Data | Volume | Owner | Form |
|---|---|---|---|
| devices | ~100 rows | shared | Kernel content. User-edited (display name, owner, notes, hidden, notify), so the kernel admin UI, roles and audit surface do that work. Bidirectional sync below. |
| people | ~20 rows | Trovato | Kernel content, created and edited in admin. Daemon reads them via REST with a service token, because arrival/departure logic needs the device-to-person mapping. |
| events | ~300/day, 90-day retention | shared | Kernel content, created by plugin sync, pruned by plugin cron. This is what makes the event log filterable through gather with zero custom UI. |
| presence sessions | ~1,000/day pre-rollup | netgraspd | `ng_presence`, nightly rollup to daily summaries. Never leaves the daemon tables. |
| ip_history, location_history | high churn | netgraspd | `ng_*` tables, rollup applies. |
| fingerprint raw signals | per device | netgraspd | `ng_device_signals`, joined into device sync as identity fields. |
| notification config, quiet hours | small | netgraspd | daemon TOML plus per-device columns. |

### Device sync, bidirectional

MAC address is the join key.

- **Daemon to kernel:** discovery and state changes write `ng_devices` and set
  `sync_state = 'dirty'`; the plugin's cron sweep picks dirty rows up and
  creates or updates the device content. Cron-cadence latency is fine for a
  dashboard, and the time-critical path (notifications) never crosses this
  boundary.
- **Kernel to daemon:** user edits (rename, assign owner, toggle notify/hidden)
  are picked up by the plugin's update tap, which writes the user-owned columns
  back to `ng_devices` directly. The user-owned column set is fixed
  (`display_name`, `notes`, `hidden`, `notify`, and the person assignment when
  it exists) so daemon and plugin never fight over the same field.

`sync_state` and `trovato_item_id` exist in this repo as **contract stubs**.
The daemon writes `sync_state`; nothing in this repo reads it.

## Identity resolution

Every raw signal is stored in `ng_device_signals` so that later signals refine
rather than overwrite. A weighted scorer picks the display identity:

| Signal | Weight |
|---|---|
| user-assigned name | absolute override |
| mDNS instance name | 0.9 |
| DHCP hostname | 0.8 |
| reverse DNS | 0.7 |
| NetBIOS name | 0.6 |
| SSDP friendly name | 0.5 |
| vendor plus device type | 0.3 |
| bare MAC | 0.1 |

Milestone 1 implements OUI vendor lookup, mDNS instance name and reverse DNS.
The other weights are reserved and their signal types already exist in the enum,
so the later parsers add rows without touching the scorer.

## Passive means passive

Netgrasp transmits nothing. Two implementation consequences that are easy to get
wrong:

1. **mDNS is captured through pcap, not through a service-discovery library.**
   Every mDNS crate worth using (`mdns-sd` included) browses by sending queries.
   Even the act of joining the 224.0.0.251 multicast group with a UDP socket
   emits an IGMP membership report. A BPF-filtered pcap handle on `udp port
   5353` plus a DNS message parser observes the same traffic and emits nothing.
2. **Reverse DNS is the one exception, and it is deliberate.** rDNS sends
   unicast queries to the configured resolver, not to the monitored device, and
   it is the price of the 0.7 signal. It is off by default in the shipped
   config example and gated behind `identity.reverse_dns`.

## Development plan

| # | Scope | Milestone |
|---|---|---|
| 1 | daemon core: config, refinery schema, ARP + mDNS capture, state machine, identity v1 (OUI, mDNS, rDNS), learning mode, event bus, ntfy notifier, CLI live table | Sees the real LAN passively, correct state tracking, meaningful first notification |
| 2 | fingerprinting and security: DHCP, SSDP, NDP, NetBIOS parsers; DHCP fingerprints; device-type classification; the six analyzers | Most devices auto-identified by name/type/OS; spoof and rogue-DHCP detection live |
| 3 | Trovato plugin: device/person/event content, bidirectional device sync, gathers, tiles, roles, event pruning, friction report | Phone-openable dashboard: name a device, assign an owner, see who is home, viewer role read-only |
| 4 | enrichment and packaging: UniFi enricher, location model, arrival/departure, people notifications, rollup jobs, docker-compose, cross-compile aarch64 | "Elena is in the backyard"; runs unattended on a Pi; deployable unit |

Milestones 1 and 2 are pure daemon work and can run before, or in parallel with,
any Trovato session.

## Where deferred work attaches

- **DHCP/SSDP/NDP/NetBIOS parsers:** `src/capture/{dhcp,ssdp,ndp,nbns}.rs`
  already exist as compiling stubs implementing `CaptureSource`. Each fills in
  `run()` and emits `Observation`s carrying its existing `SignalKind`.
- **Security analyzers:** an analyzer chain sits between the capture channel and
  the device manager, consuming the same `Observation` stream and emitting
  events on the existing bus. No schema change: `ng_events.details` is jsonb.
- **Presence rollup:** `ng_presence.is_summary` and `observation_count` exist
  now, so the nightly rollup job needs no ALTER.
- **Plugin sync:** `ng_devices.sync_state` / `trovato_item_id` and
  `ng_events.sync_state` are written by the daemon and read by nothing here.
- **People and location:** `ng_devices.current_ap` / `current_location` exist as
  nullable columns; the person mapping is a plugin-owned join table added in
  milestone 4, not a daemon concern.
- **Bluetooth passive scanning:** the `CaptureSource` trait leaves the slot.

## Open questions

1. macOS daemon support: pcap over BPF works but needs root or a `/dev/bpf*`
   group, and each protocol wants re-verification there. Linux is the target;
   macOS is a development convenience.
2. Whether devices become kernel Items or lightweight records is a milestone-3
   decision, not a daemon one.
