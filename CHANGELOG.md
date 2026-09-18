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
