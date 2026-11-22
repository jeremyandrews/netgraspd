# Changelog

Notable changes, newest first. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

**Versioning rule:** from 1.0.0 on, semantic versioning over three surfaces:
the command line, the configuration file, and the `ng_` schema. A change that
breaks any of them is a major; a feature is a minor; a fix is a patch. **A
change to the `ng_` schema is always a paired release** with the Trovato plugin,
because the two share those tables; see
[Compatibility](README.md#compatibility).

Before 1.0.0 the rule was one minor per shipped milestone, starting at 0.1.0 for
milestone 1, so a feature landing on top of milestone 3 was 0.4.0. That rule
also said there would be no 1.0 until the daemon had run unattended on a real
network long enough to earn it. 1.0.0 is cut before that has happened, by
decision rather than by oversight, and its entry says so first.

The entries for 0.1.0 to 0.3.0 were written after the fact, from the README's
milestone sections and `ARCHITECTURE.md`. They describe what those milestones
shipped rather than a release that was tagged at the time.

## [Unreleased]

### Upgrade note

- **Schema V6 turns `ng_devices.notify` off on every existing device, and makes `FALSE` its default.** Any choice an installation made about which devices it hears coming and going is reset and has to be made again in Trovato. It was done this way because under V1's `DEFAULT TRUE` no row was ever a choice: on the one installation this was measured against, all 166 devices had `notify` on, none of them set by a person, and no alert had ever been delivered. Nothing is renamed, dropped or retyped; the column keeps its name, type and `NOT NULL`. The Trovato plugin's test fixture `daemon_schema.sql` still declares `DEFAULT TRUE`; updating it is a follow up on the plugin side, and plugin 1.1.0 runs on V6 unchanged.
- **Security alerts no longer skip every rate limit.** `[security.notifications]` keys `bypass_quiet_hours`, `bypass_debounce` and `bypass_batch_window` are still accepted so an existing `netgrasp.toml` keeps loading, have no effect, and log a warning at startup; remove them at leisure. Each security type is now delivered by its alert class (below), and every pushed alert, security included, shares the batch window, so an ARP spoof can take up to `notify.batch_window` (60 s by default) to arrive. An `arp_scan` or `ip_conflict` inside quiet hours is now held back like any other alert in a class that respects them; set `respect_quiet_hours = false` on the class to have them through.

### Changed

- **Alerts are safe to switch on: a new device, a device somebody chose, a person, an attack.** After the learning window, `new_device` is delivered for every device whatever its `notify` says, because nobody has had a chance to choose anything about a device that has only just appeared (before, a device with `notify` off was not announced even when new). `returned` and `went_offline` are delivered only for a device whose `notify` a person turned on, and `notify` now starts off. `ip_changed`, `name_updated` and `device_location_changed` are recorded and never delivered, even when listed in `notify.event_types`. Person events are unchanged. Replayed through the dispatcher over the live network's last seven days with the default configuration, device lifecycle alerts fall from about 57 a day (54 `returned`, 2 batch summaries, 1 `new_device`) to about 1 (`new_device`); security events are not changed by this. The default `notify.event_types` gains `went_offline`, so a device somebody chose is heard leaving as well as coming back, and the line printed when learning ends says that a device comes and goes without an alert until its notify is turned on.

### Added

- **Alert classes, `[notify.classes.<name>]`.** Each event type belongs to one class, and the class decides `delivery` (`push`, `digest` or `off`), `instant_count` (3), `pool_period` (`1h`), `backoff_after` (`24h`), `backoff_period` (`24h`), `quiet_reset` (`1h`) and `respect_quiet_hours`. With none configured: `intrusion` (`arp_spoof`, `rogue_dhcp`; push, through quiet hours), `anomaly` (`arp_scan`, `ip_conflict`; push), `identity` (`identity_change`, `gratuitous_arp`; daily digest) and `presence` (`new_device`, `returned`, `went_offline`, `person_arrived`, `person_departed`; push). A type in two classes stops the daemon at load; a type in no class is `off`, except a security type, which falls back to `anomaly`, and both log a warning naming the type.
- **Pooling per source.** A push class counts events per (class, event type, MAC). The first `instant_count` alerts go out at once, and the last of them says "More alerts like this from d0:21:f9:dc:a1:19 will be pooled: one summary every hour." After that one summary per `pool_period` gives the count, the first and last time and when the next is due. A source repeating for `backoff_after` without a gap of `quiet_reset` slows to one summary per `backoff_period`, and the summary that switches says so. A gap of `quiet_reset` starts the source over. Pooling state is in memory, so a restart resets it: at most `instant_count` extra alerts per source after a restart.
- **The daily digest**, `notify.digest_time` (`08:00` local): one message listing counts by class, type and source for every `digest` class.
- **Approved devices stay quiet about routine behaviour**, `notify.approved_quiet_types` (`["identity_change", "gratuitous_arp", "ip_conflict"]`). A device counts as approved when it has an owner (`owner_item_id` or `[[people]]`), a name a person gave it, or `notify` on; the learned baseline does not count. Those types from an approved device are recorded and never delivered or pooled. `arp_spoof` and `rogue_dhcp` alert whatever the device's state and cannot be listed. Before, a named or owned Mac waking up raised `identity_change` and `gratuitous_arp` alerts like a stranger.
- Replayed through the dispatcher with the default configuration, the live 1.1.0 day from 2026-11-18T08:03:25Z projects 34 pushes, where the same replay before this change gave 119: 29 instant `arp_scan` alerts, 4 pooled summaries and 1 digest covering 75 `gratuitous_arp` events.

## [1.1.0] - 2026-11-18

### Changed

- **Arrival and departure alerts are one sentence on the local clock**: "Jamie is home: Jamie's iPhone joined at 18:42" and "Jamie left: last seen 07:55", where they were "Jamie arrived" and "Jamie left" with a UTC time in the body. Person events now carry `device_name` and `last_seen_at` in `details`.

### Added

- **Delivery status and a test alert the web side can ask for**, schema V4 (additive). `ng_notify_status` is one daemon-owned row: whether delivery is configured, by which transport, and whether the last attempt was accepted and when. The plugin inserts into `ng_notify_requests` to ask for a test; the daemon answers on its reconcile tick with one test alert for however many requests are waiting, and marks each `sent`, `failed` or `not_configured`. Neither table holds the topic, the server or the token, and an outcome is never the transport's error text, because that names the URL.
- **Schema V5, additive only**, so the web side reads facts the daemon keeps true instead of reconstructing them. Nothing V1 to V4 created is renamed, dropped or retyped.
  - `ng_people.last_arrived_at_epoch` and `last_departed_at_epoch`, the generated epoch twins V3 gave every other table and left off this one.
  - `ng_events.person_item_id`, the person a `person_*` event is about, null on every other event. The migration backfills it from `details` for person events already recorded, and leaves a value that is not a UUID null.
  - `ng_enrichment_status`, one row per enricher (`unifi`, `reverse_dns`), configured or not, with `state` (`not_configured`, `starting`, `ok`, `failing`), counts since start, the last success and failure times and the last error. Rewritten on every runtime status tick.
  - `ng_daemon_status`, one row: version, start time, a heartbeat, and the time zone every day boundary is measured in.
- **`timezone`**, a top-level setting naming the household's IANA zone. It is published in `ng_daemon_status.timezone` and is the one owner of what "today" means: readers measure a day as `ts AT TIME ZONE` that zone, not in their session's `TimeZone`. Unset, the database's own `TimeZone` is published. A zone Postgres does not know stops the daemon at startup.
- `Db::migrate_to`, which migrates to a given version and no further, for proving an upgrade from an earlier schema.
- **A profile for a network you do not own**, `netgrasp.foreign.toml.example`. It is an ordinary configuration file, not a mode. Notifications, enrichment and reverse DNS are off; all six sources are on; events and rollup are kept for one day; the unknown-device sample is on. It names its own database, and its status file and sample are relative paths an ordinary user can write. The image ships it beside the home example ([#18](https://github.com/jeremyandrews/netgraspd/pull/18)).
- **The visibility report**, in the status file and in `netgraspd stats`. For each interface and each source it gives frames delivered, distinct source MACs (at most 4096 kept per set, then reported as "at least"), and how long the interface has been listening. It also gives the gateway the daemon believes in and where that belief came from. Each interface then gets one plain verdict, so an isolated guest network ("capture is working: 1 sender seen (the gateway), consistent with client isolation") no longer looks like broken capture ("nothing received on en0 in 10m: capture may be broken"). The new status fields are defaulted on read, so an older status file still parses ([#18](https://github.com/jeremyandrews/netgraspd/pull/18)).
- **The unknown-device sample**, `[capture.unknown_sample]`, off by default. It keeps the first frames from each device the identifier could not name in one pcap file. These are broadcast and multicast frames only: a frame unicast to the capture host, which non-promiscuous capture also delivers, is refused, after the first home LAN run sampled 128 of them out of 150. It is bounded by frames per device, by devices and by total bytes, and each limit is logged once. Frames are held only while a device has `settle` (ten minutes, because real devices were named four to seven minutes after first sight) to be named, and a named device is never written ([#18](https://github.com/jeremyandrews/netgraspd/pull/18)).
- **`netgraspd export DIR`** writes a trip bundle that needs no database to read: `SUMMARY.md`, `devices.json` (what named and what typed each device), `events.json`, `visibility.json`, `config.json` with every secret replaced by `***`, and the unknown-device sample ([#18](https://github.com/jeremyandrews/netgraspd/pull/18)).

### Fixed

- **An arrival alert is no longer swallowed by its own device's alert.** A phone coming home is `returned` and then `person_arrived` for the same MAC in the same instant, and the per-device debounce was keyed by MAC alone, so with the default `event_types` the arrival was always counted as debounced and nobody was told. Found on the demo stack with the daemon pointed at a request logger: "Back online: Jamie's iPhone" arrived, "Jamie is home" did not. Person events now have a debounce of their own per device.
- **Log lines carry colour only on a terminal.** The tracing subscriber kept its default of ANSI on whatever stderr was, so under systemd and `docker logs`, where it is a pipe, every line reached the journal with escape bytes in it. Colour is now on only when stderr is a terminal and `NO_COLOR` is unset or empty ([#13](https://github.com/jeremyandrews/netgraspd/issues/13)).
- **The systemd unit grants `CAP_NET_RAW` alone**, as its comment and the README always said. It also granted `CAP_NET_ADMIN`, which nothing uses: every capture handle is non-promiscuous, so the daemon never changes an interface's flags, and the Kubernetes pod captures with `NET_RAW` only. The `setcap` lines in the README and in the permission message drop it too ([#9](https://github.com/jeremyandrews/netgraspd/issues/9)).
- **"New devices from now on will notify" is printed only when something would.** The end of the learning window printed it unconditionally, including under the foreign network profile with `notify.enabled = false`. It now names the reason a new device would not notify: notifications off, no notifier, or `new_device` not in `notify.event_types`.
- **A device holding several addresses at once is one device with several addresses, not a stream of `ip_changed`.** The device table kept one current IPv4 address, so a router with a leg on three segments of the same wire changed address every few seconds: 527,210 `ip_changed` rows in a week on the home LAN. A device now holds every IPv4 address it has used within an hour, and only an address it has not is a change. A MetalLB node answering for its VIP is the same case ([#11](https://github.com/jeremyandrews/netgraspd/issues/11), [#12](https://github.com/jeremyandrews/netgraspd/issues/12)).
- **A second router gets the router threshold in `arp_scan`.** Only the one MAC the gateway tracker names got `gateway_threshold`, so a multi-homed router was held to the host threshold: 19,857 `arp_scan` alerts in a week from that one router, 89% of every security event. A MAC that ARPs from two or more addresses of its own within ten minutes now gets `gateway_threshold` too, looser and never exempt; alert details carry `multi_homed` ([#11](https://github.com/jeremyandrews/netgraspd/issues/11)).
- **The gateway proxy-ARPing for an address no longer moves its `last_ip` or writes its history.** The analyzers asked the gateway tracker whether a reply was proxy ARP and the device table did not, so the gateway raised `ip_changed` to a MetalLB VIP and back and kept the VIP in `ng_ip_history`. The device table now asks the same question of the same packet, and the frame records only presence. No reverse DNS lookup is made for a proxied address either ([#12](https://github.com/jeremyandrews/netgraspd/issues/12)).
- **A reflected mDNS record no longer becomes the reflector's identity.** A frame proving its sender speaks for other hosts already lost the sender's claim to its unaddressed records, but only in that one frame. A reflector proves it in one frame and re-sends PTR, TXT and probe records that name no address in the next, so the router collected 4,278 other hosts' names, their services and their models, and changed device type with each. A MAC that has proved it speaks for others is not given unaddressed records for an hour after the last proof ([#10](https://github.com/jeremyandrews/netgraspd/issues/10)).
- **The device type no longer depends on which service a device announced last.** Within one rank of evidence the classifier took the most recently confirmed signal, so a device advertising AirPlay and AFP was a media player and a NAS by turns, an `identity_change` event each time: 1,200 in a week on the home LAN. Within a rank the classifier's table now decides.
- **The gateway is read from the capture host's own default route**, when it leaves by a captured interface, instead of being guessed from ARP popularity when the host's route already said it. In the C1 run popularity elected the capture host itself, and the router's proxy ARP then raised 5 `ip_conflict` and 1 `arp_spoof` false alerts until a DHCP Ack corrected it at minute 8.5. The route ranks below configuration and above DHCP. Popularity, now only a fallback, elects the address the most distinct MACs asked about, as its documentation always said, rather than the first to reach three ([#17](https://github.com/jeremyandrews/netgraspd/pull/17)).
- **The capture host is one device however many interfaces it captures on.** The device table had no notion of the capture host's own MACs, so a Mac on Wi-Fi and six OrbStack bridges became seven devices. Each capture interface's hardware address is now read from the operating system at startup, and frames from the host's other interfaces' MACs create no device. A Mac that withholds hardware addresses from the daemon's user reports `02:00:00:00:00:00` for every interface; that is not taken for an address, the daemon warns that it cannot identify the capture host, and records it per interface as before ([#17](https://github.com/jeremyandrews/netgraspd/pull/17)).
- **A capture thread that fails is reported when it fails.** Per-interface capture tasks were awaited in order and only at shutdown, so a filter rejected at startup was logged at SIGTERM without naming the interface. Each failure is now logged at `error` with the source, the interface and the error the moment it happens, recorded in the status file's new `capture_failures`, and printed by `netgraspd stats` ([#17](https://github.com/jeremyandrews/netgraspd/pull/17)).

### Changed

- **chrono is replaced by jiff.** chrono was declared unmaintained (RUSTSEC-2026-0543, no patched version), which failed `cargo audit --deny warnings` on every branch. Timestamps are now `clock::Timestamp`, a `jiff::Timestamp` that keeps chrono's formats: RFC 3339 with `Z` and 0, 3, 6 or 9 fractional digits in the status file, exports, `ng_events.details` and JSON output; `2026-11-17 19:15:27.957148 UTC` when displayed; the same `strftime` text. tokio-postgres uses `with-jiff-0_2` for `TIMESTAMPTZ`, cut to whole microseconds toward the Postgres epoch as chrono did, where jiff alone would round. Quiet hours and the nightly job read the local UTC offset once at startup, as before. No schema, column type, wire or file format changes; checked against chrono over a million random instants, and against a `main` build's export, `devices`, `events` and `stats` output, byte for byte.
- **Behavior change:** with no `capture.interfaces` and no `-i`, capture only on interfaces that are up with carrier, not loopback, Ethernet and IPv4-addressed ([#15](https://github.com/jeremyandrews/netgraspd/pull/15)).
- The macOS permission message names both routes, ChmodBPF and the `admin` group `chmod` ([#15](https://github.com/jeremyandrews/netgraspd/pull/15)).

### Documentation

- README: what V5 adds for the web side, and what "today" means. ARCHITECTURE: the two status tables, why day boundaries have one owner, and quiet hours' fixed offset as an open question.
- README: the release binary links `libpcap.so.0.8`, Debian's soname; on Fedora and other distributions that ship `libpcap.so.1`, a symlink to it is enough ([#7](https://github.com/jeremyandrews/netgraspd/issues/7)).
- README: the SQL form of creating the role and database, for a Postgres that is not on the local socket ([#8](https://github.com/jeremyandrews/netgraspd/issues/8)).
- README: the Docker example no longer sets `NETGRASP_DATABASE__URL`, which overrode the mounted file's `database.url` with placeholder credentials, and its `stats` example gets the network, configuration and state volume it needs ([#14](https://github.com/jeremyandrews/netgraspd/issues/14)).
- Rustdoc builds with `-D warnings`: three intra-doc links named a private item, an unresolved path and an ambiguous one.
- README: Running on a network you do not own ([#18](https://github.com/jeremyandrews/netgraspd/pull/18)).
- README: Capturing on macOS, the 2026-11-14 run of all six sources on macOS as an ordinary user, and macOS resident memory ([#15](https://github.com/jeremyandrews/netgraspd/pull/15)).

## [1.0.0] - 2026-09-23

**This daemon has never contacted a real UniFi controller.** The enricher is
tested over real HTTP against a mock controller, and the JSON shape of real
firmware is inferred from published responses. It has also never run
unattended on a real network for longer than an evening: the longest live run
was about half an hour on a home LAN on 2026-09-17. UniFi is optional and off by
default, and everything except the access point and room columns works without
it. The README's
[What has and has not been exercised](https://github.com/jeremyandrews/netgraspd#what-has-and-has-not-been-exercised)
is the full account, and it should be read before this is trusted on a network
you care about.

1.0.0 is a release of the code that was 0.4.1, with no functional change. What
it adds is the ability to install it without building it, and a stated pairing
with the Trovato plugin.

### Added

- **Releases.** A `v*` tag builds the image for `linux/amd64` and `linux/arm64`,
  pushes it to `ghcr.io/jeremyandrews/netgraspd` as `1.0.0`, `1.0` and `latest`,
  and attaches both binaries and a `SHA256SUMS` to the GitHub Release. Each
  binary is extracted from the pushed image rather than built a second time, so
  it is the binary a user of the image runs. The notes are this file's section
  for the tag, and a tag that disagrees with `Cargo.toml`, or that has no
  section here, is refused before anything is built.
- **Install from the release** in the README: the image, the binary, the
  systemd unit and the example configuration, without a Rust toolchain.
- **Compatibility** in the README: this release pairs with `netgrasp-trovato`
  1.0.0 on schema version 3, and the rule that keeps the two in step.

### Changed

- The versioning rule, above. The version is now a promise about the command
  line, the configuration and the schema rather than a count of milestones.
- The README's account of what has been exercised is brought up to date with
  the first joint run with the plugin (2026-09-17), the first capture on a real
  home network and the first on macOS. It still says, first, that no real UniFi
  controller has been contacted.

## [0.4.1] - 2026-09-18

Four defects found in a live run on 2026-09-17, the first extended one on a
real home network with VLANs, plus the fresh-install failure that run's
deployment exposed. A patch rather than a minor because no milestone shipped:
every entry is an existing feature that was wrong.

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

- **Notification titles carrying an apostrophe or an accent are readable
  again.** `X-Title` is an HTTP header, and a header is not a place where UTF-8
  means UTF-8: the value was written as raw UTF-8 and read back as Latin-1, so
  `Jeremy’s` arrived as `Jeremyâs`, each continuation byte of the three-byte
  U+2019 sequence read as its own character. ntfy documents RFC 2047 encoded
  words for non-ASCII headers, so a header value that is not plain ASCII is now
  sent as `=?UTF-8?B?...?=`, split into several encoded words when it would
  otherwise exceed the RFC's 75-character limit and never splitting a character
  across two of them.

  Pure ASCII is left exactly as it was, so an ordinary title stays readable in a
  packet capture and in ntfy's own logs. A value that is ASCII but contains `=?`
  is encoded anyway, because device names come off the network and one shaped
  like an encoded word would otherwise be decoded as one. `X-Tags` goes through
  the same function; `X-Priority` is a number. The body was never affected: it
  is the request body, sent and read as UTF-8. ntfy is the only notification
  backend in the tree.

- **A fresh `docker compose up` no longer hangs on the `migrate` service.** The
  compose file ran `netgraspd maintain --dry-run` as its one-shot migrate step,
  on the strength of a comment saying that command "connects, migrates, runs the
  schema preflight". It does not migrate. Like every other read-only command it
  calls `Db::require_schema`, which *refuses* an under-migrated database rather
  than building one, so on an empty database it exited 1, the migrate service
  never completed, and both services that depend on it waited forever. The stack
  only ever came up because `netgraspd run` migrates on startup, so anything
  that got as far as the daemon had been migrated by the daemon.

  There is now a `netgraspd migrate` subcommand that applies pending migrations,
  runs the schema preflight, and exits zero whether or not it had anything to
  apply, which is what makes it safe on every boot. The compose service runs it.
  `maintain --dry-run` is left as what it always was.

- **The compose `migrate` service was also pointed at an unreachable
  database.** Found by actually running `docker compose up` on a fresh Postgres
  rather than reasoning about it, and separate from the defect above: the
  service was given `${DATABASE_URL}`, which says `localhost`. That is correct
  only for the daemon, which is the one service using `network_mode: host`. The
  migrate service is on the default bridge, where `localhost` is the container
  itself, so it could not have connected on any platform even with the right
  command. It now takes `${MIGRATE_DATABASE_URL}`, which reaches Postgres by
  service name exactly as the optional `trovato` service already did, and
  `.env.example` says why the two differ.

### Added

- `security.proxy_arp_gateway`, default true, which is the switch for the rule
  above. Documented in `netgrasp.toml.example` and the README.
- `netgraspd migrate`. The schema error an empty database produces now names it
  rather than saying to start the daemon, which was advice that worked only as a
  side effect.
- `unattributed_names` and `proxy_arp_addresses` in the runtime status file, both
  `#[serde(default)]` so a file written by an older build still parses.
- `mdns_sleep_proxy`, a built fixture: one source MAC carrying three hosts'
  records, two of them proxied. It is the 2026-09-17 shape reduced to one frame.

### Changed

- The compose file's note on ordering says plainly what it means: the daemon
  migrates first and the plugin second, and running the plugin's migrations
  first is still fatal to the daemon's V1.

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
