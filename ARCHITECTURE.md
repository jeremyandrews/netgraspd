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

### The kernel-to-daemon direction needs a clock of its own

Writing the user-owned columns back to `ng_devices` is only half of that second
bullet. The daemon rehydrated them once, at startup, and no timer read them
again, so muting a device in the admin UI did nothing until somebody restarted
the daemon. The first joint run measured it: 33 of 35 presence deliveries
ignored a `notify` set to false and a newly assigned owner.

So there is a **reconcile tick**, `state.reconcile_interval`, ten seconds by
default. It reads the user-owned columns and the whole `ng_people` mirror and
merges them into the device table and the people registry, in that direction
only. It is the mirror image of the flush: the flush writes what the daemon owns
and names its columns explicitly, the reconcile reads what the user owns and
names its columns explicitly, and a test guards each statement against the
other's columns appearing in it.

Three things are worth stating because each was a decision rather than an
accident:

- **The merge names its columns.** It iterates a list, exactly as the plugin's
  `USER_OWNED` list works from the other side, so a column can only be merged on
  purpose. `hidden` and `notes` are on the list as columns the daemon
  deliberately does nothing with.
- **A merge does not dirty a row.** Those columns are absent from the daemon's
  update statement by design, so flushing after a merge would be a write that
  writes nothing and a `sync_state = 'dirty'` the plugin's sweep would collect
  for no reason.
- **Configuration survives a null.** An install with no plugin has
  `owner_item_id` null on every row and `[[people]]` as the only source of
  ownership. Reading that null as "nobody owns it" would have disabled people
  tracking ten seconds after start, so the registry remembers which ownership
  came from configuration and falls back to it. The database still wins wherever
  it says anything, which is the precedence the startup roster already applied.

### Why the reconcile polls, and what `LISTEN` would take

Polling is not the responsive option; it is the one that needs no agreement from
another repository. `LISTEN`/`NOTIFY` would be better on latency and cost, and
it is deferred rather than rejected:

- **The plugin does not send it today.** A `NOTIFY netgrasp_user_edit` after the
  update tap's write-back is a new line in the contract, and a contract line
  lands in both repositories or neither.
- **A pooled connection cannot hear one.** Asynchronous messages reach
  `tokio_postgres::Connection::poll_message`, and deadpool spawns that driver
  itself, so a notification never reaches a pooled `Client`. `LISTEN` means a
  dedicated connection outside the pool, owned by a task that reconnects on its
  own, because a `LISTEN` that dies silently is a daemon that stops noticing
  edits and says nothing about it.
- **The poll costs almost nothing to keep meanwhile.** The read is under a
  millisecond of server time for two thousand devices, so the poll is cheap
  enough that the interval is set by how long a person will wait after saving a
  page, not by database load.

The shape when it happens: the dedicated connection's task sends a tick down a
channel, the select loop reconciles on either that or the timer, and the timer
stays as the backstop for a missed or unsent notification. The merge itself does
not change, which is the point of it being a plain function over state.

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

Milestone 1 implemented OUI vendor lookup, mDNS instance name and reverse DNS.
Milestone 2 filled in the rest, and the prediction held: the parsers added rows
and the scorer was not touched.

The SSDP friendly name arrived with one caveat that was flagged in the milestone
1 stub and survives implementation. The UPnP `friendlyName` is not in the
multicast announcement; it lives in the device description XML at the `LOCATION`
URL, and fetching it is an HTTP GET to the monitored device. Netgrasp does not
transmit on the segment it watches, so that fetch does not happen and must not be
added. What is read instead is a friendly name a device *volunteered in a
header*: Chromecast and other DIAL devices send base64 `X-friendly-name`, some
DLNA stacks send `FRIENDLYNAME.DLNA.ORG`. Those bytes are already on the wire. A
device that volunteers nothing has no 0.5 signal and the scorer falls through, as
designed.

### Attribution, corrected after the 2026-09-17 run (0.4.1)

The scorer was never the problem. What was wrong sat one layer earlier: the mDNS
walker attributed every name in a message to the frame's source MAC, and that is
only true when a responder speaks for itself. It routinely does not. A Bonjour
Sleep Proxy answers address queries on behalf of machines that are asleep, a
responder answers for several of its own hostnames at once, and a service
response carries the additional records of whoever the service belongs to. The
live run produced one iPhone holding six other hosts' names, and one name
recorded against six different MACs.

The corrected model separates two questions that had been one. **What does this
record say** is the parser's, and it is answered without reference to the sender:
each piece of evidence is resolved to the address the message gave it, directly
for an A or AAAA record and through the SRV target for an instance name. **Whose
address is that** is the device table's, because it is the only layer holding the
ARP and DHCP evidence that answers it. The pair crosses the boundary as a
`NameClaim` on the observation, and `Manager::attribute` resolves it.

That makes a sleep proxy's answer evidence about the sleeping host rather than
about the proxy, which is what it always was. Evidence naming an address no known
device holds is counted rather than attributed, because the alternative is
inventing a device or libelling one. Evidence naming no address at all still
falls back to the sender, since a device announcing a service without repeating
its own address record is ordinary; the exception is a frame that has already
proved it speaks for somebody else, which forfeits the assumption for the rest of
its unqualified records.

The same run exposed a second, independent defect in the scorer's *adoption*
rule rather than its ranking. `improves_on` treated any equal-confidence change
of text as an improvement, and because each frame's signals are re-inserted at
the front of the list, two equal-weight mDNS names take turns winning the
same-kind tie-break. 385 `name_updated` events in thirty minutes. Rank still
promotes immediately; an equal-rank rival must now hold the win for five minutes
before it is adopted, and loses the accumulated time the moment it stops winning.
Alternating candidates never settle, a genuine rename settles once.

### Classifying signals, added in milestone 2

Seven signal kinds carry evidence about what a device *is* rather than what it is
called. They weigh zero, never compete for the display name, and exist because
the classifier needs them: `mdns_service`, `mdns_model`, `dhcp_fingerprint`,
`dhcp_vendor_class`, `ssdp_device_type`, `ssdp_server`, `netbios_workgroup` and
`ndp_role`.

## Device-type classification

Ranked by how hard the evidence is to be wrong about, first hit wins, and the
rank sets `ng_devices.device_type_confidence` so a reader downstream can tell a
declaration from a guess:

| Evidence | Confidence |
|---|---|
| IPv6 Router Advertisement | 0.99 |
| DHCP option 55 fingerprint, exact | 0.95 |
| SSDP device URN | 0.90 |
| mDNS service type | 0.85 |
| DHCP option 55 fingerprint, nearest | up to 0.80 |
| self-declared text (vendor class, mDNS model, SSDP server) | 0.70 |
| NetBIOS presence | 0.50 |
| IEEE vendor | 0.40 |
| always-on plus an IoT vendor | 0.35 |

Two consequences of stored signals never being removed, both deliberate:

1. **Weaker evidence arriving later cannot move a classification.** A NAS that
   speaks NetBIOS and advertises `_smb._tcp` stays a NAS rather than becoming a
   Windows computer.
2. **A classification therefore changes only when higher-rank evidence
   contradicts lower-rank evidence.** That is precisely what `identity_change`
   alerts on, and it is why that analyzer is quiet on a healthy network.

The device-type vocabulary is closed. Anything outside it, including from a
downloaded fingerprint table, is ignored rather than stored, because
`state.device_type_overrides` keys on these values and the plugin will facet on
them.

### The fingerprint table

`data/dhcp_fingerprints.conf` is a curated subset in the shape of the PacketFence
and Fingerbank files, embedded with `include_str!`. It is **not** a verbatim copy
of the upstream database, which is much larger and separately licensed; the
parser ignores unknown keys so the upstream file parses here unchanged if
somebody drops one in.

Embedded rather than fetched, because a passive monitor that phones a vendor to
identify a device is not a passive monitor. `netgraspd update-fingerprints <url>`
refreshes it on demand, parses and validates the download before replacing
anything, and writes to `identity.fingerprint_path`, which the daemon prefers
when it exists.

Matching is exact first, then nearest by longest common subsequence of the two
ordered lists normalised by the longer one. Order is preserved throughout because
two operating systems routinely request the same options in a different sequence
and that sequence is most of the discriminating power. A near match reports a
confidence below any exact one, so a guess never claims as much as a match.

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
| 2 | **done.** DHCP, SSDP, NDP, NetBIOS parsers; DHCP fingerprints; device-type classification; the six analyzers | Most devices auto-identified by name/type/OS; spoof and rogue-DHCP detection live |
| 3 | Trovato plugin: device/person/event content, bidirectional device sync, gathers, tiles, roles, event pruning, friction report | Phone-openable dashboard: name a device, assign an owner, see who is home, viewer role read-only |
| 4 | enrichment and packaging: UniFi enricher, location model, arrival/departure, people notifications, rollup jobs, docker-compose, cross-compile aarch64 | "Elena is in the backyard"; runs unattended on a Pi; deployable unit |

Milestones 1 and 2 are pure daemon work and can run before, or in parallel with,
any Trovato session.

## The security analyzer chain

Six analyzers between the capture channel and the device manager, consuming the
same `Observation` stream and emitting on the existing bus. The milestone 1
prediction that this would need no schema change held: `ng_events.details` is
jsonb and the six new event types carry their evidence in it.

Three properties the design turns on.

**Analyzers see every observation, including the deduplicated ones.** The
cross-interface dedup collapses on `(MAC, kind, second)`, which is exactly the
shape of a scan burst: two hundred ARP requests from one MAC in one second are
one observation to the state machine and are the entire signal to `arp_scan`. The
daemon therefore runs the state machine on the deduplicated stream and the
analyzers on everything. The state machine runs *first*, so a brand-new
attacker's device row exists before the alert about it is recorded and the event
can carry a `device_id`.

**Analyzers are stateless across restarts.** Nothing is persisted. A detector
that trusted state written before a crash would be trusting state written by
whatever caused it. The one place this costs something is `rogue_dhcp`, whose
first-seen-server heuristic re-learns after a restart;
`security.rogue_dhcp.known_servers` closes that window and the analyzer logs the
fact the first time it learns one.

**Analyzers know nothing about devices.** They deal in MAC addresses, so they
need no lock on the device table and no database. `Manager::security_event`
attaches names, vendors and row ids afterwards.

Every analyzer holds itself back with a cooldown, so a condition that persists
for an hour produces alerts at a bounded rate rather than one per packet. That is
not the notification dispatcher's debounce, which security events deliberately
bypass; it is the detector declining to say the same thing twice.

### The gateway is worked out passively

`arp_spoof` treats a claim on the gateway address as an immediate alert, and
`arp_scan` holds the gateway to a looser threshold, so the chain needs to know
which device it is. In order of trust: configuration, then DHCP option 3, then
the address the most *distinct* MACs have ARPed for. Distinct askers rather than
total requests, because one device retrying one address would otherwise elect it.

Two rules stop this becoming an attack surface of its own:

- A **learned** gateway MAC may be set by equal-rank evidence but **replaced**
  only by strictly stronger evidence. The MAC is learned from ARP replies and
  from traffic sourced at the gateway address, both of which an attacker
  controls completely. An attacker who could replace it with one forged reply
  would make `arp_spoof` treat itself as the gateway and stop alerting, turning
  the detector into an accessory.
- Gateway impersonation fires **without** requiring a prior ARP claim by the real
  gateway. On a settled network everybody already has the gateway cached and it
  may never answer an ARP at all; requiring a prior claim would mean the one
  attack this analyzer exists for is the one it would miss.

### Proxy ARP, added after the 2026-09-17 run (0.4.1)

Knowing which device is the gateway turned out to matter for a third reason. A
router that routes between VLANs answers ARP for the far side with its own
hardware address, so an address is legitimately in use at the router's MAC *and*
at its real owner's. `ip_conflict` measures exactly that co-presence and
`arp_spoof` measures exactly that handover, so both fired on every segment. All
34 alerts in the live run were this, and an analyzer that fires on ordinary
traffic trains its operator to ignore it, which is the failure mode the whole
chain is designed around.

The exemption is deliberately narrow and is evaluated per packet rather than
from a remembered set, so nothing an attacker sends can widen it later. It
requires all three of: a **reply**, because a request claims the sender's own
address; the learned gateway MAC as the **Ethernet source**, not the ARP sender
field, which an attacker writes freely; and an address that is **not** the
gateway's own, because the gateway answering for the gateway is the gateway and
impersonating it is the attack.

Both analyzers return before touching their state, which is the part that is
easy to get wrong. Had the router been recorded as a user or holder of the
proxied address, the real owner's next packet would have read as displacing it
and alerted on the way past: the false positive would have moved rather than
gone. Because the router never becomes the holder, a stranger taking a proxied
address is still caught against the real owner.

## IPv6 addressing, revisited

The milestone 1 note asked for the IPv4-only `last_ip` decision to be revisited
once NDP landed. It was, and it stands with one addition.

`ng_devices.last_ip` remains IPv4-only, because it drives `ip_changed` and RFC
4941 privacy addresses rotate as often as daily; a single current-address column
would emit a meaningless `ip_changed` per device per day. What was actually
missing was a current IPv6 address at all, so `ng_devices.last_ipv6` was added in
migration V2: written on flush, never event-generating, and preferring a global
address over the link-local one every device always has and which is derived from
the MAC anyway.

Privacy-extension rotation means one MAC legitimately accumulates many rows in
`ng_ip_history`. Netgrasp is MAC-keyed so this produces no phantom devices, but
the row count is worth watching; it is a candidate for the presence rollup job in
the enrichment milestone.

## Milestone 3: enrichment, location, people and unattended operation

### Enrichment is the one thing that asks

Everything else in the daemon works from frames that arrived on their own. An
enricher asks a controller the operator already runs which access point a device
is on. The standing fence holds: it never sends anything to a monitored device.

**Why it is in the daemon and not in the Trovato plugin.** The controller sits on
a private address, and the kernel's HTTP host function refuses private addresses
under its SSRF policy. A plugin cannot reach it at all.

The trait takes a poll interval and a device list and returns enrichments. The
orchestrator holds per-source deadlines and runs each due source in turn; a
source that fails produces a logged warning and no enrichments, so every device
keeps the location it had. A controller that is down for an hour makes locations
stale, never absent.

`stat/sta` reports the access point as `ap_mac`, not as a name, so each poll also
reads `stat/device` for the inventory. Locations are keyed on names because
`Living Room AP` is what somebody typed into the controller and `f4:e2:c6:…` is
not something anybody wants in a config file. An AP that cannot be resolved falls
back to its MAC: ugly, visible, never silently absent.

### Location is a place plus a crossing

A place comes from the operator's map, with the AP's own name as the fallback so
that a newly adopted access point shows up as itself.

A crossing is classified from the pair of access points, and this is the whole
reason edge APs exist. Edge-then-interior is somebody arriving; interior-then-edge
followed by silence is somebody leaving; interior-to-interior is somebody walking
about and must never read as either. An unmapped AP counts as interior, so a
forgotten mapping produces no arrival rather than a false one.

`ng_location_history` carries the same partial unique index `ng_presence` does,
so at most one stay is open per device. A location change is **one** effect that
closes and opens, rather than two that could be half-applied.

An enricher polling every thirty seconds reports the same association every time.
Turning each into a stay would reproduce the row-per-observation failure this
whole daemon exists to avoid, through a different door, so an unchanged access
point produces nothing at all.

### People, and what the edge evidence is measured against

A person is home when any device they own is online; the first online after all
were offline is an arrival and the last offline is a departure. Every
elaboration of that anybody has tried announces you have left while you are
sitting in the house.

Edge crossings supply evidence rather than changing the rule. The subtlety that
cost a rewrite: **an arrival and a departure measure the evidence window against
different things.** An arrival is decided the moment a device is heard from, so
the crossing is minutes old. A departure is decided a whole `offline_timeout`
after the device fell silent, three hours by default, which puts every crossing
outside a fifteen-minute window forever. So a departure measures the crossing
against the *device's own last activity*: not "did they cross an edge recently"
but "did they cross an edge shortly before they stopped talking".

Ownership is merged from two sources rather than chosen between: the plugin's
`ng_devices.owner_item_id`, and `[[people]]` in the config file for a standalone
install. A configured person who already exists in `ng_people` is adopted by
name, which is what makes it safe to be listed in both. That adoption is the only
place the daemon writes a plugin-owned column, and only when creating a row that
did not exist.

### The schema is a contract, and it is checked twice

The plugin declares the same tables with `CREATE TABLE IF NOT EXISTS`, so a table
that already exists with the wrong types is accepted in silence and fails weeks
later as a broken page. Two checks close that: a plugin-first detector before
migrating, and a full column-and-type preflight after. Neither adopts and neither
drops. `EXPECTED` in `db/schema.rs` is the single statement of the contract, and
an integration test asserts the live schema matches it exactly, so a change here
breaks this repository's suite rather than the plugin's.

Every `timestamptz` the plugin reads has a generated `bigint` twin, because the
kernel's database host function decodes a fixed list of types and returns null
for a `timestamptz`. `GENERATED ALWAYS ... STORED`, so nothing can write one out
of step with its source.

### Maintenance, and the two invariants it may never break

The current day is never touched, and an open session is never compacted. Both
are enforced in the queries rather than trusted: every cutoff comes from one
function that returns the start of a UTC day, and every rollup requires
`ended_at IS NOT NULL`.

Cutoffs are computed in Rust from a `now` passed in rather than from the
database's `now()`, which is what lets a test seed six months of history and roll
it up without waiting six months.

Location rolls up per device per **location** per day, unlike presence which is
per device per day. Merging across locations would record a stay somewhere
between the kitchen and the driveway, which is not a place.

### Runtime status is a file, not a table

`netgraspd stats` is a separate process, so uptime, resident memory and
per-source capture rates cannot come from Postgres. An `ng_stats` table would be
a schema change the plugin has not seen, written once a minute forever, to hold
numbers that are meaningless the moment the daemon stops. So the daemon writes a
small JSON file atomically and `stats` reads it, says plainly when it is missing
or stale, and answers the database half regardless.

Resident memory scales with interfaces × sources × `capture.buffer_size`, since
each is a pcap handle with a kernel buffer: 15 MB on one interface with all six
sources, 185 MB on a Docker host with twenty-three.

## Where deferred work attaches

- **Bluetooth passive scanning:** the `CaptureSource` trait leaves the slot, and
  `StubSource` survives unused so that the next protocol can be nameable in
  config and present in the startup path before it can capture anything.
- **A second enricher:** the `Enricher` trait takes a poll interval and returns
  enrichments; nothing about the orchestrator, the location model or the people
  registry is UniFi-specific.
- **Plugin sync:** `ng_devices.sync_state` / `trovato_item_id` and
  `ng_events.sync_state` are written by the daemon and read by nothing here.
- **`LISTEN` for user edits:** the reconcile tick is a plain function over state
  with a timer in front of it, so the channel that replaces the timer attaches
  without touching the merge. Design above, under "Why the reconcile polls".
- **Per-poll telemetry:** VLAN and byte counters ride into
  `ng_events.details` on a location change rather than into columns. If anybody
  ever wants to chart them, that is a schema change the plugin has to see first.

## Open questions

1. macOS daemon support: pcap over BPF works but needs root or a `/dev/bpf*`
   group, and each protocol wants re-verification there. Linux is the target;
   macOS is a development convenience.
2. Whether devices become kernel Items or lightweight records is a plugin
   decision, not a daemon one. The daemon's side of it is settled:
   `ng_devices.trovato_item_id` is a UUID the plugin fills and the daemon only
   reads.
3. No real UniFi controller has been contacted. The decoder ignores unknown
   fields and tolerates missing ones, which is the most that can be done from
   published response shapes; the first contact with real firmware is the thing
   most likely to need a fix.
