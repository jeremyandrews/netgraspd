# netgraspd

A passive network device monitor. It watches LAN broadcast and multicast
traffic, works out what each device is by combining signals from several
protocols, tracks a per-device state machine, notices when somebody comes home,
and alerts you when something turns up that it has not seen before.

**It never transmits a packet on the segment it is watching.** No scanning, no
pinging, no ARP sweeps, no mDNS queries. It reads what is already on the wire.

There is exactly one thing it asks rather than overhears, and it is opt-in: an
*enricher* reads a controller you already run to find out which access point a
device is on. That is a question to your own infrastructure, never to a
monitored device, and it is off until you configure it.

## The rule

**State changes are stored, raw packet observations are not.**

The predecessor wrote one row per ARP packet and drowned in its own database.
This one keeps devices in memory, writes a row per *session* and a row per
*state change*, and counts packet volume as an integer on the open session.
There is no observations table and there must never be one; the integration
suite asserts it.

## Status

Milestone 3, which closes v1. On top of milestones 1 and 2:

- **Enrichment.** A UniFi enricher that reads which access point each device is
  associated with, behind a trait so another controller can be added without
  touching anything else.
- **Location.** An operator's map from access points to rooms, a history of
  where each device has been, and edge access points that distinguish somebody
  arriving from somebody wandering between rooms.
- **People.** Who is home, inferred from which of their devices are online, with
  arrival and departure notifications.
- **Maintenance.** Nightly rollup, pruning and vacuum, which is what makes an
  unattended year on a Raspberry Pi survivable.
- **`netgraspd stats`.** The command you run three months in to answer "is this
  thing healthy".
- **Packaging.** Docker image, compose stack, systemd unit, cross-compiled
  binaries for x86-64 and aarch64.

Milestone 1's state machine, identity resolution, learning mode, event bus, ntfy
notifier and CLI, and milestone 2's six capture sources, fingerprinting and six
security analyzers, are underneath unchanged.

See `ARCHITECTURE.md` for the design record, and
[What has and has not been exercised](#what-has-and-has-not-been-exercised)
below before you trust any of it on a network you care about.

## Quickstart

```sh
# 1. A database of its own.
createuser netgrasp --pwprompt
createdb netgrasp --owner netgrasp

# 2. Configuration.
cp netgrasp.toml.example netgrasp.toml
$EDITOR netgrasp.toml          # at minimum, database.url

# 3. Build, and grant the one capability capture needs.
cargo build --release
sudo setcap cap_net_raw,cap_net_admin+ep target/release/netgraspd

# 4. Watch. The first run on an empty database spends five minutes learning.
./target/release/netgraspd run
```

Then, in another terminal:

```sh
netgraspd devices          # what it has found
netgraspd events           # what it has decided
netgraspd stats            # whether it is healthy
```

## Building

```sh
cargo build --release
```

Needs libpcap headers: `libpcap-dev` on Debian and Ubuntu, `libpcap-devel` on
Fedora, already present in the macOS SDK.

## Capturing needs privilege

Packet capture needs raw socket access, and `netgraspd` checks on startup and
tells you which of the following you need.

**Linux.** Grant the capability to the binary rather than running the daemon as
root:

```sh
sudo setcap cap_net_raw,cap_net_admin+ep /usr/local/bin/netgraspd
```

This has to be reapplied after every upgrade. Under systemd, don't: the shipped
unit grants `CAP_NET_RAW` through `AmbientCapabilities`, which survives an
upgrade and takes every other capability away. See
[Deploying](#deploying).

**macOS.** There is no `setcap`. `/dev/bpf*` is root-only out of the box, so
either run under `sudo`, or install Wireshark's ChmodBPF helper so that members
of the `access_bpf` group can open it. macOS is a development platform for this
daemon; Linux is the deployment target, and each capture source needs verifying
per protocol on macOS because the BPF behaviour differs.

**In a container.** Capture needs `--network=host` *and* `--cap-add=NET_RAW`.
Without host networking the container sees the Docker bridge rather than your
LAN, so the daemon starts, captures nothing, and looks exactly like it is
working. See the comments at the top of `Dockerfile` for why the binary is
deliberately not `setcap`-ed in the image.

## Database

One Postgres database, shared with a Trovato instance if you run one. Every
table is prefixed `ng_`. Migrations are embedded and run on startup.

### How the Trovato plugin relates, and why the daemon must migrate first

The `ng_` tables are a contract with a Trovato plugin that lives in a different
repository. **The daemon owns that schema.** It writes the migrations, and it
refuses to start if what it finds does not match what this build expects,
naming the table and the column.

The plugin declares the same tables with `CREATE TABLE IF NOT EXISTS`, which
means it will happily accept tables that already exist with the wrong types and
fail much later as a broken device page. Two checks close that:

- **Before migrating**, the daemon looks for `ng_` tables it did not create. If
  the plugin got there first there is no `refinery_schema_history` table, and
  the daemon stops with a message telling you how to reconcile rather than
  failing with `relation "ng_devices" already exists`. Nothing is adopted and
  nothing is dropped: adopting types nobody checked is worse than stopping, and
  dropping somebody's data to fix a startup message is worse than either.
- **After migrating**, a preflight compares every `ng_` table against what this
  build expects and refuses to start on a divergence.

So the order is: **run `netgraspd` once against an empty database, then point
the plugin at it.** `docker-compose.yml` encodes that as a one-shot `migrate`
service everything else depends on.

Who owns which column:

| Table | Daemon writes | Plugin writes |
|---|---|---|
| `ng_devices` | identity, state, addresses, location | `display_name`, `notes`, `hidden`, `notify`, `owner_item_id`, `trovato_item_id` |
| `ng_people` | `state`, `current_location`, `last_arrived_at`, `last_departed_at` | `item_id`, `name`, `notes`, `notify_arrive`, `notify_depart` |
| everything else | all of it | nothing |

Every `timestamptz` the plugin reads has a generated `bigint` twin named
`<column>_epoch`, because the Trovato kernel's database host function decodes a
fixed list of types and returns null for a `timestamptz`. They are
`GENERATED ALWAYS ... STORED`, so nothing can write one out of step with its
source and the `timestamptz` column stays canonical.

### Backup and restore

```sh
# Back up. Custom format, so pg_restore can be selective later.
pg_dump postgres://netgrasp:netgrasp@localhost:5432/netgrasp \
    -Fc -f netgrasp-$(date +%Y%m%d).dump

# Restore into a clean database. Drop and recreate rather than --clean, which
# only drops objects that are *in* the dump and leaves anything added since.
dropdb --if-exists netgrasp
createdb netgrasp --owner netgrasp
pg_restore -d postgres://netgrasp:netgrasp@localhost:5432/netgrasp \
    netgrasp-20260814.dump
```

Stop the daemon first, or accept that the dump is a snapshot with open presence
sessions in it. Those are harmless: a restored open session is closed by the
first sweep after the daemon starts again.

A restored dump carries `refinery_schema_history`, so the daemon recognises it
as its own and migrates forward normally.

## Running

```sh
netgraspd run                      # watch, with a live device table
netgraspd run --learn              # force a baseline learning window first
netgraspd run -i eth0 -i wlan0     # specific interfaces
netgraspd devices                  # print the device table once
netgraspd devices --state offline  # ...filtered
netgraspd events --limit 50        # recent events
netgraspd events --security        # ...only what the analyzers found
netgraspd people                   # who is home, and where
netgraspd stats                    # is this installation healthy
netgraspd maintain                 # run the nightly jobs now
netgraspd maintain --dry-run       # ...and report what they would do
netgraspd update-fingerprints URL  # refresh the DHCP fingerprint table
```

The first run on an empty database spends five minutes learning the network.
Everything works normally during the window and every event is recorded; only
the *notifications* are suppressed, so you do not get a hundred alerts for the
devices that were already there. Devices found during the window are flagged
`baseline`.

## Configuration

`netgrasp.toml` in the working directory, or `--config`. See
`netgrasp.toml.example` for every setting with its default and the reasoning
behind it; a unit test asserts that the shipped example still parses and
validates, so it cannot rot.

Precedence, highest first:

1. Command-line flags.
2. Environment: `NETGRASP_` prefix, `__` between levels, e.g.
   `NETGRASP_DATABASE__URL`, `NETGRASP_STATE__IDLE_TIMEOUT`.
3. `netgrasp.toml`.
4. Compiled defaults.

Durations are written as `30m`, `2h`, `1d`, `90s`, or a bare integer meaning
seconds.

Unknown keys are rejected rather than ignored, so a typo is an error rather than
a setting that silently does nothing. **That applies to the environment too**:
every `NETGRASP_`-prefixed variable is read as configuration, so one that is not
a config key will stop the daemon starting. (This repository's own test harness
uses `NETGRASPD_TEST_DATABASE_URL`, deliberately outside the prefix, for exactly
that reason.)

The blocks this milestone adds:

| Block | What it does |
|---|---|
| `[enrichment]` | master switch for everything that asks a question |
| `[enrichment.unifi]` | controller URL, credentials or API key, site, poll interval, TLS verification, `edge_aps` |
| `[enrichment.unifi.locations]` | access point names to rooms |
| `[[people]]` | a person and the MACs they own, for an install with no Trovato plugin |
| `[maintenance]` | when the nightly jobs run, and how long presence and events are kept |
| `[runtime]` | where the daemon publishes the counters `netgraspd stats` reads |

`[enrichment.unifi.locations]` is a TOML table, so it must come after every
plain key in `[enrichment.unifi]`.

## Location and people

An enricher tells the daemon which access point a device is associated with. The
operator's map turns that into a room. An access point with no entry in the map
falls back to its own name, so a newly adopted AP shows up as itself rather than
disappearing.

**Edge access points** are the ones that see arrivals and departures first: a
driveway, a garage. They are what separate a threshold crossing from ordinary
movement:

| Crossing | Reads as |
|---|---|
| edge → interior | arriving |
| interior → edge | on the way out |
| interior → interior | walking about, and nothing else |
| edge → edge | still outside |
| nothing → anywhere | unknown; a device already here when the daemon started has not arrived |

The person rules are deliberately simple, because every elaboration anybody has
tried produces a system that announces you have left the house while you are
sitting in it:

- A person is **home** when any device they own is online.
- The first owned device online after all were offline is an **arrival**.
- The last owned device going offline is a **departure**.
- A person's **location** is that of their most recently active device. Not the
  first, not an average: the phone in your pocket is talking and the tablet in
  the drawer is not.

Edge crossings do not change those rules; they supply the *evidence*, so an
arrival reads "through the Driveway" rather than just "arrived". A departure is
declared a whole offline timeout after the device fell silent, so the crossing
is matched against the device's own last activity rather than against the
moment of departure.

Ownership comes from `ng_devices.owner_item_id` when the plugin fills it, and
from `[[people]]` in `netgrasp.toml` when there is no plugin. The two are merged
rather than chosen between, and a person named in the file who already exists in
`ng_people` is adopted rather than duplicated, so it is safe to list somebody in
both.

`person_arrived` and `person_departed` are gated by `notify_arrive` and
`notify_depart` on the person row, which default to off. They do not have to
appear in `notify.event_types` as well; requiring both would make a silent
misconfiguration look like a working setup. `person_location_changed` is
recorded and never delivered.

## Maintenance and retention

Without the nightly jobs, `ng_presence` grows one row per session forever and
`ng_events` never stops. With them the database reaches a steady size a few
weeks in and stays there.

| Job | Default |
|---|---|
| presence sessions compact into one summary row per device per day | after 30 days |
| location stays compact into one row per device per location per day | after 30 days |
| events are deleted | after 90 days |
| overlapping address ranges merge | always (a structural no-op; see below) |
| `VACUUM ANALYZE` | after a rollup that actually moved rows |

Two invariants hold whatever the configuration says: **the current day is never
touched**, and **an open session is never compacted**. A device that has been
continuously online for a year keeps its session.

The address-range merge is a no-op by construction: `ng_ip_history` carries
`UNIQUE (device_id, ip)`, so a second row for one pair cannot exist. It runs
anyway as a safety net if that index is ever dropped, and reports zero. A
maintenance routine that quietly omits a job it claims to run is worse than one
that runs it and reports nothing to do.

Note that a plain `VACUUM` returns space to the table's free space map, not to
the filesystem, so `pg_total_relation_size` can grow across a rollup and then
stay flat forever after. That is the intended steady state; if you want the
space back, `VACUUM FULL` while the daemon is stopped.

## Health

`netgraspd stats` reads two independent sources and says plainly when one is
missing:

- The **runtime status file** for facts about the process: uptime, resident
  memory, per-source capture rates, enricher poll and failure counts. `stats` is
  a separate process, so none of that can come from Postgres. If the file is
  absent or stale, `stats` says the daemon is not running and answers the rest
  regardless.
- The **database** for what has been recorded: device counts by state, events by
  type, the retention span, how far the rollup has got, and the size of every
  `ng_` table.

Resident memory scales with **interfaces × sources × `capture.buffer_size`**,
because each is a pcap handle with a kernel buffer. One interface with all six
sources measured 15 MB; the same daemon on a Docker host with twenty-three
interfaces measured 185 MB. On anything with more interfaces than you care
about, list the ones you want with `capture.interfaces` or `-i`.

## Deploying

### systemd

```sh
sudo install -m 0755 target/release/netgraspd /usr/local/bin/
sudo install -m 0644 packaging/netgraspd.service /etc/systemd/system/
sudo useradd --system --no-create-home --shell /usr/sbin/nologin netgraspd
sudo install -m 0640 -o root -g netgraspd netgrasp.toml /etc/netgrasp.toml
sudo systemctl daemon-reload && sudo systemctl enable --now netgraspd
```

The unit grants `CAP_NET_RAW` through `AmbientCapabilities` rather than running
as root, and survives an upgrade in a way that `setcap` on the binary does not.

### Docker

```sh
docker build -t netgraspd .

# Capture: host networking to see the LAN, one capability, nothing else.
docker run -d --name netgraspd \
    --network=host --cap-drop=ALL --cap-add=NET_RAW --user root \
    -e NETGRASP_DATABASE__URL=postgres://netgrasp:netgrasp@localhost:5432/netgrasp \
    -v /etc/netgrasp.toml:/etc/netgrasp.toml:ro \
    -v netgraspd-state:/var/lib/netgraspd \
    netgraspd run --config /etc/netgrasp.toml --no-table

# Everything else needs neither, and runs as the image's unprivileged user.
docker run --rm netgraspd stats
```

Build the Raspberry Pi image with `--platform linux/arm64`.

### Compose

```sh
cp .env.example .env
$EDITOR .env netgrasp.toml
docker compose up -d
```

The `migrate` service applies the schema and exits; the daemon and the optional
Trovato service both wait for it, which is what makes "the daemon migrates
first" a fact rather than a hope. Trovato is behind a profile and its image is
parameterised, because this repository does not know which build you run:

```sh
docker compose --profile trovato up -d
```

### Cross-compiled binaries

CI builds `x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` with
[`cross`](https://github.com/cross-rs/cross) and uploads both as artifacts.
`Cross.toml` installs libpcap for the target architecture, which the stock
images do not carry; without it the build fails at link time with
`cannot find -lpcap`, which is a confusing message for something that builds
fine on the host.

To build one locally:

```sh
cargo install cross --locked
cross build --release --target aarch64-unknown-linux-gnu
```

## How a device gets its name

Every signal ever seen is stored in `ng_device_signals` and never overwritten,
so a later signal *refines* the identity instead of replacing it. The scorer
picks the highest-weighted one available:

| Signal | Weight | Where it comes from |
|---|---|---|
| name you typed in Trovato | absolute | honoured; the daemon never overwrites it |
| mDNS instance name | 0.9 | `_airplay._tcp` and friends, and A record owner names |
| DHCP hostname | 0.8 | option 12 on a client message |
| reverse DNS | 0.7 | opt-in; the one thing that transmits |
| NetBIOS name | 0.6 | a name registration or a datagram source name |
| SSDP friendly name | 0.5 | a header the device volunteered, never a fetch |
| vendor plus device type | 0.3 | the IEEE registry plus the classifier |
| bare MAC | 0.1 | always available |

The SSDP friendly name deserves its footnote. The UPnP `friendlyName` lives in
the device description XML at the `LOCATION` URL, and fetching it means an HTTP
GET **to the monitored device**. That is not passive, so it does not happen.
What is read instead is a friendly name a device volunteered in a header, which
Chromecast and other DIAL devices do as base64 `X-friendly-name`; those bytes are
already on the wire. A device that volunteers nothing simply has no 0.5 signal.

## How a device gets its type

Separately from its name, because the two come from different signals: a
fingerprint knows the operating system and a service type knows the device.
Evidence is ranked by how hard it is to be wrong about, and the first hit wins:

| Evidence | Confidence | Why it ranks there |
|---|---|---|
| IPv6 Router Advertisement | 0.99 | a device that sends one *is* a router |
| SSDP device URN | 0.90 | it declared its own UPnP class, unprompted |
| mDNS service type | 0.85 | `_ipp._tcp` is a printer, but a laptop sharing one says so too |
| DHCP option 55 fingerprint | 0.95 exact, less for a near match | Fingerbank-shaped table, embedded |
| vendor class, mDNS model, SSDP server | 0.70 | self-declared text, where false positives live |
| NetBIOS presence | 0.50 | a Windows-speaking machine, but so is a Samba NAS |
| IEEE vendor | 0.40 | Espressif makes IoT chips, but vendors make many things |
| always-on plus an IoT vendor | 0.35 | inference, not evidence, so it goes last |

The confidence is stored in `ng_devices.device_type_confidence`, so a reader can
tell "this is a printer because it said so" from "this is probably a printer
because Brother made it".

The fingerprint table is compiled into the binary, so classification works on a
network with no internet access. `netgraspd update-fingerprints <url>` downloads
a fresh one; it parses and validates the download **before** replacing anything,
so a captive portal serving a login page cannot break classification.

Vendors come from all three IEEE registries (MA-L, MA-M and MA-S) embedded in
the binary, with longest-prefix lookup so that the 24-bit blocks IEEE has
subdivided resolve to the real assignee.

Reverse DNS is **off by default**. It is the one thing the daemon does that puts
packets on a wire; they go to your resolver rather than to the monitored device,
but "passive" should mean passive unless you said otherwise.

## Notifications

All rate limiting lives in the dispatcher, not in any notifier:

- per-device debounce, five minutes by default;
- batching, so ten or more devices appearing inside a minute collapse into one
  summary rather than a storm (this is what makes a router reboot one message);
- quiet hours, evaluated in local time;
- a per-device `notify` toggle you set from Trovato.

The batch window costs up to `notify.batch_window` of latency on every
notification. Set `notify.batch_threshold = 0` to turn batching off if you would
rather have them instantly.

Two categories skip the `notify.event_types` allowlist because they are governed
elsewhere: security events by `[security.notifications]`, and person events by
`notify_arrive` and `notify_depart` on the person row. Requiring them in two
places would make a silent misconfiguration look like a working setup.

## Security analyzers

Six detectors sit between the capture layer and the device state machine. They
consume the same observation stream, keep bounded in-memory state, persist
nothing, and emit events onto the same bus.

| Analyzer | Fires when | The false positive it is built to avoid |
|---|---|---|
| `arp_scan` | one MAC asks about many *distinct* addresses in a window | a device retrying one unanswered ARP is not scanning |
| `arp_spoof` | a MAC claims an address whose holder is still talking | leases change hands all day; only a live holder makes it an attack |
| `rogue_dhcp` | an Offer, Ack or Nak from an unexpected MAC | only a server sends those, so a client never trips it |
| `identity_change` | stronger evidence contradicts what weaker evidence said | learning what a device is for the first time is a refinement |
| `ip_conflict` | two active MACs use one address | a handover after the window is a reassignment |
| `gratuitous_arp` | a flood of unsolicited announcements from one MAC | devices legitimately send a few on boot |

Three properties are worth stating outright.

**They see every observation, including the deduplicated ones.** The
cross-interface dedup collapses on `(MAC, kind, second)`, which is exactly the
shape of a scan burst. Running the analyzers downstream of it would make
`arp_scan` useless, so the daemon feeds them before dedup decides anything.

**They are stateless across restarts.** A detector that trusted state written
before a crash would be trusting state written by whatever caused it. The cost is
that `rogue_dhcp` re-learns the legitimate server after a restart; set
`security.rogue_dhcp.known_servers` to close that window.

**Security events play by different notification rules.** They are recorded
during a learning window, they ignore the per-device `notify` toggle, they do not
have to appear in `notify.event_types`, and by default they bypass quiet hours,
the debounce and the batch window. The one thing they do not bypass is
`notify.enabled`, because a master switch with an exception is not a master
switch.

The gateway is worked out passively, because several analyzers treat it
differently: DHCP option 3 states it outright, and failing that the address the
most *distinct* MACs ARP for is the gateway. Once known, it is not given up to
evidence that is no stronger, which is what stops an attacker forging one ARP
reply to become the gateway and silence the detector that was watching for
exactly that.

## What has and has not been exercised

Written plainly, because a monitoring tool whose limits you cannot see is worse
than one that has none.

**Exercised against a live network:** capture on Linux, in a container with
`--network=host` and `--cap-add=NET_RAW`. All six sources start, the permission
path works end to end, and devices, presence sessions, events and a security
event were produced from real traffic. That was a container host's own segment
over a few minutes, not a home LAN over weeks.

**Exercised against a real database:** the schema, every migration, the rollup,
the retention, the location history invariants, the people state machine and the
plugin contract. Postgres 17.10 locally and Postgres 17 in CI; the V3 generated
columns were verified on both 16.13 and 17.10.

**Exercised against fixtures or a mock:** every packet parser (recorded `.bin`
frames), the six analyzers, and the whole UniFi enricher. The UniFi tests drive
real HTTP over a real socket against a mock controller, including an expired
session mid-poll and an unreachable controller, but **no real UniFi controller
has ever been contacted**.

**Not exercised at all:**

- A real UniFi controller, so the exact JSON shape of your firmware is a
  guess informed by published responses rather than something that has been
  seen. The decoder ignores unknown fields and tolerates missing ones, which is
  the best that can be done without one.
- A Raspberry Pi. The aarch64 image is built and runs; nothing has been left on
  a Pi for a month.
- The Trovato plugin. The schema is asserted from this side against the DDL both
  repositories agree on; the two have never been run together.
- Capture on macOS beyond the permission check. `/dev/bpf*` is root-only, and
  each protocol needs verifying separately there.
- Months of real elapsed time. The rollup evidence is a synthetic six-month
  dataset compacted in one run, not six months of a daemon running.

## Development

```sh
cargo test --lib                   # unit tests, no database needed
cargo test --all                   # everything, needs Postgres
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
cargo audit
```

The integration suite needs a Postgres it can migrate and truncate. Point it
somewhere with `NETGRASPD_TEST_DATABASE_URL`; without a reachable database those
tests print why and pass, so a checkout with no Postgres still goes green on
everything else. A database that *is* reachable but cannot be migrated is a
failure rather than a skip, because a whole binary silently skipping is a green
tick that proved nothing.

Run the whole suite in one command rather than target by target. Every
integration target shares one database, which is what makes cross-file
interference through shared fixtures observable.

Refresh the embedded vendor registry with `scripts/refresh-oui.sh`.

Regenerate the packet fixtures with `cargo run --example build-fixtures`. The
`.bin` files under `tests/fixtures/` are what the parsers actually read; a test
asserts that they still equal what the builders in
`src/capture/fixtures/build.rs` produce, so a builder edit that is not
regenerated fails rather than leaving every parser test quietly green against
stale bytes.

## Licence

MIT.
