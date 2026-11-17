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

Version 1.0.0: milestone 3, which closes v1, plus the reconcile tick that makes
an edit in Trovato reach a running daemon and the fixes from the first run on a
real home network. It is the code that was 0.4.1, released: `CHANGELOG.md` has
the history and the versioning rule, which from 1.0.0 is semantic versioning
over the command line, the configuration file and the `ng_` schema.

**No real UniFi controller has ever been contacted**, and the daemon has not yet
run unattended on a real network for longer than an evening. Read
[What has and has not been exercised](#what-has-and-has-not-been-exercised)
before you rely on it.

On top of milestones 1 and 2:

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

## Install

From a [release](https://github.com/jeremyandrews/netgraspd/releases), with no
Rust toolchain. Each release publishes the same daemon two ways: a
multi-architecture image, and the binary out of that image for `x86_64` and
`aarch64` (a Raspberry Pi), with a `SHA256SUMS`.

Whichever you choose, the daemon needs a Postgres database of its own, and it
creates its tables there before anything else touches it:

```sh
createuser netgrasp --pwprompt
createdb netgrasp --owner netgrasp
```

`createuser` and `createdb` connect to a server on the local socket. When
Postgres runs in a container or on another host, run the same two steps as SQL
over a superuser connection instead:

```sh
psql "postgresql://postgres:…@127.0.0.1:5432/postgres" \
    -c "create role netgrasp login password '…'"
psql "postgresql://postgres:…@127.0.0.1:5432/postgres" \
    -c "create database netgrasp owner netgrasp"
```

and point `database.url` at it:
`postgres://netgrasp:…@127.0.0.1:5432/netgrasp`. The same holds wherever
`createuser` or `createdb` appears below.

### The image

```sh
docker pull ghcr.io/jeremyandrews/netgraspd:1.0.0

# The example configuration ships inside the image.
docker run --rm --entrypoint cat ghcr.io/jeremyandrews/netgraspd:1.0.0 \
    /usr/share/netgraspd/netgrasp.toml.example > netgrasp.toml
$EDITOR netgrasp.toml          # at minimum, database.url
```

Then run it as [Docker](#docker) below describes, substituting
`ghcr.io/jeremyandrews/netgraspd:1.0.0` for the locally built `netgraspd`, or
with [Compose](#compose). Tags are the version (`1.0.0`), the minor line
(`1.0`) and `latest`; pin the version.

### The binary, under systemd

```sh
v=1.0.0
arch=x86_64-unknown-linux-gnu          # or aarch64-unknown-linux-gnu
base=https://github.com/jeremyandrews/netgraspd/releases/download/v$v
curl -fLO "$base/netgraspd-$v-$arch"
curl -fLO "$base/SHA256SUMS"
sha256sum --check --ignore-missing SHA256SUMS

sudo apt-get install libpcap0.8        # the one runtime library
sudo install -m 0755 "netgraspd-$v-$arch" /usr/local/bin/netgraspd

# The unit and the example configuration, from the same tag.
raw=https://raw.githubusercontent.com/jeremyandrews/netgraspd/v$v
curl -fLO "$raw/packaging/netgraspd.service"
curl -fLO "$raw/netgrasp.toml.example"
cp netgrasp.toml.example netgrasp.toml
$EDITOR netgrasp.toml                  # at minimum, database.url

sudo useradd --system --no-create-home --shell /usr/sbin/nologin netgraspd
sudo install -m 0640 -o root -g netgraspd netgrasp.toml /etc/netgrasp.toml
sudo install -m 0644 netgraspd.service /etc/systemd/system/

# Create the schema, then start. Starting would migrate too; doing it first
# means a database problem is reported here rather than in the journal.
sudo -u netgraspd netgraspd migrate --config /etc/netgrasp.toml
sudo systemctl daemon-reload && sudo systemctl enable --now netgraspd
```

The binary is built on Debian 13 (trixie) and is dynamically linked against its
glibc and libpcap, so it wants a comparably recent distribution. On an older
one, run the image instead.

It links libpcap by Debian's soname, `libpcap.so.0.8`, which is what the
`libpcap0.8` package installs. Other distributions ship the same libpcap 1.x
as `libpcap.so.1`, and the binary will not start there (`error while loading
shared libraries: libpcap.so.0.8`). Debian's `libpcap0.8` is itself libpcap
1.10 under the old name, and every `pcap_*` symbol the binary uses is
unversioned and present in libpcap 1.x, so a link to the installed library is
enough. On Fedora and other RPM distributions:

```sh
sudo dnf install libpcap
sudo ln -s libpcap.so.1 /usr/lib64/libpcap.so.0.8 && sudo ldconfig
```

(the library directory is `/usr/lib` on some distributions; `ldconfig -p |
grep libpcap` says where it is). Or run the image, which carries its own. The unit grants the capture capability itself, so
the binary needs no `setcap`; see [Deploying](#deploying).

If you run the Trovato plugin as well, read [Compatibility](#compatibility)
first: the two versions have to pair, and the daemon migrates first.

## Compatibility

`netgraspd` shares its database with
[netgrasp-trovato](https://github.com/jeremyandrews/netgrasp-trovato), the
Trovato plugin that is its web interface. The two are separate releases that
have to agree on one thing, the `ng_` tables.

| netgraspd | netgrasp-trovato | `ng_` schema | Trovato kernel |
|---|---|---|---|
| 1.0.0 | 1.0.0 | version 3 (`V3__enrichment_location_people.sql`) | 0.102.0 or a later 0.x |

**The rule.** A daemon and a plugin pair when they are built for the same `ng_`
schema version, which is the highest migration under `migrations/` here.
This repository owns that schema and its migrations are the canonical DDL; the
plugin carries the tables it reads twice, as a test fixture reproducing this
repository's DDL and as its own guarded migration, and its CI checks the
migration against the fixture column by column. The daemon checks the other
side at startup, refusing to run on tables whose columns differ from what it
was built for, and naming the table and the column.

**A schema change is a paired release.** Any change to an `ng_` table ships as a
new daemon release and a new plugin release together, each naming the other in
this table, and the daemon is upgraded and migrated first. A daemon or plugin
release that does not touch the schema pairs with whatever the other side's
current release is, and says so here.

## Quickstart, from source

```sh
# 1. A database of its own.
createuser netgrasp --pwprompt
createdb netgrasp --owner netgrasp

# 2. Configuration.
cp netgrasp.toml.example netgrasp.toml
$EDITOR netgrasp.toml          # at minimum, database.url

# 3. Build, and grant the one capability capture needs.
cargo build --release
sudo setcap cap_net_raw+ep target/release/netgraspd

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
sudo setcap cap_net_raw+ep /usr/local/bin/netgraspd
```

This has to be reapplied after every upgrade. Under systemd, don't: the shipped
unit grants `CAP_NET_RAW` through `AmbientCapabilities`, which survives an
upgrade and takes every other capability away. See
[Deploying](#deploying).

**macOS.** See [Capturing on macOS](#capturing-on-macos).

**In a container.** Capture needs `--network=host` *and* `--cap-add=NET_RAW`.
Without host networking the container sees the Docker bridge rather than your
LAN, so the daemon starts, captures nothing, and looks exactly like it is
working. See the comments at the top of `Dockerfile` for why the binary is
deliberately not `setcap`-ed in the image.

### Capturing on macOS

macOS has no `setcap`. Capture goes through `/dev/bpf*`, which is `root:wheel`
mode 600 out of the box, so either run the daemon under `sudo` or give a group
read and write on the BPF devices. There are two ways to do that, and both
need an administrator once:

- **Permanently: Wireshark's ChmodBPF.** `brew install --cask
  wireshark-chmodbpf` installs a launch daemon that runs at every boot, creates
  every BPF device the kernel allows (`sysctl debug.bpf_maxdevices`, 256 on
  current macOS), and gives the `access_bpf` group read and write on all of
  them. Check with `id` that you are in `access_bpf` (`sudo dseditgroup -o
  edit -a "$USER" -t user access_bpf` if not), then log out and in again.
- **Until the next reboot: the `admin` group.** An administrator account is
  already in `admin`, so:

  ```sh
  sudo chgrp admin /dev/bpf*
  sudo chmod g+rw /dev/bpf*
  ```

  This only covers the devices that exist when you run it. macOS creates BPF
  devices on demand, one per open capture handle, and a device created later is
  `root:wheel` 600 again. The daemon opens one handle per source per interface
  (42 for six sources on seven interfaces), so on a freshly booted Mac it can
  need more devices than exist; the reboot also undoes the change. Use it to
  try the daemon, and ChmodBPF to keep it.

Either way the daemon then runs as you, with no `sudo`. If it still cannot
capture, it says so on startup and names both routes.

**Which interfaces it captures on.** With `capture.interfaces` empty and no
`-i`, the daemon keeps an interface only when it is up with carrier, not
loopback, has an Ethernet link layer (Wi-Fi counts) and holds an IPv4 address.
A Mac lists dozens of interfaces, and most of them are not the LAN: `awdl0`
and `llw0` (AirDrop and its low-latency link), `utun*` (VPNs, Tailscale, iCloud
Private Relay), `anpi*`, `ap1`, and every unplugged Thunderbolt or Ethernet
port. Each of those used to get a pcap handle per source, and on a `utun` the
ARP filter does not compile, because a tunnel has no Ethernet header. The same
rule applies on Linux, where it leaves out `lo`, `veth*`, a `docker0` with no
containers and `tailscale0`.

An addressed bridge with carrier is kept. On a Mac that runs OrbStack, Docker
Desktop or another hypervisor, that is its host networks (`bridge100` and up);
on Linux it is `cni0` or a `docker0` with containers. Nothing about the
interface tells such a bridge apart from a router's LAN bridge. The machine
running the daemon is still one device however many of these it captures on:
the daemon reads each capture interface's hardware address from the operating
system at startup, records the host under its MAC on the interface its default
route leaves by, and does not turn its own frames on the other interfaces into
devices. The VMs and containers behind a bridge are devices of their own. On a
Mac where the operating system withholds interface hardware addresses from the
user running the daemon (it reports `02:00:00:00:00:00` for every interface;
`ifconfig` shows the same), the daemon cannot tell which MACs are its own, says
so in a warning at startup, and records the host once per interface as before. If
an earlier version already recorded the Mac's bridge addresses as devices,
those rows are left alone and go offline like any silent device. If you do not
want the bridges at all, name your LAN interface:

```sh
netgraspd run -i en1                # or en0; `route -n get default` says which
```

or set `capture.interfaces = ["en1"]`. An explicit list is used as given, and a
name that does not exist is an error. Start with `--log info,netgraspd::capture=debug`
to see why each interface was left out.

**Resident memory.** `netgraspd stats` prints "resident memory unavailable on
this platform" on macOS. The daemon reads its own resident size from
`/proc/self/status`, which only Linux has, and the macOS equivalent is a libc
call that the crate's `#![forbid(unsafe_code)]` rules out. Measure it from
outside: `ps -o rss= -p $(pgrep netgraspd)`.

**Not in a container.** No container runtime on macOS can capture the Mac's
own network. Docker Desktop, OrbStack, Colima, Podman and Apple's `container`
all run Linux in a virtual machine, so `--network=host` is the VM's network: the
daemon would start, capture the VM's virtual segment, and look as if it worked.
On a Mac, run the binary.

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
fail much later as a broken device page. Three checks close that:

- **Before migrating**, the daemon looks for `ng_` tables it did not create. If
  the plugin got there first, `refinery_schema_history` records no applied
  migration, and the daemon stops with a message telling you how to reconcile
  rather than failing with `relation "ng_devices" already exists`. Nothing is
  adopted and nothing is dropped: adopting types nobody checked is worse than
  stopping, and dropping somebody's data to fix a startup message is worse than
  either. The `DROP TABLE` the message suggests is read out of the database, so
  it names the `ng_` tables that are really there, including the ones only the
  plugin creates.
- **After migrating**, a preflight compares every `ng_` table against what this
  build expects and refuses to start on a divergence.
- **Before reading**, `devices`, `events`, `people`, `stats` and `maintain` run
  both of those plus a migration-version check. None of them migrate, so an
  empty, an under-migrated or a plugin-built database used to answer them with a
  bare `relation "ng_location_history" does not exist`.

Every one of those checks reads `pg_catalog` and never `information_schema`,
because `information_schema` lists only what the *connecting role* holds a
privilege on. Where the plugin creates the tables as one role and the daemon
connects as another, asking `information_schema` is asking a different question
and getting a confidently wrong answer to it.

So the order is: **migrate with `netgraspd` against an empty database, then
point the plugin at it.** `netgraspd migrate` is the command for it; starting
the daemon does the same thing on its way up. `docker-compose.yml` runs
`migrate` as a one-shot service everything else waits on, which is what makes
the ordering a fact rather than a hope.

Who owns which column:

| Table | Daemon writes | Plugin writes |
|---|---|---|
| `ng_devices` | identity, state, addresses, location | `display_name`, `notes`, `hidden`, `notify`, `owner_item_id`, `trovato_item_id` |
| `ng_people` | `state`, `current_location`, `last_arrived_at`, `last_departed_at` | `item_id`, `name`, `notes`, `notify_arrive`, `notify_depart` |
| `ng_notify_requests` | `handled_at`, `outcome` | inserts the row (`requested_by`, `requested_at`) |
| everything else | all of it | nothing |

Ownership runs in both directions, on two different clocks. The daemon writes
its columns as things happen and sets `sync_state = 'dirty'` for the plugin's
cron sweep to collect. The plugin writes the user's columns whenever somebody
saves a page, and the daemon reads them back every `state.reconcile_interval`
(ten seconds by default), so renaming a device, muting it or assigning it to
somebody takes effect on a running daemon rather than at the next restart. The
read is one statement over `ng_devices` and one over `ng_people`, it names only
the columns above, and it never writes.

**What `hidden` does, exactly:** it hides the device from the Trovato listings
and nothing else. A hidden device is still captured, still recorded, still
produces presence sessions, and still notifies. `notify` is the flag that
decides whether you hear it come and go, and it starts off. The two are separate on purpose: a checkbox labelled "hide"
that also stopped alerts would be a blind spot in a security tool created by
somebody tidying up a dashboard.

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
netgraspd migrate                  # apply pending migrations, check, exit
netgraspd maintain                 # run the nightly jobs now
netgraspd maintain --dry-run       # ...and report what they would do
netgraspd update-fingerprints URL  # refresh the DHCP fingerprint table
netgraspd export DIR               # write a trip bundle; see below
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

Every subcommand logs which file it read and which database that resolved to,
with the password redacted, before it connects to anything. When no file is
found it says so as a **warning**, because falling back to the compiled
`database.url` is how `netgraspd stats` reports confidently on a database the
daemon is not writing to:

```
 INFO configuration read from file path=netgrasp.toml
 INFO effective database url=postgres://netgrasp:***@localhost:5432/netgrasp
```

```
 WARN no configuration file found; every setting not given as a flag or a NETGRASP_ variable is a compiled default, database.url included looked_for=netgrasp.toml
```

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
  memory, per-source capture rates, enricher poll and failure counts, and the
  [visibility report](#running-on-a-network-you-do-not-own): per interface and
  source, frames, distinct senders and listening time, the gateway belief, and
  a verdict. `stats` is
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

That is Linux, where a capture handle's ring buffer is mapped into the process.
On macOS the BPF buffer stays in the kernel, so resident size barely moves with
the handle count: measured with `ps` on a Mac Studio, 115 handles (six sources
on twenty-one interfaces, under the previous default selection) held 23.8 MB and 42 handles
held 21.7 MB. `stats` cannot report it there; see
[Capturing on macOS](#capturing-on-macos).

## Running on a network you do not own

A hotel, a conference, a friend's flat: a few hours on a network with no
controller of yours on it, hundreds of strangers' devices, and quite possibly
wireless client isolation hiding every one of them. netgraspd still never
sends a packet there. What changes is the configuration, what you read, and
what you take home.

**The profile.** [`netgrasp.foreign.toml.example`](netgrasp.foreign.toml.example)
is an ordinary configuration file, not a mode: notifications off (every
analyzer fires on an unknown network and the alerts are noise; the events are
still recorded), enrichment off, reverse DNS off, all six sources on, one day of
retention, the unknown-device sample on, and its own database, never the home
one. Its status file and sample are relative paths, so they land where you run
it and an ordinary user can write them; run every command from one directory.

```sh
createdb netgrasp_trip --owner netgrasp     # once, or CREATE DATABASE in psql
cp netgrasp.foreign.toml.example trip.toml
netgraspd --config trip.toml migrate
netgraspd --config trip.toml run -i en0     # `route -n get default` names it
netgraspd --config trip.toml stats          # from another terminal, any time
netgraspd --config trip.toml export trip-bundle
```

Name the interface. Left to the default selection, a Mac running OrbStack,
Docker Desktop or another hypervisor keeps its bridges too, and they are not
the network you came to look at.

**The visibility report** is the first thing to read. `netgraspd stats` prints,
per interface, how long it has been listening, how many frames arrived and from
how many distinct senders, the same per source, and one plain verdict:

```
Visibility
  gateway 10.20.0.1 (from route) at 00:11:22:33:44:01 (from inferred)
  en0: listening 10m 0s, 40 frames from 2 senders
    arp          40 frames  2 senders
    capture is working: 1 sender seen (the gateway), consistent with client isolation
```

How to read it:

- *capture is working: N senders seen besides this host* is an ordinary shared
  segment.
- *1 sender seen (the gateway), consistent with client isolation* is what an
  isolated guest network looks like: the access point forwards the gateway's
  broadcasts and nobody else's. Capture is fine; the network is hiding its
  clients from you, and from everyone else. That is the honest answer, and
  netgraspd will not probe to second-guess it.
- *only this host's own frames arrive* means capture works (libpcap hands a
  host its own broadcasts back) but nothing else reaches it, not even the
  gateway: isolation that hides the gateway too, or an empty segment.
- *nothing received on en0 in 10m: capture may be broken* means not even this
  host's own frames arrived. Check permissions and the interface name. Under two
  minutes it says it is too early to say instead.
- *capture failed on X* means every capture thread there failed; the reason is
  printed beside it.

Frames are counted as the BPF filter delivers them, before any parser looks at
them. The distinct sender count is bounded: each interface (and each source on
it) remembers at most 4096 addresses, about 100 KiB, and beyond that reports
"at least 4096". The gateway line says where the belief came from: `route`
(this host's routing table), `dhcp`, `configured` or `inferred`.

**The unknown-device sample** keeps the first few frames from each device the
identifier could not name (no name from mDNS, DHCP, NetBIOS, SSDP, reverse DNS
or a person; a vendor guess or a bare MAC does not count) in one pcap file, so
they can be studied afterwards. It is off by default and on in the profile:

```toml
[capture.unknown_sample]
enabled = true
path = "netgraspd-trip/unknown-sample.pcap"   # relative to where you run it
frames_per_device = 5
max_devices = 200
max_bytes = 10485760                          # the header included
settle = "10m"
```

The frames are **broadcast and multicast only**: a frame is kept only when it
is addressed to a group. The filters alone would not guarantee that, because
non-promiscuous capture also delivers frames unicast to the capture host
itself (on the run that found this, 128 of 150 sampled frames were the
gateway's unicast ARP to the Mac); those are this host's own conversations and
are never kept.

A device's frames are held for `settle` (ten minutes) to give it the chance to
be named, and dropped if it is. Naming is slower than it looks: on a real LAN,
mDNS and NetBIOS names arrived four to seven minutes after a device was first
seen. A device already named is never held at all, and the capture host's own
frames are never kept. When the daemon stops, frames still held are decided
on what is known at that moment. Each bound stops something and is logged once:
`frames_per_device` stops that device, `max_devices` admits no new device, and
`max_bytes` stops the file. An existing sample at the path is appended to, so a
restart keeps what came before. `stats` shows how far it has got. Open it in
Wireshark or `tcpdump -r`.

**The export.** `netgraspd export DIR` writes a bundle that needs no database
to read: `SUMMARY.md` for a person, and beside it `devices.json` (every device,
what named it and what typed it, and every signal behind it), `events.json`
(every event still in the database), `visibility.json` (the report and its
verdicts), `config.json` (the configuration with every password, token, topic
and API key replaced by `***`) and `unknown-sample.pcap` when there is one. It
refuses a directory that already holds anything.

**Leaving nothing behind.** Stop the daemon, export, then `dropdb
netgrasp_trip` and delete the run directory. Nothing else was written.

**Two honest ways to run it away from home:**

- **Natively on macOS**, as yourself, once BPF access is set up; see
  [Capturing on macOS](#capturing-on-macos). No container runtime on a Mac
  can capture the Mac's own network.
- **On a Linux host, from the image**, with host networking and the one
  capability, the trip directory mounted as the working directory so the
  relative paths land in it. The profile and `export` are newer than 1.0.0, so
  use an image built from this repository (`docker build -t netgraspd .`, as in
  [Docker](#docker)) until the next release:

  ```sh
  mkdir trip && cd trip
  docker run --rm --entrypoint cat netgraspd \
      /usr/share/netgraspd/netgrasp.foreign.toml.example > trip.toml
  $EDITOR trip.toml              # database.url, for the database you brought
  docker run --rm -it --network=host --cap-drop=ALL --cap-add=NET_RAW --user root \
      -v "$PWD:/trip" -w /trip netgraspd --config trip.toml run -i wlan0 --no-table
  docker run --rm --network=host -v "$PWD:/trip" -w /trip --user root \
      netgraspd --config trip.toml export bundle
  ```

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
# database.url comes from the mounted file.
docker run -d --name netgraspd \
    --network=host --cap-drop=ALL --cap-add=NET_RAW --user root \
    -v /etc/netgrasp.toml:/etc/netgrasp.toml:ro \
    -v netgraspd-state:/var/lib/netgraspd \
    netgraspd run --config /etc/netgrasp.toml --no-table

# Everything else needs no capability, and runs as the image's unprivileged
# user. It still needs the same configuration, the same network to reach a
# database on the host's loopback, and the state volume the status file is in.
docker run --rm --network=host \
    -v /etc/netgrasp.toml:/etc/netgrasp.toml:ro \
    -v netgraspd-state:/var/lib/netgraspd \
    netgraspd --config /etc/netgrasp.toml stats
```

An environment variable overrides the file: `-e
NETGRASP_DATABASE__URL=…` would replace the mounted `database.url`, credentials
and all. Use one or the other, not both.

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

### Standalone binaries

Every release attaches both, named `netgraspd-<version>-x86_64-unknown-linux-gnu`
and `netgraspd-<version>-aarch64-unknown-linux-gnu`, with a `SHA256SUMS`; see
[Install](#install). The release workflow pushes each platform's image first and
extracts the binary from the pushed image, so the file on the Release is the
binary inside the image, not a second build of it.

CI does the same on every push without publishing: it builds the image for
`linux/amd64` and `linux/arm64`, extracts the binary from each, asserts with
`file` that it really is for the architecture it claims, and uploads both as
workflow artifacts.

The container build *is* the cross-compilation story here. A separate
[`cross`](https://github.com/cross-rs/cross) job was tried and removed: its
stock image for aarch64 is Ubuntu 16.04 and cannot install libpcap for the
foreign architecture, so the build failed before it reached any Rust. The
container build produces the same binary on a current base, and it is the one
that actually ships in the image.

To build one locally, for the Raspberry Pi target:

```sh
docker build --platform linux/arm64 -t netgraspd:arm64 .
id=$(docker create --platform linux/arm64 netgraspd:arm64)
docker cp "$id:/usr/local/bin/netgraspd" ./netgraspd-aarch64
docker rm "$id"
```

Note that the binary is dynamically linked against the image's libpcap and
glibc, so it wants a comparably recent distribution. Run the image itself if
that is inconvenient.

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

### Whose name is it

A name arriving in an mDNS response is evidence about **whoever holds the
address the record names**, not about whoever transmitted the frame. The two are
routinely different: a Bonjour Sleep Proxy answers on behalf of machines that are
asleep, so one phone's frames carry the names and services of every host it is
covering. Reading them as the phone's gave one iPhone six other machines' names
on a real network, and made one name the answer for six different MACs.

So each name is resolved to an address before it is attributed. An A or AAAA
record names its address directly; an instance name reaches one through its SRV
target. Then:

- the address is the sender's, whether from ARP, from DHCP or from the frame's
  own source address, and the name is the sender's;
- the address belongs to another known device, and the name is *that* device's,
  which is how a sleep proxy's answer ends up naming the sleeper;
- the address belongs to nobody known, and the name is kept as a count rather
  than guessed at. `netgraspd stats` reports the running total.

A record the message tied to no address at all still falls back to the sender,
because announcing a service without repeating your own address record is
ordinary and nothing contradicts it. The exception is a frame that has already
proved it answers for somebody else, which forfeits that assumption for all of
its unqualified records.

### Renaming, and why it waits

A name that wins on **rank** is adopted immediately: mDNS arriving on a device
known only by its vendor is a straight promotion.

A name of **equal** rank is held for five minutes before it is adopted. Two mDNS
names of the same weight take turns winning the scorer's same-kind tie-break as
consecutive frames reorder the signal list, and adopting each turn produced 385
`name_updated` events in thirty minutes on a real network. A candidate that
loses even once starts the clock again, so an alternating pair never settles and
never emits. A device somebody genuinely renamed settles once and emits one
event. Nothing is lost by waiting: the name is stored as a signal the moment it
arrives, and only the display identity and its event are held back.

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

What reaches your phone, once the learning window is over:

| Event | Delivered |
|---|---|
| `new_device` | always, whatever the device's `notify` says: nobody has chosen anything about a device that has only just appeared |
| `returned`, `went_offline` | only for a device whose `notify` a person turned on in Trovato; it starts off |
| `person_arrived`, `person_departed` | when the person's `notify_arrive` or `notify_depart` is on; they start off |
| security events | always, under `[security.notifications]` (below) |
| `ip_changed`, `name_updated`, `device_location_changed`, `person_location_changed` | never |

Everything is recorded in `ng_events` either way. `notify.event_types` is a
filter on top of this, never a way round it: listing `ip_changed` there does not
make it deliver, and the default, `["new_device", "returned", "went_offline"]`,
lets a device you chose be heard both coming and going.

All rate limiting lives in the dispatcher, not in any notifier:

- per-device debounce, five minutes by default;
- batching, so ten or more devices appearing inside a minute collapse into one
  summary rather than a storm (this is what makes a router reboot one message);
- quiet hours, evaluated in local time;
- a per-device `notify` toggle you set from Trovato, off until you turn it on.

The batch window costs up to `notify.batch_window` of latency on every
notification. Set `notify.batch_threshold = 0` to turn batching off if you would
rather have them instantly.

Two categories skip the `notify.event_types` allowlist because they are governed
elsewhere: security events by `[security.notifications]`, and person events by
`notify_arrive` and `notify_depart` on the person row. Requiring them in two
places would make a silent misconfiguration look like a working setup.

Arriving and leaving are one sentence each, with the time on the local clock:

- `Jamie is home: Jamie's iPhone joined at 18:42`
- `Jamie left: last seen 07:55`

They use the person's name and the device's, never a pronoun. A departure gives
the time the device was last heard from, not the time the offline timeout
declared it gone.

**What the web side can see.** The plugin cannot read this file and has no
outbound HTTP, so two tables carry what it needs, and neither ever holds the
topic, the server or the token:

- `ng_notify_status`, one row: `notify_configured` (a notifier is built and
  `notify.enabled` is on), `notify_backend` (`ntfy`), and `last_delivery_ok` and
  `last_delivery_at` for the most recent attempt, an alert or a test.
- `ng_notify_requests`: the plugin inserts a row to ask for a test alert. Every
  `state.reconcile_interval` the daemon sends one test for however many rows are
  waiting ("Netgrasp test alert": "Alerts from netgraspd reach this device. Sent
  at 18:43.") and marks each one handled with an `outcome` of `sent`, `failed`
  or `not_configured`. The outcome is a word and never the transport's error,
  because that error names the URL and the URL contains the topic.

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

The gateway is worked out without asking, because several analyzers treat it
differently. `security.gateway_ip` wins if set. Otherwise the daemon reads its
own host's default route at startup, when that route leaves by a captured
interface, and logs `gateway belief at startup` with the address and where it
came from. Failing that, DHCP option 3 states it outright, and failing that the
address the most *distinct* MACs ARP for is the gateway. Once known, it is not given up to
evidence that is no stronger, which is what stops an attacker forging one ARP
reply to become the gateway and silence the detector that was watching for
exactly that.

**Proxy ARP by the gateway is not an attack**, and `security.proxy_arp_gateway`
(on by default) says so. A router that routes between VLANs answers ARP for the
far side with its own hardware address, which makes the same address appear at
the router's MAC and at its real owner's. On one real network that accounted for
every single `ip_conflict` and `arp_spoof` alert, across several VLANs. Those
replies are now ignored by both analyzers and the router is never recorded as
holding the address, so the real owner stays the holder and a genuine spoof of
it is still caught. The exemption needs all three of: a reply, from the learned
gateway MAC, for an address that is not the gateway's own. A stranger claiming
the gateway's address is not the gateway and still alerts immediately.

## What has and has not been exercised

Written plainly, because a monitoring tool whose limits you cannot see is worse
than one that has none.

**No real UniFi controller has ever been contacted.** That comes first because
it is the largest gap. The enricher is optional and off by default, and nothing
but the access point and room columns depends on it.

**Exercised against a live network:**

- A home LAN of about 48 devices across several VLANs, on 2026-09-17, for about
  half an hour: the ARP, mDNS, DHCP and SSDP sources on a MacBook's `en0`,
  captured as root, writing to the same database as the Trovato plugin with the
  plugin's AI assistant editing devices while the daemon ran. That run is the
  first joint run of the two, recorded in the plugin repository's
  `docs/JOINT-RUN.md`. It found four daemon defects, all fixed in 0.4.1: mDNS
  names attributed to the wrong device, a name flapping between two candidates,
  the router's proxy ARP read as an attack, and garbled non-ASCII notification
  titles. **The fixes are tested against fixtures built from what that run saw,
  not re-run on that network.**
- Capture on Linux, in a container with `--network=host` and
  `--cap-add=NET_RAW`: all six sources start, the permission path works end to
  end, and devices, presence sessions, events and a security event were produced
  from real traffic. Clean shutdown on SIGTERM was verified there too, which is
  what the systemd unit's `TimeoutStopSec` depends on. That was a container
  host's own segment over a few minutes.
- All six sources on macOS, as an ordinary user, on 2026-11-14: a Mac Studio's
  Wi-Fi interface `en1` on the same home LAN, for fifteen minutes, as `jandrews`
  through group read and write on `/dev/bpf*`, with no `sudo`. The default
  interface selection chose `en1` and six OrbStack host bridges (42 handles);
  every source captured: per second, ARP 1.36, mDNS 8.33, DHCP 0.01, SSDP 0.13,
  NDP 0.12 and NetBIOS 0.05. 52 devices, 24 of them named by mDNS, NetBIOS or
  DHCP. Resident memory 21.2 to 21.7 MB by `ps`, flat after the first minute;
  SIGTERM to exit in 0.13 seconds. Seven of the 52 were the Mac itself, once per
  bridge, and the run reproduced issues #10, #11 and #12 on this network rather
  than finding anything specific to macOS.

**Exercised against a real database:** the schema, every migration, the rollup,
the retention, the location history invariants, the people state machine and the
plugin contract. Postgres 17.10 locally and Postgres 17 in CI; the V3 generated
columns were verified on both 16.13 and 17.10.

**Exercised against fixtures or a mock:** every packet parser (recorded `.bin`
frames), the six analyzers, and the whole UniFi enricher. The UniFi tests drive
real HTTP over a real socket against a mock controller, including an expired
session mid-poll and an unreachable controller.

**Not exercised at all:**

- A real UniFi controller, so the exact JSON shape of your firmware is a
  guess informed by published responses rather than something that has been
  seen. The decoder ignores unknown fields and tolerates missing ones, which is
  the best that can be done without one.
- An unattended run on a real network: no week-long soak, no Raspberry Pi left
  running, no nightly maintenance fired on real data. The aarch64 image is built
  and runs; nothing has been left on a Pi.
- The NDP and NetBIOS sources on any network but the one above, for longer than
  fifteen minutes.
- Months of real elapsed time. The rollup evidence is a synthetic six-month
  dataset compacted in one run, not six months of a daemon running.
- The release artifacts themselves until the first tag: the binary downloaded
  from a Release and run under the shipped systemd unit, and the image pulled
  from the registry rather than built locally.

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
