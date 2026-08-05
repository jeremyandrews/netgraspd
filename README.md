# netgraspd

A passive network device monitor. It watches LAN broadcast and multicast
traffic, works out what each device is by combining signals from several
protocols, tracks a per-device state machine, and alerts you when something
turns up that it has not seen before.

**It never transmits a packet on the segment it is watching.** No scanning, no
pinging, no ARP sweeps, no mDNS queries. It reads what is already on the wire.

## The rule

**State changes are stored, raw packet observations are not.**

The predecessor wrote one row per ARP packet and drowned in its own database.
This one keeps devices in memory, writes a row per *session* and a row per
*state change*, and counts packet volume as an integer on the open session.
There is no observations table and there must never be one; the integration
suite asserts it.

## Status

Milestone 2. Six capture sources (ARP, mDNS, DHCP, SSDP, IPv6 NDP, NetBIOS),
device-type and OS classification from an embedded DHCP fingerprint table plus
every other signal on the wire, and six security analyzers. Milestone 1's device
state machine, identity resolution, learning mode, event bus, ntfy notifier and
CLI are underneath it unchanged.

See `ARCHITECTURE.md` for the design record and for where the remaining work
attaches.

## Building

```
cargo build --release
```

Needs libpcap headers: `libpcap-dev` on Debian and Ubuntu, `libpcap-devel` on
Fedora, already present in the macOS SDK.

## Capturing needs privilege

Packet capture needs raw socket access. Grant it once rather than running the
whole daemon as root:

```
sudo setcap cap_net_raw,cap_net_admin+ep target/release/netgraspd
```

macOS has no `setcap`. Either run under `sudo`, or install Wireshark's ChmodBPF
helper so that members of the `access_bpf` group can open `/dev/bpf*`.

`netgraspd` checks on startup and tells you which of these you need.

## Database

One Postgres database, shared with a Trovato instance if you run one. Every
table is prefixed `ng_`.

```
createuser netgrasp --pwprompt
createdb netgrasp --owner netgrasp
```

Migrations are embedded and run automatically on startup.

## Running

```
netgraspd run                      # watch, with a live device table
netgraspd run --learn              # force a baseline learning window first
netgraspd run -i eth0 -i wlan0     # specific interfaces
netgraspd devices                  # print the device table once
netgraspd devices --state offline  # ...filtered
netgraspd events --limit 50        # recent events
netgraspd events --security        # ...only what the analyzers found
netgraspd update-fingerprints URL  # refresh the DHCP fingerprint table
```

The first run on an empty database spends five minutes learning the network.
Everything works normally during the window and every event is recorded; only
the *notifications* are suppressed, so you do not get a hundred alerts for the
devices that were already there. Devices found during the window are flagged
`baseline`.

## Configuration

`netgrasp.toml` in the working directory, or `--config`. See
`netgrasp.toml.example` for every setting with its default.

Precedence, highest first:

1. Command-line flags.
2. Environment: `NETGRASP_` prefix, `__` between levels, e.g.
   `NETGRASP_DATABASE__URL`, `NETGRASP_STATE__IDLE_TIMEOUT`.
3. `netgrasp.toml`.
4. Compiled defaults.

Durations are written as `30m`, `2h`, `1d`, `90s`, or a bare integer meaning
seconds.

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

## Development

```
cargo test --lib                   # unit tests, no database needed
cargo test                         # everything, needs Postgres
cargo clippy --all-targets -- -D warnings
cargo fmt --all -- --check
```

The integration suite needs a Postgres it can migrate and truncate. Point it
somewhere with `NETGRASP_TEST_DATABASE_URL`; without a reachable database those
tests print why and pass, so a checkout with no Postgres still goes green on
everything else.

Refresh the embedded vendor registry with `scripts/refresh-oui.sh`.

Regenerate the packet fixtures with `cargo run --example build-fixtures`. The
`.bin` files under `tests/fixtures/` are what the parsers actually read; a test
asserts that they still equal what the builders in
`src/capture/fixtures/build.rs` produce, so a builder edit that is not
regenerated fails rather than leaving every parser test quietly green against
stale bytes.

## Licence

MIT.
