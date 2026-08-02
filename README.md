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

Milestone 1: ARP and mDNS capture, the device state machine, identity
resolution from OUI, mDNS and reverse DNS, learning mode, the event bus, an
ntfy.sh notifier and the CLI. See `ARCHITECTURE.md` for the design record and
for where the deferred work attaches.

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

| Signal | Weight | Status |
|---|---|---|
| name you typed in Trovato | absolute | honoured; the daemon never overwrites it |
| mDNS instance name | 0.9 | implemented |
| DHCP hostname | 0.8 | milestone 2 |
| reverse DNS | 0.7 | implemented, opt-in |
| NetBIOS name | 0.6 | milestone 2 |
| SSDP friendly name | 0.5 | milestone 2 |
| vendor plus device type | 0.3 | vendor implemented |
| bare MAC | 0.1 | always available |

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

## Licence

MIT.
