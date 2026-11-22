# Field log: Netgrasp 1.1.0 on a home LAN

An observe only run of the live Netgrasp 1.1.0 deployment on a real home
network: about 170 devices on one LAN. A collector sampled the deployment
every hour, and a person-free check ran four times a day. The run was planned
for seven days. It was stopped on day 4 by decision, so this log covers the
78 hours that were measured. Nothing was changed on the cluster, the network
or the daemon during the run.

All counts below come from read only `kubectl` calls and read only SQL
(`BEGIN READ ONLY`) against the live database. Device and person identities
are left out on purpose. Devices are described by vendor and class only.

## What ran

| Item | Value |
|---|---|
| netgraspd | 1.1.0, `ghcr.io/jeremyandrews/netgraspd@sha256:0f5578ccab8f44b990a5360652a6c15fb57636b8ca8b04ee5ace400568695123` (also the `migrate` init image) |
| Netgrasp Trovato plugin | 1.1.0, `ghcr.io/jeremyandrews/netgrasp-trovato@sha256:9ec8551200585c5b5e41a9eadfb475131fc7c30c5637b2402b212b7efb5f2a46` |
| Trovato kernel | 0.104.0, `ghcr.io/jeremyandrews/trovato@sha256:ec4bde0e6df6c2c4d1ca4262f376e8c1c6e8426f1e7fe3cada3209fa64d4db30` |
| PostgreSQL | CloudNativePG, `ghcr.io/cloudnative-pg/postgresql@sha256:1ec419e997a8bde5263b6951f4c5ebc4aa2e1937927001f2561025c0a816e174`, behind two PgBouncer poolers |
| Redis | `docker.io/library/redis@sha256:7f7d30b7fdd09467bac58198a1f166dd69789d348d4fe859cccb20e0cf287fbe` |
| Cluster | three node k3s. netgraspd, Trovato and Redis on one node; PostgreSQL and the poolers on the other two |
| Capture | host network, interface `end0`, ARP and mDNS. At t0: 2.13 million frames from 99 senders in 24 h (ARP 8.1/s, mDNS 16.5/s) |
| Enrichment | UniFi not configured, reverse DNS not configured |
| People | none tracked: no people, no owners, no display names, no places |
| 1.1.0 deployed | 2026-11-18 09:03 Europe/Rome |
| t0 (first sample) | 2026-11-19 09:06 Europe/Rome (Thursday) |
| Last sample | 2026-11-22 15:02 Europe/Rome (Sunday) |
| Planned end | 2026-11-26 09:04 Europe/Rome |

**Epochs.** One. Every image digest and every container restart count was
identical in all 79 samples. No pod was rescheduled or replaced.

**Coverage.** 79 hourly samples over 77.9 hours. No gap between samples was
longer than 60 minutes, so no gap over 90 minutes. The scheduled checks ran
13 times, every six hours from 2026-11-19 09:00 to 2026-11-22 09:00, none
missed.

## Per day

Days are Europe/Rome calendar days. Event counts and would-be alerts come
from `ng_events` for the whole calendar day, except 22 November, which stops
at the last sample (15:02). Resource figures come from the hourly samples, so
19 November covers only 09:06 to 23:02.

### Events and would-be alerts

| Day | Coverage | Devices (total) | Online (min to max) | name_updated | returned | went_offline | ip_changed | gratuitous_arp | arp_scan | other | Total events | 1.1.0 rules | PR 24 rules |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Thu 19 Nov | partial (samples from 09:06; events whole day) | 170 | 67 to 82 | 618 | 71 | 65 | 36 | 53 | 25 | 0 | 868 | 149 | **78** |
| Fri 20 Nov | full | 170 to 171 | 53 to 89 | 366 | 71 | 71 | 63 | 104 | 49 | identity_change 3, new_device 1 | 728 | 228 | **157** |
| Sat 21 Nov | full | 171 | 67 to 87 | 581 | 69 | 70 | 63 | 59 | 46 | 0 | 888 | 174 | **105** |
| Sun 22 Nov | partial (00:00 to 15:02) | 171 | 69 to 85 | 374 | 33 | 40 | 47 | 44 | 25 | 0 | 563 | 102 | **69** (110 a day at that pace) |

No `arp_spoof`, `ip_conflict`, `rogue_dhcp` or person event happened in the
run.

How the two alert columns are counted:

- **1.1.0 rules**: the 1.1.0 default allowlist, `new_device` and `returned`,
  for devices with `notify` on, plus every security event (`arp_scan`,
  `arp_spoof`, `rogue_dhcp`, `identity_change`, `ip_conflict`,
  `gratuitous_arp`), which skip the allowlist. All devices on this install
  had `notify` on, because V1 defaulted it to true.
- **PR 24 rules** (migration V6, merged to `main` but not deployed): security
  always; `new_device` after learning always; `returned`, `went_offline` and
  person events only for devices whose `notify` a person turned on;
  `ip_changed`, `name_updated` and `device_location_changed` never. V6 sets
  every existing `notify` to false, so on this install nothing is chosen and
  the column is security plus `new_device`.
- Both columns are **upper bounds**: they count events, not deliveries, and
  ignore debounce, batching and quiet hours. No notification was actually
  sent in this run.

### Health and resources

| Day | Samples | Restarts | /health OK | /health median, max | Database size at end | Growth |
|---|---|---|---|---|---|---|
| Thu 19 Nov | 15 (partial) | 0 | 15 of 15 | 0.47 s, 0.51 s | 1,244.5 MB | +0.70 MB in 14 h |
| Fri 20 Nov | 24 | 0 | 24 of 24 | 0.15 s, 0.49 s | 1,245.4 MB | +0.88 MB |
| Sat 21 Nov | 24 | 0 | 23 of 24 | 0.09 s, 0.20 s | 1,246.5 MB | +1.05 MB |
| Sun 22 Nov | 16 (partial) | 0 | 16 of 16 | 0.09 s, 0.42 s | 1,247.2 MB | +0.61 MB in 14 h |

MB here is 10^6 bytes. Over the whole run the database grew from
1,243,790,359 to 1,247,198,231 bytes: 3.4 MB in 77.9 hours, about **1.05 MB
a day**. `ng_events` accounted for 1.0 MB of it. At that rate the 90 day
retention window holds about 95 MB of 1.1.0 era events, against the 1.2 GB
the pre-1.1.0 event storm left behind.

CPU (millicores) and memory (MiB), min / median / max, from metrics-server:

| Container | Thu 19 CPU | Thu 19 mem | Fri 20 CPU | Fri 20 mem | Sat 21 CPU | Sat 21 mem | Sun 22 CPU | Sun 22 mem |
|---|---|---|---|---|---|---|---|---|
| netgraspd | 6/11/19 | 15/18/23 | 6/12/22 | 17/21/24 | 8/10/16 | 19/22/27 | 6/13/20 | 19/22/25 |
| trovato | 1/2/4 | 139/142/153 | 1/1/4 | 141/142/147 | 1/1/3 | 142/143/146 | 1/1/5 | 143/143/149 |
| trovato cron | 0/1/1 | 0/0/3 | 0/0/1 | 0/0/2 | 0/0/1 | 0/0/1 | 0/0/1 | 0/0/2 |
| redis | 18/18/19 | 9/11/14 | 14/18/19 | 7/10/14 | 17/18/18 | 7/8/12 | 18/18/19 | 7/10/12 |
| postgres | 11/32/74 | 1198/1249/1345 | 9/34/65 | 1188/1225/1326 | 11/42/82 | 1194/1229/1323 | 11/36/74 | 1194/1230/1320 |
| pgbouncer (both pods) | 1/3/5 | 25/69/71 | 1/2/8 | 24/69/70 | 1/3/6 | 26/69/73 | 1/2/6 | 25/69/70 |

Peak memory over the run: netgraspd 27 MiB, trovato 153 MiB, redis 14 MiB,
postgres 1,345 MiB, pgbouncer 73 MiB. netgraspd memory drifted from a median
of 18 MiB on day 1 to 22 MiB on days 3 and 4 and then held; that is too short
to call a leak or rule one out.

**Restarts.** None in the run, in any container. The Trovato container
carried 4 restarts from before t0 (the last on 2026-11-18 at 22:09, a kubelet
kill after liveness probe timeouts while cron requests took 6 to 11 s). One
pooler pod carried 2 restarts from 16 days earlier.

**Availability.** `/health` answered 200 in 78 of 79 samples (98.7 %). The
one miss, 2026-11-21 08:02, got no HTTP response at all in 0.10 s while the
same sample's `kubectl` and SQL reads worked, and a retry a minute later
answered in 0.08 s. The cause is unknown (ingress or the sampling machine);
it is counted as a miss.

## Inventory accuracy

**Not measured.** The plan was to compare the device list with the UniFi
controller or, without UniFi credentials, with the ARP cache of a machine on
the LAN. No UniFi credentials were available to the run, and the sampling
machine's ARP cache was empty at every attempt (four tries, one a day), so no
comparison was possible.

What was observed: the inventory grew from 170 to 171 devices. The one new
device, an Apple media player, was first seen on 20 November at 12:47 and
raised exactly one `new_device` event. Online counts ranged from 53 (night)
to 89 (afternoon); idle devices 7 to 25.

## Presence accuracy and flap rate

With no people tracked, there was no person home and away to check against.
Device presence was checked for flaps: a `went_offline` followed by
`returned` (or the reverse) for the same device within 10 minutes.

| Day | Devices that changed state | Transitions | Flaps | Flapping devices | Flap share |
|---|---|---|---|---|---|
| Thu 19 Nov | 20 | 136 | 44 | 8 | 32 % |
| Fri 20 Nov | 36 | 142 | 25 | 8 | 18 % |
| Sat 21 Nov | 23 | 139 | 2 | 1 | 1 % |
| Sun 22 Nov (to 15:02) | 20 | 73 | 1 | 1 | 1 % |
| t0 to last sample | 37 | 432 | 57 | 8 | 13 % |

Every flap was offline then back. Two device groups caused them:

- **Seven Ubiquiti network devices** went offline together at the same second
  every four hours and returned 2 to 6 minutes later, five or six flaps each
  a day. Their announcement cadence sits just over the effective offline
  timeout. On 20 November from 15:25 the cycle changed shape: they went
  offline at 18:25 and stayed offline past the next check, and the flaps
  stopped for the rest of the run. Filed as netgraspd #26.
- **One IoT Wi-Fi module** (Shanghai High-Flying) went offline and back
  within 2 to 16 s about four times a day. Same cause.

Whether a device shown online was really on could not be tested without an
independent inventory (see above).

## Alert volume against the 100 a day target

| Day | 1.1.0 rules | PR 24 rules | Of which security | Target |
|---|---|---|---|---|
| Thu 19 Nov | 149 | 78 | 78 | 100 |
| Fri 20 Nov | 228 | 157 | 156 | 100 |
| Sat 21 Nov | 174 | 105 | 105 | 100 |
| Sun 22 Nov (15 h) | 102 | 69 (110 a day pace) | 69 | 100 |

- Under **1.1.0's rules** the target is missed every day, by 1.5 to 2.3
  times. `returned` alone adds about 70 a day, many of them from the flapping
  devices described above.
- Under **PR 24's rules** the two full days averaged **131 a day**, missed on
  three of four days. Every one of those would-be alerts is a security event
  except the single `new_device`.
- The security events are almost all from Apple computers and Apple TVs:
  `gratuitous_arp` 44 to 104 a day from four Apple devices and one Espressif
  module, `arp_scan` 25 to 49 a day from six Apple machines (ten distinct
  targets in 30 s, urgent priority). This matches macOS sleep proxy and wake
  behaviour, so they look like false positives. Filed as netgraspd #28.
  Without `gratuitous_arp` and `arp_scan`, PR 24's rules would give 0 to 4
  alerts a day on this network.
- For comparison, a theoretical 1.1.0 install with every event type allowed
  for every device would alert on every event: 563 to 888 a day.
- `name_updated` is the largest event type (366 to 618 a day) and is never
  alerted under either rule set. It comes from about 38 devices whose mDNS
  name alternates between two to four values every few minutes (a networked
  receiver, Bluesound players, Raspberry Pis). Filed as netgraspd #27.

PR 30 (alert classes and pooling per source) merged to `main` after PR 24 and
would pool repeat security events per source. Its effect was not measured.

## Nightly maintenance

Nightly maintenance ran at 04:30 every night it was checked, took 0.3 to 0.4 s,
and did what it should:

| Night | Duration | Presence rows rolled up | Summaries written | Events pruned | Vacuum |
|---|---|---|---|---|---|
| 19 to 20 Nov | 0.4 s | 87 | 34 | 0 | ran |
| 20 to 21 Nov | 0.3 s | 89 | 33 | 0 | ran |
| 21 to 22 Nov | 0.3 s | 81 | 30 | 0 | ran |

No events were pruned because the oldest event (2026-09-25) was still inside
the 90 day retention window. The newest presence summary day advanced by one
each night. The separate `postgres-dump` CronJob completed each night at 03:30
in 11 to 14 s.

## Assistant accuracy and tokens

Nine questions were asked of the network assistant, three a day on three days,
each day in a new conversation, and checked against SQL run the same minute.
**5 of 9 answers were right.**

| # | Question (paraphrased) | Result | Why wrong |
|---|---|---|---|
| 1 | Devices online now | right | |
| 2 | Devices first seen in the last 24 h | wrong | a device seen 37 h earlier read as "1 day ago" (netgrasp-trovato #32) |
| 3 | `gratuitous_arp` events yesterday | wrong | no tool exposes events: a capability gap |
| 4 | Devices offline now | wrong, off by one | counted by hand from a list truncated at 12 kB (netgrasp-trovato #33) |
| 5 | Most recently first seen device and when | right | the "about an hour ago" qualifier was wrong by an hour (#32) |
| 6 | Devices with an owner | right | |
| 7 | Devices online now | right | |
| 8 | Vendor with the most devices | wrong, 40 for 41 | counted from the truncated list (#33) |
| 9 | Devices idle now | right | after correcting itself |

Latency was 1.7 to 12.5 s a question. Token use was high: the conversation
totals after three questions were 70,329, 58,785 and 61,905 tokens, about
20,000 a question. Two of three conversations passed the site's 60,000 token
cap on the third question. The cause is tool results: a `list_devices` of the
online devices is about 17,000 tokens and is resent every turn.

## Errors in logs

| Container | ERROR lines | WARN lines | What they are |
|---|---|---|---|
| netgraspd | 0 | 397 | every one a `security event` line for `gratuitous_arp` or `arp_scan` |
| trovato | 2,922 | 6,522 | "very slow request" (ERROR) and "slow request" (WARN) from the kernel's query profiler: the `/health` probe at about 270 ms and the 60 s cron POST at 450 to 600 ms, against a low threshold |
| trovato, of the WARN lines above | | 56 | "Database pool utilization at 100%" (54, a pool of 2 or 3 connections), one "failed to get Redis connection" in cron, one "include results truncated" |
| pgbouncer | 0 | 6 | info level records the WARNING match miscounted |
| postgres, redis, cron | 0 | 0 | |

Kubernetes Warning events appeared once: early on 20 November the Trovato
container's liveness and readiness probes timed out (the slowest request in
that hour took 5.0 s), but never three liveness failures in a row, so it was
not restarted. No other Warning events in the run.

netgraspd itself logged no error in 78 hours.

## Issues filed

From the run:

- netgraspd #26: devices that announce every few hours flap offline and back
  each cycle.
- netgraspd #27: a display name flips between a device's own mDNS names every
  few minutes.
- netgraspd #28: Apple computers and Apple TVs raise `arp_scan` and
  `gratuitous_arp` security events every day.
- netgrasp-trovato #32: assistant relative times truncate, so a device first
  seen 37 hours ago reads as within the last day.
- netgrasp-trovato #33: `list_devices` truncates at 12,000 bytes, so on a
  network over about 100 devices the assistant counts from a partial list.

Seen and not filed: no tool for events or security events in the assistant
(question 3); no count by state or offline filter in `list_devices`
(question 4); Trovato's query profiler logs about 120 ERROR and WARN lines an
hour for normal requests; Trovato's database pool sits at 100 % of 2 or 3
connections; Trovato probe timeouts and the pre-run restarts.

## What was not measured, and why

- **Days 5 to 7.** The run was planned for seven days, 2026-11-19 to
  2026-11-26. It was cut on day 4 by decision, not by a failure: the numbers
  had settled, the issues were filed, and the alert rules had changed on
  `main`. A full weekday and weekend cycle was not seen twice.
- **PR 24 and PR 30 live.** PR 24 (alert defaults, migration V6) merged to
  `main` on 2026-11-22 as `1dc0ec6`, and PR 30 (alert classes and pooling) as
  `bba78cc`, but neither is released or deployed. The daemon ran 1.1.0
  throughout; PR 24's numbers here are computed from 1.1.0's events.
- **Real deliveries.** No notification was sent. Alert counts are upper bounds
  from `ng_events`: debounce, batching, quiet hours and pooling were not
  applied.
- **Inventory accuracy.** No UniFi credentials and an empty ARP cache on the
  sampling machine; see above.
- **Person presence.** Nobody is tracked on this install.
- **Enrichment.** UniFi and reverse DNS are not configured.
- **CPU and memory between samples.** One reading an hour; short spikes are
  not in the tables.
