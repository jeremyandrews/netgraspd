# Packet fixtures

One raw Ethernet frame per file, no pcap wrapper. Loaded through
`src/capture/fixtures.rs` with `include_bytes!`, so the tests have no
working-directory dependency.

These were **not** sniffed from a live network, because the machine this was
built on had no packet-capture permission. They are synthesised to the on-wire
layouts in the relevant RFCs.

**Two generations, two methods.** The milestone 1 ARP and mDNS frames were
assembled byte by byte and their layouts are documented below, so a real capture
can replace one without guesswork: dump a frame with `tcpdump -w`, strip the pcap
header, and check the parser still agrees.

The milestone 2 frames are built in code instead, by
`src/capture/fixtures/build.rs`, and written out with
`cargo run --example build-fixtures`. Hand-assembly does not survive contact with
DHCP, where the BOOTP header is 236 bytes before the options start, or with
anything carrying a length field that has to agree with its payload. The `.bin`
files are still what the parsers read; a test asserts that each one still equals
what its builder produces, so an edit to a builder that is not regenerated fails
loudly rather than leaving every parser test quietly green against stale bytes.

Between them they cover the details that break naive parsers: 60-byte Ethernet
padding, an 802.1Q tag, a DNS compression pointer inside PTR rdata, the mDNS
cache-flush class bit, an ARP probe with a 0.0.0.0 sender, and an IPv6
link-local source.

## MAC addresses used

| MAC | Registry says | Role |
|---|---|---|
| `3c:22:fb:9a:1b:2c` | Apple, Inc. | a phone |
| `b8:27:eb:44:55:66` | Raspberry Pi Foundation | the gateway, and the mDNS responder |
| `3c:2a:f4:11:22:33` | Brother Industries, LTD. | a printer |
| `00:11:32:aa:bb:cc` | Synology Incorporated | a NAS |
| `b0:a7:37:0a:0b:0c` | Roku, Inc. | a television |

The gateway and the mDNS responder deliberately share a MAC: it gives the
integration suite a device that is discovered by one protocol and then renamed
and re-addressed by another, which is the `name_updated` and `ip_changed` path.

That shared MAC has a second consequence in milestone 2, and it is intentional
too. The same host advertises `_airplay._tcp` over mDNS and sends IPv6 Router
Advertisements, so the classifier reads it as a media player and then as a
router. Higher-rank evidence contradicting lower-rank evidence is exactly what
`identity_change` fires on, so the "healthy network" integration test asserts one
`identity_change` and zero of everything else, rather than silence.

## Files

### `arp_request.bin` (60 bytes)

Broadcast ARP request, the phone asking for the gateway.

```
00  ff ff ff ff ff ff        destination: broadcast
06  3c 22 fb 9a 1b 2c        source: the phone
12  08 06                    EtherType: ARP
14  00 01                    hardware type: Ethernet
16  08 00                    protocol type: IPv4
18  06 04                    hardware length 6, protocol length 4
20  00 01                    opcode: request
22  3c 22 fb 9a 1b 2c        sender hardware address
28  c0 a8 01 28              sender protocol address: 192.168.1.40
32  00 00 00 00 00 00        target hardware address: unknown
38  c0 a8 01 01              target protocol address: 192.168.1.1
42  00 x18                   padding to the 60-byte Ethernet minimum
```

Only the *sender* fields are ever treated as a sighting. The target is the
address being asked about, not a device known to be present.

### `arp_reply.bin` (60 bytes)

Same layout, opcode `00 02`, unicast to the phone, sender
`b8:27:eb:44:55:66` at `192.168.1.1`.

### `arp_gratuitous.bin` (60 bytes)

Opcode `00 01` from the NAS, but sender and target protocol addresses are both
`192.168.1.77`, which makes it an announcement rather than a question.

### `arp_probe.bin` (60 bytes)

Opcode `00 01` from the phone with a sender protocol address of `00 00 00 00`.
The device is present but has no address yet, so the parser reports presence
with `ip: None`. Recording `0.0.0.0` as an address would be wrong.

### `arp_request_vlan.bin` (60 bytes)

`arp_request.bin` with an 802.1Q tag (`81 00 00 64`, VLAN 100) inserted at offset
12. Everything after shifts by four bytes.

### `mdns_response_ipv4.bin` (236 bytes)

Ethernet to `01:00:5e:00:00:fb` / IPv4 `192.168.1.55` to `224.0.0.251` / UDP
5353 to 5353 / DNS response.

| Section | Record |
|---|---|
| answer | `_airplay._tcp.local` PTR, class `0001`, TTL 4500, rdata `"Living Room Apple TV"` then a compression pointer `c0 0c` back to the service name |
| answer | `living-room-apple-tv.local` A, class `8001` (cache-flush set), TTL 120, rdata `192.168.1.55` |
| additional | `Living Room Apple TV._airplay._tcp.local` SRV, class `8001`, port 7000, target `living-room-apple-tv.local` |

Two `MdnsName` signals come out of this, in order: the instance name a human
chose, then the host name the vendor generated. That order is load-bearing, and
the same-kind tie-break in the scorer is what keeps the human's name on top.

### `mdns_response_ipv6.bin` (252 bytes)

Ethernet to `33:33:00:00:00:fb` / IPv6 `fe80::3e2a:f4ff:fe11:2233` to `ff02::fb`
/ UDP 5353. SRV and TXT for `Office Printer._ipp._tcp.local`, no address record.
Exercises the IPv6 path and the "recorded in `ng_ip_history` but does not move
`last_ip`" rule.

### `mdns_query.bin` (88 bytes)

A service-enumeration query for `_services._dns-sd._udp.local`. Proves presence
and names nothing: the meta-service must never be mistaken for an instance name.

## Milestone 2 files

Built by `src/capture/fixtures/build.rs`. Every length field agrees with its
payload; IP and UDP checksums are left zero, which Netgrasp never reads and which
is what an interface doing checksum offload hands over anyway.

### `dhcp_discover.bin` (325 bytes)

The phone, broadcast, `0.0.0.0` to `255.255.255.255`, UDP 68 to 67. Options: 53
(Discover), 12 (`auroras-ipad`), 55 (`1,121,3,6,15,119,252`, the list iOS
actually sends), 60 (`iPhone-iOS17.4`).

`ciaddr` is zero, so the parser must report presence with no address: recording
`0.0.0.0` would be as wrong here as it is for an ARP probe.

### `dhcp_offer.bin` (316 bytes)

The gateway answering, sourced from `192.168.1.1`, UDP 67 to 68. `yiaddr` is
`192.168.1.40`; options 53 (Offer), 54, 51, 1, 3 (`192.168.1.1`) and 6.

Option 3 is what the gateway tracker reads, and the packet being sourced from the
gateway's own address is what names its MAC in the same breath.

### `dhcp_ack.bin` (318 bytes)

The same shape with option 53 = Ack, and it **echoes the client's hostname in
option 12**, exactly as a real server does. That is the trap: attributing it
would name the router after the tablet, so a server message must contribute no
identity signal at all.

### `dhcp_request_overloaded.bin` (289 bytes)

The printer, with option 52 = 1 marking the `file` field as option space and
option 12 (`overflow-host`) living there. A parser that ignores option overload
silently loses every option after the overflow.

### `ssdp_notify.bin` (367 bytes)

The NAS to `239.255.255.250`, `NT: urn:schemas-upnp-org:device:MediaServer:1`,
`NTS: ssdp:alive`, and a `SERVER` header naming Linux. It also carries a
`LOCATION`, which is never fetched.

### `ssdp_msearch.bin` (208 bytes)

The phone searching. Its `ST` names what it *wants*, so it must yield no device
type; its `USER-AGENT` is still the sender naming itself.

### `ssdp_response.bin` (323 bytes)

The television answering, with `X-friendly-name: TGl2aW5nIFJvb20gVFY=`, which is
base64 for `Living Room TV`. This is the whole of the passive friendly-name path.

### `ndp_solicitation.bin` (86 bytes)

The phone at `fe80::3e22:fbff:fe9a:1b2c` asking about `2001:db8::1`, with a
source link-layer address option. The target is the address being asked about and
must never be recorded as a sighting, exactly as for ARP.

### `ndp_advertisement.bin` (86 bytes)

The gateway advertising `2001:db8::1` as its own while sourced from its
link-local address, with a target link-layer address option. Here the target
*is* the advertiser's address, which is the exception worth a test.

### `ndp_router_advertisement.bin` (110 bytes)

The gateway, with a source link-layer option and a prefix information option.
Yields the `ndp_role = router` signal, the least ambiguous device-type evidence
there is.

### `ndp_dad.bin` (78 bytes)

The printer doing Duplicate Address Detection: sourced from `::` and carrying no
source link-layer option, as RFC 4862 requires. Proves presence and names no
address.

### `nbns_registration.bin` (110 bytes)

The NAS claiming `JEREMY-PC` with suffix `0x00`. Flags `0x2910` are opcode 5 with
recursion desired and the broadcast bit set, which is what a Windows machine puts
on the wire.

### `nbns_query.bin` (92 bytes)

The phone asking about `JEREMY-PC`. A query request claims nothing, so it must
yield presence and no name; reading it as the sender's name would label every
machine after whatever it last looked for.

### `nbns_datagram.bin` (133 bytes)

A browser announcement on UDP 138: source name `JEREMY-PC<00>`, destination name
`WORKGROUP<1d>`, then a few bytes of SMB mailslot data. The suffix is what decides
that one is a machine and the other is a workgroup.
