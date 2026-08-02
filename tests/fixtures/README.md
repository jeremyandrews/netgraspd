# Packet fixtures

One raw Ethernet frame per file, no pcap wrapper. Loaded through
`src/capture/fixtures.rs` with `include_bytes!`, so the tests have no
working-directory dependency.

These were assembled byte by byte to the layouts in RFC 826 (ARP), RFC 1035
(DNS) and RFC 6762 (mDNS). They were **not** sniffed from a live network,
because the machine this milestone was built on had no packet-capture
permission. Each file's layout is documented below so a real capture can replace
one without guesswork: dump a frame with `tcpdump -w`, strip the pcap header,
and check the parser still agrees.

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

The gateway and the mDNS responder deliberately share a MAC: it gives the
integration suite a device that is discovered by one protocol and then renamed
and re-addressed by another, which is the `name_updated` and `ip_changed` path.

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
