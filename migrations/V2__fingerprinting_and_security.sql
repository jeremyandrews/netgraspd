-- Netgrasp daemon schema, milestone 2: full fingerprinting and the security
-- analyzers.
--
-- Additive only. Every column milestone 1 created keeps its name, its type and
-- its meaning, because the Trovato plugin reads these tables as a contract and
-- a destructive ALTER here is a broken plugin there.
--
-- ng_events needs no change at all: details is jsonb, so the six new security
-- event types carry their evidence without a column each. That was the point of
-- making it jsonb in V1.

-- How much to trust ng_devices.device_type. The classifier ranks its evidence
-- by how hard it is to be wrong about, so this distinguishes "it advertises
-- _ipp._tcp" from "its chip vendor mostly makes printers".
ALTER TABLE ng_devices ADD COLUMN device_type_confidence REAL;

COMMENT ON COLUMN ng_devices.device_type_confidence IS
    'Daemon-owned. Confidence in device_type, 0.0 to 1.0. A Router Advertisement '
    'scores 0.99; an OUI vendor guess scores 0.4.';

-- The current IPv6 address, added when the NDP source landed.
--
-- Deliberately separate from last_ip rather than replacing it. last_ip stays
-- IPv4 because it drives ip_changed, and RFC 4941 privacy addresses rotate as
-- often as daily; a single current-address column would emit a meaningless
-- ip_changed event per device per day. This column is written on flush, never
-- generates an event, and prefers a global address over the link-local one every
-- device always has.
ALTER TABLE ng_devices ADD COLUMN last_ipv6 TEXT;

COMMENT ON COLUMN ng_devices.last_ipv6 IS
    'Daemon-owned. Current IPv6 address, global preferred over link-local. Never '
    'raises ip_changed: privacy-extension rotation would make that pure noise.';

-- The plugin will facet the device list by type, and most rows have one.
CREATE INDEX ng_devices_device_type_idx ON ng_devices (device_type)
    WHERE device_type IS NOT NULL;

-- The security feed is a small slice of a large table, read newest first.
-- Partial rather than a plain index on event_type, because security events are
-- a few percent of the rows and the ordinary lifecycle events already have
-- ng_events_time_idx.
CREATE INDEX ng_events_security_idx ON ng_events (event_type, "timestamp" DESC)
    WHERE event_type IN (
        'arp_scan', 'arp_spoof', 'rogue_dhcp',
        'identity_change', 'ip_conflict', 'gratuitous_arp'
    );
