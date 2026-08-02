-- Netgrasp daemon schema, milestone 1.
--
-- Every table is prefixed ng_ so that the Trovato plugin can declare exactly
-- these tables in its manifest db_tables allowlist and see nothing else.
--
-- The rule this schema exists to enforce: state changes are stored, raw packet
-- observations are not. There is no observations table and there must never be
-- one. ng_presence holds one row per online session, not one per sighting.
--
-- Addresses are text rather than inet. The values are exchanged with a WASM
-- plugin that has no inet type, they are only ever compared for equality, and
-- text keeps the daemon and the plugin reading the same bytes.

CREATE TABLE ng_devices (
    id                  BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    mac                 TEXT        NOT NULL UNIQUE,

    -- User-owned. The daemon never writes these; the Trovato plugin writes them
    -- back from admin edits. A fixed, disjoint set so daemon and plugin cannot
    -- fight over a field.
    display_name        TEXT,
    notes               TEXT,
    hidden              BOOLEAN     NOT NULL DEFAULT FALSE,
    notify              BOOLEAN     NOT NULL DEFAULT TRUE,

    -- Daemon-owned identity. resolved_name is what the scorer picked from the
    -- signals in ng_device_signals; display_name overrides it for humans.
    resolved_name       TEXT,
    identity_source     TEXT,
    identity_confidence REAL,
    hostname            TEXT,
    mdns_name           TEXT,
    vendor              TEXT,
    device_type         TEXT,
    os_family           TEXT,

    -- Daemon-owned state.
    state               TEXT        NOT NULL DEFAULT 'online',
    last_ip             TEXT,
    last_interface      TEXT,
    first_seen_at       TIMESTAMPTZ NOT NULL,
    last_seen_at        TIMESTAMPTZ NOT NULL,
    baseline            BOOLEAN     NOT NULL DEFAULT FALSE,

    -- Reserved for the enrichment milestone; nothing writes these yet.
    current_ap          TEXT,
    current_location    TEXT,

    -- Contract stubs for the Trovato plugin. The daemon sets sync_state to
    -- 'dirty' on every change it makes; the plugin's cron sweep clears it and
    -- fills trovato_item_id. Nothing in this repo reads either column.
    sync_state          TEXT        NOT NULL DEFAULT 'dirty',
    trovato_item_id     BIGINT
);

COMMENT ON COLUMN ng_devices.display_name IS
    'User-owned. The daemon never writes this column.';
COMMENT ON COLUMN ng_devices.sync_state IS
    'Contract stub for the Trovato plugin: dirty means the plugin should re-sync.';

CREATE INDEX ng_devices_state_idx ON ng_devices (state);
CREATE INDEX ng_devices_last_seen_idx ON ng_devices (last_seen_at DESC);
-- Partial: the sweep only ever asks for dirty rows, and most rows are clean.
CREATE INDEX ng_devices_sync_state_idx ON ng_devices (sync_state)
    WHERE sync_state <> 'clean';

-- Every raw identity signal ever seen, never overwritten, so that a later
-- signal refines the identity rather than replacing it.
CREATE TABLE ng_device_signals (
    id            BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id     BIGINT      NOT NULL REFERENCES ng_devices (id) ON DELETE CASCADE,
    signal_type   TEXT        NOT NULL,
    value         TEXT        NOT NULL,
    first_seen_at TIMESTAMPTZ NOT NULL,
    last_seen_at  TIMESTAMPTZ NOT NULL,
    UNIQUE (device_id, signal_type, value)
);

CREATE INDEX ng_device_signals_device_idx
    ON ng_device_signals (device_id, last_seen_at DESC);

-- One row per online session. Opened when a device becomes online, closed when
-- it goes offline. is_summary and observation_count exist now so that the
-- nightly rollup in the enrichment milestone needs no ALTER.
CREATE TABLE ng_presence (
    id                BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id         BIGINT      NOT NULL REFERENCES ng_devices (id) ON DELETE CASCADE,
    interface         TEXT,
    ip                TEXT,
    started_at        TIMESTAMPTZ NOT NULL,
    ended_at          TIMESTAMPTZ,
    is_summary        BOOLEAN     NOT NULL DEFAULT FALSE,
    observation_count BIGINT      NOT NULL DEFAULT 1
);

CREATE INDEX ng_presence_device_idx ON ng_presence (device_id, started_at DESC);
-- At most one open session per device; the partial unique index is what makes
-- that an invariant rather than a convention.
CREATE UNIQUE INDEX ng_presence_open_idx ON ng_presence (device_id)
    WHERE ended_at IS NULL AND is_summary = FALSE;

-- State changes worth telling somebody about.
CREATE TABLE ng_events (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id  BIGINT      REFERENCES ng_devices (id) ON DELETE SET NULL,
    event_type TEXT        NOT NULL,
    -- Named "timestamp" per the plugin contract. It is a Postgres type name, so
    -- every reference to it must be double-quoted.
    "timestamp" TIMESTAMPTZ NOT NULL,
    details    JSONB       NOT NULL DEFAULT '{}'::jsonb,
    notified   BOOLEAN     NOT NULL DEFAULT FALSE,
    sync_state TEXT        NOT NULL DEFAULT 'dirty'
);

CREATE INDEX ng_events_time_idx ON ng_events ("timestamp" DESC);
CREATE INDEX ng_events_device_idx ON ng_events (device_id, "timestamp" DESC);
CREATE INDEX ng_events_sync_state_idx ON ng_events (sync_state)
    WHERE sync_state <> 'clean';

-- Which addresses a device has held, collapsed to one row per address.
CREATE TABLE ng_ip_history (
    id         BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id  BIGINT      NOT NULL REFERENCES ng_devices (id) ON DELETE CASCADE,
    ip         TEXT        NOT NULL,
    interface  TEXT,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen  TIMESTAMPTZ NOT NULL,
    UNIQUE (device_id, ip)
);

CREATE INDEX ng_ip_history_device_idx ON ng_ip_history (device_id, last_seen DESC);
CREATE INDEX ng_ip_history_ip_idx ON ng_ip_history (ip);
