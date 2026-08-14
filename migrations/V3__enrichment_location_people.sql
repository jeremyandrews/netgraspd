-- Netgrasp daemon schema, milestone 3: enrichment, location and people.
--
-- This migration is a contract, not a proposal. The Trovato plugin ships a
-- byte-identical copy of this DDL as a test fixture, runs its real queries
-- against that fixture, and compares its own migration to it column by column.
-- A column that differs by a letter breaks a shipped test in the other repo,
-- and it breaks there rather than here.
--
-- Everything V1 and V2 created keeps its name, its type and its meaning, with
-- one deliberate exception spelled out below.

-- Item join columns. The kernel's item.id is UUID, so these are UUID. Both are
-- user owned: the plugin writes them, the daemon only ever reads them.
-- trovato_item_id is a BIGINT stub today that nothing reads and nothing writes,
-- so it is dropped and re-added at the right type. This is the one deliberate
-- destructive ALTER in the series and it is safe only because the repo is
-- unpushed and no install exists.
ALTER TABLE ng_devices DROP COLUMN trovato_item_id;
ALTER TABLE ng_devices ADD COLUMN trovato_item_id UUID;
ALTER TABLE ng_devices ADD COLUMN owner_item_id UUID;
CREATE INDEX ng_devices_owner_idx ON ng_devices (owner_item_id)
    WHERE owner_item_id IS NOT NULL;

COMMENT ON COLUMN ng_devices.owner_item_id IS
    'User-owned. The person Item that owns this device. The plugin writes it; '
    'the daemon only reads it, and tolerates a value whose ng_people row has '
    'not been mirrored yet.';

-- Epoch companions. The kernel's db host function decodes a fixed list of
-- Postgres types (BOOL, INT2, INT4, INT8, FLOAT4, FLOAT8, UUID, JSON, JSONB)
-- and returns null for anything else, which includes timestamptz. So every
-- timestamptz the plugin reads gets a generated bigint twin. Generated and
-- stored: nothing can write one, and the timestamptz column stays canonical.
-- The AT TIME ZONE 'UTC' form is required, because EXTRACT(EPOCH FROM ts) alone
-- is not immutable and Postgres refuses it in a generated column.
ALTER TABLE ng_devices
    ADD COLUMN first_seen_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (first_seen_at AT TIME ZONE 'UTC'))::bigint) STORED,
    ADD COLUMN last_seen_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_seen_at AT TIME ZONE 'UTC'))::bigint) STORED;
ALTER TABLE ng_presence
    ADD COLUMN started_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (started_at AT TIME ZONE 'UTC'))::bigint) STORED,
    ADD COLUMN ended_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (ended_at AT TIME ZONE 'UTC'))::bigint) STORED;
ALTER TABLE ng_events
    ADD COLUMN timestamp_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM ("timestamp" AT TIME ZONE 'UTC'))::bigint) STORED;
ALTER TABLE ng_ip_history
    ADD COLUMN first_seen_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (first_seen AT TIME ZONE 'UTC'))::bigint) STORED,
    ADD COLUMN last_seen_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_seen AT TIME ZONE 'UTC'))::bigint) STORED;

-- Where a device is, over time. Daemon owned in full.
CREATE TABLE ng_location_history (
    id               BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    device_id        BIGINT      NOT NULL REFERENCES ng_devices (id) ON DELETE CASCADE,
    ap_name          TEXT,
    location         TEXT        NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL,
    ended_at         TIMESTAMPTZ,
    is_summary       BOOLEAN     NOT NULL DEFAULT FALSE,
    started_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (started_at AT TIME ZONE 'UTC'))::bigint) STORED,
    ended_at_epoch   BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (ended_at AT TIME ZONE 'UTC'))::bigint) STORED
);
CREATE INDEX ng_location_history_device_idx
    ON ng_location_history (device_id, started_at DESC);
-- At most one open stay per device, the same invariant ng_presence carries.
CREATE UNIQUE INDEX ng_location_history_open_idx ON ng_location_history (device_id)
    WHERE ended_at IS NULL AND is_summary = FALSE;

-- People. item_id is the person Item the plugin mirrors here; with no plugin
-- installed the daemon generates one from config so the standalone path works.
-- Plugin owned: item_id, name, notes, notify_arrive, notify_depart.
-- Daemon owned: state, current_location, last_arrived_at, last_departed_at.
CREATE TABLE ng_people (
    item_id          UUID PRIMARY KEY,
    name             TEXT    NOT NULL,
    notes            TEXT,
    notify_arrive    BOOLEAN NOT NULL DEFAULT FALSE,
    notify_depart    BOOLEAN NOT NULL DEFAULT FALSE,
    state            TEXT    NOT NULL DEFAULT 'away',
    current_location TEXT,
    last_arrived_at  TIMESTAMPTZ,
    last_departed_at TIMESTAMPTZ
);

COMMENT ON COLUMN ng_people.last_arrived_at IS
    'Daemon-owned. The plugin orders its person listing by this column, so the '
    'daemon writes it on every arrival; a row whose timestamps stay null sorts '
    'to the bottom of a page nobody can fix from the UI.';
