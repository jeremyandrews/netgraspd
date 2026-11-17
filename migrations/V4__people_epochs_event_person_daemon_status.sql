-- Netgrasp daemon schema, V4: what the web side had to reconstruct, kept true
-- by the daemon instead.
--
-- Additive only. Nothing V1 to V3 created is renamed, dropped or retyped: the
-- Trovato plugin's migrations and its daemon_schema.sql fixture read those
-- tables, and an install whose plugin has not adopted anything below must keep
-- working exactly as it did.

-- ---------------------------------------------------------------------------
-- ng_people: epoch twins
-- ---------------------------------------------------------------------------
-- V3 gave every timestamptz the plugin reads a generated bigint twin, because
-- the kernel's db host decodes a timestamptz as null, and skipped this table.
-- The plugin's ng_people_presence view computed them instead. Same expression
-- as every other twin; generated and stored, so existing rows are filled as the
-- column is added and nothing can write one out of step with its source.
ALTER TABLE ng_people
    ADD COLUMN last_arrived_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_arrived_at AT TIME ZONE 'UTC'))::bigint) STORED,
    ADD COLUMN last_departed_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_departed_at AT TIME ZONE 'UTC'))::bigint) STORED;

-- ---------------------------------------------------------------------------
-- ng_events.person_item_id
-- ---------------------------------------------------------------------------
-- The person a person event is about (person_arrived, person_departed,
-- person_location_changed), and null on every other event. Daemon owned.
--
-- No foreign key to ng_people, on purpose: an event outlives the person it
-- names. "Arlo left at 08:10" stays true after Arlo's Item is deleted and the
-- plugin drops the mirror row.
ALTER TABLE ng_events ADD COLUMN person_item_id UUID;

-- Backfill from what the daemon has always written into details. A value that
-- is not a UUID is left null rather than cast, because one malformed row must
-- not fail an upgrade.
UPDATE ng_events
   SET person_item_id = (details ->> 'person_item_id')::uuid
 WHERE event_type IN ('person_arrived', 'person_departed', 'person_location_changed')
   AND details ->> 'person_item_id'
       ~* '^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$';

CREATE INDEX ng_events_person_idx ON ng_events (person_item_id, "timestamp" DESC)
    WHERE person_item_id IS NOT NULL;

COMMENT ON COLUMN ng_events.person_item_id IS
    'Daemon-owned. The person a person_* event is about; null on every other '
    'event. Deliberately not a foreign key: an event outlives its person.';

-- ---------------------------------------------------------------------------
-- ng_daemon_status: one row about the daemon itself
-- ---------------------------------------------------------------------------
-- Daemon owned in full, and rewritten on every runtime status tick, so an
-- updated_at that has stopped moving means the daemon has stopped.
--
-- timezone is the one owner of what "today" means. A day boundary is measured
-- as `ts AT TIME ZONE ng_daemon_status.timezone`, never in whatever TimeZone a
-- reading session happens to carry. It is the daemon's `timezone` setting when
-- one is configured (timezone_source = 'config'), and the database's own
-- TimeZone as the daemon's session saw it otherwise ('database').
CREATE TABLE ng_daemon_status (
    id               BIGINT      PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    version          TEXT        NOT NULL,
    timezone         TEXT        NOT NULL,
    timezone_source  TEXT        NOT NULL,
    started_at       TIMESTAMPTZ NOT NULL,
    updated_at       TIMESTAMPTZ NOT NULL,
    started_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (started_at AT TIME ZONE 'UTC'))::bigint) STORED,
    updated_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (updated_at AT TIME ZONE 'UTC'))::bigint) STORED
);

-- ---------------------------------------------------------------------------
-- ng_enrichment_status: one row per enricher the daemon knows
-- ---------------------------------------------------------------------------
-- Why a device has no location (UniFi) or no reverse-DNS name. Daemon owned in
-- full, rewritten on every runtime status tick, and present for an enricher
-- that is not configured too, so "not configured" is a row and not an absence.
--
-- state is one of:
--   not_configured  switched off in the daemon's configuration
--   starting        configured, not asked yet
--   ok              the last attempt succeeded
--   failing         the last attempt failed; last_error says why
-- polls and failures count attempts since the daemon started.
CREATE TABLE ng_enrichment_status (
    enricher              TEXT        PRIMARY KEY,
    configured            BOOLEAN     NOT NULL,
    state                 TEXT        NOT NULL,
    polls                 BIGINT      NOT NULL DEFAULT 0,
    failures              BIGINT      NOT NULL DEFAULT 0,
    last_success_at       TIMESTAMPTZ,
    last_failure_at       TIMESTAMPTZ,
    last_error            TEXT,
    updated_at            TIMESTAMPTZ NOT NULL,
    last_success_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_success_at AT TIME ZONE 'UTC'))::bigint) STORED,
    last_failure_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_failure_at AT TIME ZONE 'UTC'))::bigint) STORED,
    updated_at_epoch      BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (updated_at AT TIME ZONE 'UTC'))::bigint) STORED
);
