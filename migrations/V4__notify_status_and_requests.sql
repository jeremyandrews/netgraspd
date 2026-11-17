-- Netgrasp daemon schema, V4: whether alerts can reach anybody, and a way to
-- ask the daemon to prove it.
--
-- Additive only. Nothing V1 to V3 created is touched.
--
-- The Trovato plugin cannot read the daemon's configuration and has no
-- outbound HTTP, so the web side could only infer delivery from
-- ng_events.notified and could never send a test. These two tables are the
-- whole interface. Neither ever holds the ntfy topic, the server URL or the
-- token: whoever can read the plugin's database must not learn where alerts go.
--
-- Guarded with IF NOT EXISTS, unlike V1 to V3, and on purpose. The plugin ships
-- a byte-for-byte guarded copy of these two tables so that its Alerts page works
-- on an install with no daemon, and a site that deploys the plugin before
-- upgrading the daemon would otherwise have this migration fail on a table that
-- is already there, exactly as the daemon would have created it. The preflight
-- still compares every column after migrating, so a copy that differs is caught.

-- ---------------------------------------------------------------------------
-- ng_notify_status: one row about delivery
-- ---------------------------------------------------------------------------
-- Daemon owned in full. Written when the notifier task starts and after every
-- delivery attempt.
--
-- notify_configured  a notifier is built and the master switch is on
-- notify_backend     which transport ('ntfy'); null when there is none
-- last_delivery_ok   whether the most recent attempt, alert or test, was
--                    accepted; null when nothing has been attempted yet
-- last_delivery_at   when that attempt was made
CREATE TABLE IF NOT EXISTS ng_notify_status (
    id                     BIGINT      PRIMARY KEY DEFAULT 1 CHECK (id = 1),
    notify_configured      BOOLEAN     NOT NULL,
    notify_backend         TEXT,
    last_delivery_ok       BOOLEAN,
    last_delivery_at       TIMESTAMPTZ,
    updated_at             TIMESTAMPTZ NOT NULL,
    last_delivery_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (last_delivery_at AT TIME ZONE 'UTC'))::bigint) STORED,
    updated_at_epoch       BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (updated_at AT TIME ZONE 'UTC'))::bigint) STORED
);

-- ---------------------------------------------------------------------------
-- ng_notify_requests: "send me a test alert"
-- ---------------------------------------------------------------------------
-- Plugin owned: the row itself, requested_at, requested_by. The plugin inserts
-- and never updates.
-- Daemon owned: handled_at, outcome. The daemon reads unhandled rows on its
-- reconcile tick, sends one test alert for however many are waiting, and marks
-- every one of them handled.
--
-- outcome is one of:
--   sent            a notifier accepted the test
--   failed          every notifier refused it or could not be reached
--   not_configured  there is nowhere to send it
-- It is a word, never an error message: the transport's errors name the URL,
-- and the URL contains the topic.
CREATE TABLE IF NOT EXISTS ng_notify_requests (
    id                 BIGINT      GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    kind               TEXT        NOT NULL DEFAULT 'test' CHECK (kind = 'test'),
    requested_by       TEXT,
    requested_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    handled_at         TIMESTAMPTZ,
    outcome            TEXT        CHECK (outcome IN ('sent', 'failed', 'not_configured')),
    requested_at_epoch BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (requested_at AT TIME ZONE 'UTC'))::bigint) STORED,
    handled_at_epoch   BIGINT GENERATED ALWAYS AS
        (EXTRACT(EPOCH FROM (handled_at AT TIME ZONE 'UTC'))::bigint) STORED
);
CREATE INDEX IF NOT EXISTS ng_notify_requests_pending_idx ON ng_notify_requests (id)
    WHERE handled_at IS NULL;
