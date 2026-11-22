-- Netgrasp daemon schema, V8: three partial indexes on ng_events for the web
-- side's event pages.
--
-- Indexes only. No table, column, constraint or row changes, so the schema
-- contract (src/db/schema.rs) and every query the daemon runs read exactly as
-- they did.
--
-- Why. Every one of these pages read the whole event log, which on a live home
-- network is about 4.1 million rows and over 1 GB, roughly 95% of it
-- ip_changed. None of V1 to V7's indexes could answer them:
--
-- * Activity and new devices filter on event_type: new_device, the person
--   events and the actionable security types. ng_events_security_idx covers
--   only the six security types, so new_device and the person events were found
--   by scanning every row. Walking ng_events_time_idx instead is worse, because
--   the rows wanted are rare (171 new_device events in 4.1 million).
--   ng_events_type_time_idx leaves ip_changed out, so it is small, and gives
--   any other type in time order.
--
-- * Alerts' "Recently sent" is WHERE notified ORDER BY "timestamp" DESC. On a
--   real network almost nothing is notified, so walking the time index reads
--   the whole log to find a page of them. ng_events_notified_time_idx holds
--   only the notified rows.
--
-- * /events/security's deeper pages are ORDER BY "timestamp" DESC over the six
--   security types. ng_events_security_idx is (event_type, "timestamp"), in
--   time order only within one type, so a deep page either walks the time
--   index past the other events or sorts every security event.
--   ng_events_security_time_idx gives the six types in one time order. Its
--   type list is ng_events_security_idx's (V2), word for word.
--
-- Locking. refinery runs each migration in one transaction, so CONCURRENTLY is
-- not available. Each CREATE INDEX takes a SHARE lock on ng_events until this
-- migration commits: reads carry on, writes to ng_events wait. The daemon runs
-- its migrations at startup before it records anything, so its own writes are
-- not affected; the web side's reads are not blocked. On a 4.1 million row
-- copy of a live log the whole migration took 0.56 s with a warm cache (0.19 s,
-- 0.11 s and 0.20 s for the three builds); each build reads the table once, so
-- a cold cache or a slow disk costs more.
--
-- Most inserts touch none of the three: an ip_changed event matches no
-- predicate. Marking an event notified changes a column an index predicate
-- reads, so that UPDATE can no longer be HOT; it happens once per delivered
-- alert.
--
-- IF NOT EXISTS, with stable names, so a site whose operator built them by hand
-- ahead of this release migrates cleanly.

CREATE INDEX IF NOT EXISTS ng_events_type_time_idx
    ON ng_events (event_type, "timestamp" DESC)
    WHERE event_type <> 'ip_changed';

CREATE INDEX IF NOT EXISTS ng_events_notified_time_idx
    ON ng_events ("timestamp" DESC)
    WHERE notified;

CREATE INDEX IF NOT EXISTS ng_events_security_time_idx
    ON ng_events ("timestamp" DESC)
    WHERE event_type IN ('arp_scan', 'arp_spoof', 'rogue_dhcp', 'identity_change',
                         'ip_conflict', 'gratuitous_arp');

COMMENT ON INDEX ng_events_type_time_idx IS
    'Every event but ip_changed, by type, newest first. Serves the web side''s '
    'Activity and new devices pages.';

COMMENT ON INDEX ng_events_notified_time_idx IS
    'Delivered alerts, newest first. Serves the web side''s "Recently sent".';

COMMENT ON INDEX ng_events_security_time_idx IS
    'The six security event types in one time order. Serves the web side''s '
    'security events pages at any depth.';
