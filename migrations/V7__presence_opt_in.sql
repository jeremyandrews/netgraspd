-- Netgrasp daemon schema, V7: presence is opt in, and only carried devices
-- decide who is home.
--
-- Additive in shape: two user-owned columns and one daemon-owned column, and
-- ng_people.state gains a third value. Nothing V1 to V6 created is renamed,
-- dropped or retyped.
--
-- Why. Until now every device a person owned counted alike, so a laptop or a
-- desktop left at home kept its owner home all day and their location followed
-- it. And presence was always on, for every person with an owned device, with
-- no way to switch it off. Tracking where household members are is something
-- people should choose.
--
-- ng_devices.counts_for_presence (user owned). NULL means "decide by type": a
-- device counts when its device_type is phone or wearable, and not otherwise.
-- TRUE or FALSE is a person's explicit choice for that device. Existing rows
-- stay NULL.
--
-- ng_people.track_presence (user owned). Off unless switched on. The daemon's
-- presence_tracking setting has to be on as well.
--
-- ng_people.state now reads 'home', 'away' or 'untracked'. An untracked person
-- has no location, is never home or away, and produces no person events. Every
-- existing person is set to untracked here, because the new default is off: no
-- data from the old behaviour is kept, on purpose. A person whose tracking is
-- switched on is re-evaluated by the daemon from their devices, silently.
--
-- ng_daemon_status.presence_tracking (daemon owned) publishes the install's
-- switch, so the web side can say tracking is off for everybody.
--
-- Every ADD COLUMN is IF NOT EXISTS because the Trovato plugin ships a guarded
-- copy of the two user-owned columns: a site that upgrades the plugin first
-- already has them when this runs. Either order ends in the same schema.

ALTER TABLE ng_devices ADD COLUMN IF NOT EXISTS counts_for_presence BOOLEAN;

COMMENT ON COLUMN ng_devices.counts_for_presence IS
    'User-owned. Whether this device decides if its owner is home. NULL decides '
    'by device_type (phone and wearable count); TRUE or FALSE is a person''s '
    'explicit choice. The daemon reads it and never writes it.';

ALTER TABLE ng_people ADD COLUMN IF NOT EXISTS track_presence BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN ng_people.track_presence IS
    'User-owned. Whether anybody keeps track of whether this person is home. '
    'Off by default; the daemon''s presence_tracking setting must be on too.';

ALTER TABLE ng_people ALTER COLUMN state SET DEFAULT 'untracked';

UPDATE ng_people SET state = 'untracked', current_location = NULL;

COMMENT ON COLUMN ng_people.state IS
    'Daemon-owned. home, away or untracked. Untracked is neither home nor away: '
    'presence tracking is off for this person, for the whole install, or they '
    'own no device that counts.';

ALTER TABLE ng_daemon_status
    ADD COLUMN IF NOT EXISTS presence_tracking BOOLEAN NOT NULL DEFAULT FALSE;

COMMENT ON COLUMN ng_daemon_status.presence_tracking IS
    'Daemon-owned. The daemon''s presence_tracking setting. Off means every '
    'person is untracked whatever their own switch says.';
