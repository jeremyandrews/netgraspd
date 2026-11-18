-- Netgrasp daemon schema, V6: a device comes and goes without an alert until a
-- person chooses it.
--
-- Additive in shape. No table, column or type changes: ng_devices.notify keeps
-- its name, its type and NOT NULL, which is everything the Trovato plugin's
-- copy of the schema reads. Only the default changes, and the value on the rows
-- that already exist.
--
-- What notify now means. A new device is always announced once the learning
-- window is over, whatever notify says, because nobody has had a chance to
-- choose anything about it yet. returned and went_offline are announced only
-- for a device whose notify a person turned on. ip_changed, name_updated and
-- device_location_changed are never announced. Every event is still recorded in
-- ng_events.
--
-- Why every existing row is set to FALSE, and not just the default changed.
-- Under V1's DEFAULT TRUE no row was ever a choice: every device the daemon had
-- seen was set to notify the moment it was inserted. On the one installation
-- this was written against, 166 devices had notify on, none of them set by a
-- person, and no alert had ever been delivered. Keeping those TRUEs would keep
-- the stream of comings and goings this migration exists to stop. Another
-- installation's choices about which devices it hears coming and going reset
-- here and have to be made again; the CHANGELOG upgrade note says so.
--
-- notify is a user-owned column. The daemon never writes it at run time; this
-- one-off reset is the schema's, not the daemon's.

ALTER TABLE ng_devices ALTER COLUMN notify SET DEFAULT FALSE;

UPDATE ng_devices SET notify = FALSE WHERE notify;
