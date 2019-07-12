BEGIN;

ALTER TABLE sca_check ADD COLUMN condition TEXT;

UPDATE metadata SET value = 3 WHERE key = 'db_version';

END;