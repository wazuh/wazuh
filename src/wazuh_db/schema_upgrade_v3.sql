/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2019, Wazuh Inc.
 * July, 2019.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

ALTER TABLE sca_check ADD COLUMN condition TEXT;

UPDATE metadata SET value = 3 WHERE key = 'db_version';

END;