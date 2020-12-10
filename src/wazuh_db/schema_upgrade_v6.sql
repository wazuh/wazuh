/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * October 5, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

ALTER TABLE sys_osinfo ADD COLUMN os_patch TEXT DEFAULT NOT NULL CHECK (checksum <> '');

ALTER TABLE sys_netiface ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_netproto ADD COLUMN checksum TEXT DEFAULT NULL;
ALTER TABLE sys_netaddr ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_ports ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_programs ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_hotfixes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_processes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 6);
