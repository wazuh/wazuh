/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * October 5, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

DELETE FROM sys_osinfo;
DELETE FROM sys_netiface;
DELETE FROM sys_netproto;
DELETE FROM sys_netaddr;
DELETE FROM sys_programs;
DELETE FROM sys_hotfixes;
DELETE FROM sys_processes;

ALTER TABLE sys_osinfo ADD COLUMN os_patch TEXT DEFAULT NULL;

DROP TABLE sys_ports;
CREATE TABLE IF NOT EXISTS sys_ports (
    scan_id INTEGER,
    scan_time TEXT,
    protocol TEXT,
    local_ip TEXT,
    local_port INTEGER CHECK (local_port >= 0),
    remote_ip TEXT,
    remote_port INTEGER CHECK (remote_port >= 0),
    tx_queue INTEGER,
    rx_queue INTEGER,
    inode INTEGER,
    state TEXT,
    PID INTEGER,
    process TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (protocol, local_ip, local_port, inode)
);

ALTER TABLE sys_netiface ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_netproto ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_netaddr ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_programs ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_hotfixes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');
ALTER TABLE sys_processes ADD COLUMN checksum TEXT DEFAULT NOT NULL CHECK (checksum <> '');

ALTER TABLE sys_netiface ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netproto ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netaddr ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_ports ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN item_id TEXT DEFAULT NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 6);
