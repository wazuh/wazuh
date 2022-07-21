/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * December 30, 2020.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

CREATE TABLE IF NOT EXISTS _sys_ports (
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
    item_id TEXT,
    PRIMARY KEY (protocol, local_ip, local_port, inode)
);
INSERT INTO _sys_ports (scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, checksum) SELECT scan_id, scan_time, protocol, local_ip, local_port, remote_ip, remote_port, tx_queue, rx_queue, inode, state, PID, process, 'legacy' AS checksum FROM sys_ports;

DROP TABLE IF EXISTS sys_ports;
ALTER TABLE _sys_ports RENAME TO sys_ports;

CREATE TABLE IF NOT EXISTS vuln_cves (
    name TEXT,
    version TEXT,
    architecture TEXT,
    cve TEXT,
    PRIMARY KEY (name, version, architecture, cve)
);

CREATE INDEX IF NOT EXISTS packages_id ON vuln_cves (name);
CREATE INDEX IF NOT EXISTS cves_id ON vuln_cves (cve);

ALTER TABLE sys_netiface ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_netproto ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_netaddr ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_programs ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_hotfixes ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_processes ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_hwinfo ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');
ALTER TABLE sys_osinfo ADD COLUMN checksum TEXT DEFAULT '' NOT NULL CHECK(checksum <> '');

ALTER TABLE sys_netiface ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netproto ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_netaddr ADD COLUMN item_id TEXT DEFAULT NULL;
ALTER TABLE sys_programs ADD COLUMN item_id TEXT DEFAULT NULL;

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 7);
