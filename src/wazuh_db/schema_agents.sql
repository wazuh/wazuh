/*
 * SQL Schema for global database
 * Copyright 2016 Wazuh, Inc. <info@wazuh.com>
 * June 30, 2016.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

CREATE TABLE IF NOT EXISTS fim_file (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    path TEXT NOT NULL,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry'))
);

CREATE UNIQUE INDEX IF NOT EXISTS fim_file_path ON fim_file (type, path);

CREATE TABLE IF NOT EXISTS fim_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    id_file INTEGER NOT NULL REFERENCES fim_file (id),
    type TEXT NOT NULL CHECK (type IN ('added', 'modified', 'readded', 'deleted')),
    date TEXT,
    size INTEGER,
    perm TEXT,
    uid INTEGER,
    gid INTEGER,
    md5 TEXT,
    sha1 TEXT,
    uname TEXT,
    gname TEXT,
    mtime TEXT,
    inode INTEGER
);

CREATE INDEX IF NOT EXISTS fim_event_type ON fim_event (type);
CREATE INDEX IF NOT EXISTS fim_event_file ON fim_event (id_file);
CREATE INDEX IF NOT EXISTS fim_event_date ON fim_event (date);
CREATE INDEX IF NOT EXISTS fim_event_md5 ON fim_event (md5);
CREATE INDEX IF NOT EXISTS fim_event_sha1 ON fim_event (sha1);

CREATE TABLE IF NOT EXISTS pm_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_first TEXT,
    date_last TEXT,
    log TEXT,
    pci_dss TEXT,
    cis TEXT
);

CREATE INDEX IF NOT EXISTS pm_event_log ON pm_event (log);
CREATE INDEX IF NOT EXISTS pm_event_date ON pm_event (date_last);

PRAGMA journal_mode=WAL;

CREATE TABLE IF NOT EXISTS netaddr (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    address TEXT NOT NULL,
    netmask TEXT NOT NULL,
    broadcast TEXT,
    gateway TEXT,
    dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'bootp')) DEFAULT 'unknown'
);

CREATE INDEX IF NOT EXISTS netaddr_address ON netaddr (address);

CREATE TABLE IF NOT EXISTS netiface (
    name TEXT PRIMARY KEY,
    adapter TEXT,
    type TEXT,
    state TEXT,
    mtu INTEGER CHECK (mtu > 0),
    mac TEXT,
    tx_packets INTEGER,
    rx_packets INTEGER,
    tx_bytes INTEGER,
    rx_bytes INTEGER,
    id_ipv4 INTEGER REFERENCES netaddr (id),
    id_ipv6 INTEGER REFERENCES netaddr (id)
);

CREATE INDEX IF NOT EXISTS netiface_mac ON netiface (mac);

CREATE TABLE IF NOT EXISTS osinfo (
    os_name TEXT PRIMARY KEY,
    os_version TEXT,
    nodename TEXT,
    machine TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT
);

CREATE TABLE IF NOT EXISTS hwinfo (
    board_serial TEXT PRIMARY KEY,
    cpu_name TEXT,
    cpu_cores INTEGER CHECK (cpu_cores > 0),
    cpu_mhz REAL CHECK (cpu_mhz > 0),
    ram_total INTEGER CHECK (ram_total > 0),
    ram_free INTEGER CHECK (ram_free > 0)
);
