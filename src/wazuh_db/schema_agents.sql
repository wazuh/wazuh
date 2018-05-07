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

CREATE TABLE IF NOT EXISTS fim_entry (
    file TEXT PRIMARY KEY,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry')),
    date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    changes INTEGER NOT NULL DEFAULT 0,
    size INTEGER,
    perm TEXT,
    uid TEXT,
    gid TEXT,
    md5 TEXT,
    sha1 TEXT,
    uname TEXT,
    gname TEXT,
    mtime INTEGER,
    inode TEXT
);

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

CREATE TABLE IF NOT EXISTS sys_netiface (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    scan_time TEXT,
    name TEXT,
    adapter TEXT,
    type TEXT,
    state TEXT,
    mtu INTEGER CHECK (mtu > 0),
    mac TEXT,
    tx_packets INTEGER,
    rx_packets INTEGER,
    tx_bytes INTEGER,
    rx_bytes INTEGER,
    tx_errors INTEGER,
    rx_errors INTEGER,
    tx_dropped INTEGER,
    rx_dropped INTEGER
);

CREATE INDEX IF NOT EXISTS netiface_id ON sys_netiface (scan_id);

CREATE TABLE IF NOT EXISTS sys_netproto (
    id INTEGER REFERENCES sys_netiface (id),
    scan_id INTEGER,
    iface TEXT,
    type TEXT,
    gateway TEXT,
    dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
    PRIMARY KEY (id, type)
);

CREATE INDEX IF NOT EXISTS netproto_id ON sys_netproto (scan_id);

CREATE TABLE IF NOT EXISTS sys_netaddr (
    id INTEGER REFERENCES sys_netiface (id),
    scan_id INTEGER,
    proto TEXT,
    address TEXT,
    netmask TEXT,
    broadcast TEXT,
    PRIMARY KEY (id, address)
);

CREATE INDEX IF NOT EXISTS netaddr_id ON sys_netaddr (scan_id);

CREATE TABLE IF NOT EXISTS sys_osinfo (
    scan_id INTEGER,
    scan_time TEXT,
    hostname TEXT,
    architecture TEXT,
    os_name TEXT,
    os_version TEXT,
    os_codename TEXT,
    os_major TEXT,
    os_minor TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    PRIMARY KEY (scan_id, os_name)
);

CREATE TABLE IF NOT EXISTS sys_hwinfo (
    scan_id INTEGER,
    scan_time TEXT,
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER CHECK (cpu_cores > 0),
    cpu_mhz REAL CHECK (cpu_mhz > 0),
    ram_total INTEGER CHECK (ram_total > 0),
    ram_free INTEGER CHECK (ram_free > 0),
    ram_usage INTEGER CHECK (ram_usage >= 0 AND ram_usage <= 100),
    PRIMARY KEY (scan_id, board_serial)
);

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
    process TEXT
);

CREATE INDEX IF NOT EXISTS ports_id ON sys_ports (scan_id);

CREATE TABLE IF NOT EXISTS sys_programs (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT NOT NULL CHECK (format IN ('deb', 'rpm', 'win', 'pkg')),
    name TEXT,
    priority TEXT,
    section TEXT,
    size INTEGER CHECK (size >= 0),
    vendor TEXT,
    install_time TEXT,
    version TEXT,
    architecture TEXT,
    multiarch TEXT,
    source TEXT,
    description TEXT,
    location TEXT,
    triaged INTEGER(1),
    PRIMARY KEY (scan_id, name, version, architecture)
);

CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

CREATE TABLE IF NOT EXISTS sys_processes (
    scan_id INTEGER,
    scan_time TEXT,
    pid TEXT,
    name TEXT,
    state TEXT,
    ppid INTEGER,
    utime INTEGER,
    stime INTEGER,
    cmd TEXT,
    argvs TEXT,
    euser TEXT,
    ruser TEXT,
    suser TEXT,
    egroup TEXT,
    rgroup TEXT,
    sgroup TEXT,
    fgroup TEXT,
    priority INTEGER,
    nice INTEGER,
    size INTEGER,
    vm_size INTEGER,
    resident INTEGER,
    share INTEGER,
    start_time INTEGER,
    pgrp INTEGER,
    session INTEGER,
    nlwp INTEGER,
    tgid INTEGER,
    tty INTEGER,
    processor INTEGER,
    PRIMARY KEY (scan_id, pid)
);

CREATE INDEX IF NOT EXISTS processes_id ON sys_processes (scan_id);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);
