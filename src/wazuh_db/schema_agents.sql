/*
 * SQL Schema for global database
 * Copyright (C) 2015, Wazuh Inc.
 * June 30, 2016.
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
 */

BEGIN;

CREATE TABLE IF NOT EXISTS fim_entry (
    full_path TEXT NOT NULL PRIMARY KEY,
    file TEXT,
    type TEXT NOT NULL CHECK (type IN ('file', 'registry_key', 'registry_value')),
    date INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    changes INTEGER NOT NULL DEFAULT 1,
    arch TEXT CHECK (arch IN (NULL, '[x64]', '[x32]')),
    value_name TEXT,
    value_type TEXT,
    size INTEGER,
    perm TEXT,
    uid TEXT,
    gid TEXT,
    md5 TEXT,
    sha1 TEXT,
    uname TEXT,
    gname TEXT,
    mtime INTEGER,
    inode INTEGER,
    sha256 TEXT,
    attributes TEXT,
    symbolic_path TEXT,
    checksum TEXT
);

CREATE INDEX IF NOT EXISTS fim_full_path_index ON fim_entry (full_path);
CREATE INDEX IF NOT EXISTS fim_file_index ON fim_entry (file);
CREATE INDEX IF NOT EXISTS fim_date_index ON fim_entry (date);
CREATE INDEX IF NOT EXISTS fim_type_full_path_index ON fim_entry (type, full_path);
CREATE INDEX IF NOT EXISTS fim_type_file_index ON fim_entry (type, file);
CREATE INDEX IF NOT EXISTS fim_type_full_path_checksum_index ON fim_entry(type,full_path,checksum);
CREATE INDEX IF NOT EXISTS fim_type_file_checksum_index ON fim_entry(type,file,checksum);


CREATE TABLE IF NOT EXISTS pm_event (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    date_first INTEGER,
    date_last INTEGER,
    log TEXT,
    pci_dss TEXT,
    cis TEXT
);

CREATE INDEX IF NOT EXISTS pm_event_log ON pm_event (log);
CREATE INDEX IF NOT EXISTS pm_event_date ON pm_event (date_last);

CREATE TABLE IF NOT EXISTS sys_netiface (
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
    rx_dropped INTEGER,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, name)
);

CREATE INDEX IF NOT EXISTS netiface_id ON sys_netiface (scan_id);

CREATE TABLE IF NOT EXISTS sys_netproto (
    scan_id INTEGER REFERENCES sys_netiface (scan_id),
    iface TEXT REFERENCES sys_netiface (name),
    type TEXT,
    gateway TEXT,
    dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
    metric INTEGER,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, iface, type)
);

CREATE INDEX IF NOT EXISTS netproto_id ON sys_netproto (scan_id);

CREATE TABLE IF NOT EXISTS sys_netaddr (
    scan_id INTEGER REFERENCES sys_netproto (scan_id),
    iface TEXT REFERENCES sys_netproto (iface),
    proto TEXT REFERENCES sys_netproto (type),
    address TEXT,
    netmask TEXT,
    broadcast TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, iface, proto, address)
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
    os_patch TEXT,
    os_build TEXT,
    os_platform TEXT,
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    os_display_version TEXT,
    reference TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (scan_id, os_name)
);

CREATE TABLE IF NOT EXISTS sys_hwinfo (
    scan_id INTEGER,
    scan_time TEXT,
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz REAL,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
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
    process TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (protocol, local_ip, local_port, inode)
);

CREATE INDEX IF NOT EXISTS ports_id ON sys_ports (scan_id);

CREATE TABLE IF NOT EXISTS sys_programs (
    scan_id INTEGER,
    scan_time TEXT,
    format TEXT,
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
    cpe TEXT,
    msu_name TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (scan_id, name, version, architecture, format, location)
);

CREATE INDEX IF NOT EXISTS programs_id ON sys_programs (scan_id);

CREATE TABLE IF NOT EXISTS sys_hotfixes (
    scan_id INTEGER,
    scan_time TEXT,
    hotfix TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, hotfix)
);

CREATE INDEX IF NOT EXISTS hotfix_id ON sys_hotfixes (scan_id);

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
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (scan_id, pid)
);

CREATE INDEX IF NOT EXISTS processes_id ON sys_processes (scan_id);

CREATE TABLE IF NOT EXISTS sys_users (
    scan_id INTEGER,
    scan_time TEXT,
    user_name TEXT,
    user_full_name TEXT,
    user_home TEXT,
    user_id INTEGER,
    user_uid_signed INTEGER,
    user_uuid TEXT,
    user_groups TEXT,
    user_group_id INTEGER,
    user_group_id_signed INTEGER,
    user_created REAL,
    user_roles TEXT,
    user_shell TEXT,
    user_type TEXT,
    user_is_hidden INTEGER,
    user_is_remote INTEGER,
    user_last_login INTEGER,
    user_auth_failed_count INTEGER,
    user_auth_failed_timestamp REAL,
    user_password_last_change REAL,
    user_password_expiration_date INTEGER,
    user_password_hash_algorithm TEXT,
    user_password_inactive_days INTEGER,
    user_password_max_days_between_changes INTEGER,
    user_password_min_days_between_changes INTEGER,
    user_password_status TEXT,
    user_password_warning_days_before_expiration INTEGER,
    process_pid INTEGER,
    host_ip TEXT,
    login_status INTEGER,
    login_tty TEXT,
    login_type TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (user_name)
);

CREATE TABLE IF NOT EXISTS sys_groups (
    scan_id INTEGER,
    scan_time TEXT,
    group_id INTEGER,
    group_name TEXT,
    group_description TEXT,
    group_id_signed INTEGER,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (group_name)
);

CREATE TABLE IF NOT EXISTS sys_browser_extensions (
    scan_id INTEGER,
    scan_time TEXT,
    browser_name TEXT,
    user_id TEXT,
    package_name TEXT,
    package_id TEXT,
    package_version TEXT,
    package_description TEXT,
    package_vendor TEXT,
    package_build_version TEXT,
    package_path TEXT,
    browser_profile_name TEXT,
    browser_profile_path TEXT,
    package_reference TEXT,
    package_permissions TEXT,
    package_type TEXT,
    package_enabled INTEGER,
    package_visible INTEGER,
    package_autoupdate INTEGER,
    package_persistent INTEGER,
    package_from_webstore INTEGER,
    browser_profile_referenced INTEGER,
    package_installed TEXT,
    file_hash_sha256 TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (browser_name, user_id, browser_profile_path, package_name, package_version)
);

CREATE TABLE IF NOT EXISTS sys_services (
    scan_id INTEGER,
    scan_time TEXT,
    service_id TEXT,
    service_name TEXT,
    service_description TEXT,
    service_type TEXT,
    service_state TEXT,
    service_sub_state TEXT,
    service_enabled TEXT,
    service_start_type TEXT,
    service_restart TEXT,
    service_frequency INTEGER,
    service_starts_on_mount INTEGER,
    service_starts_on_path_modified TEXT,
    service_starts_on_not_empty_directory TEXT,
    service_inetd_compatibility INTEGER,
    process_pid INTEGER,
    process_executable TEXT,
    process_args TEXT,
    process_user_name TEXT,
    process_group_name TEXT,
    process_working_directory TEXT,
    process_root_directory TEXT,
    file_path TEXT,
    service_address TEXT,
    log_file_path TEXT,
    error_log_file_path TEXT,
    service_exit_code INTEGER,
    service_win32_exit_code INTEGER,
    service_following TEXT,
    service_object_path TEXT,
    service_target_ephemeral_id INTEGER,
    service_target_type TEXT,
    service_target_address TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    item_id TEXT,
    PRIMARY KEY (service_id, file_path)
);

CREATE INDEX IF NOT EXISTS services_id ON sys_services (scan_id);

CREATE TABLE IF NOT EXISTS ciscat_results (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER,
    scan_time TEXT,
    benchmark TEXT,
    profile TEXT,
    pass INTEGER,
    fail INTEGER,
    error INTEGER,
    notchecked INTEGER,
    unknown INTEGER,
    score INTEGER
);

CREATE INDEX IF NOT EXISTS ciscat_id ON ciscat_results (scan_id);

CREATE TABLE IF NOT EXISTS metadata (
    key TEXT PRIMARY KEY,
    value TEXT
);

CREATE TABLE IF NOT EXISTS scan_info (
    module TEXT PRIMARY KEY,
    first_start INTEGER DEFAULT 0,
    first_end INTEGER DEFAULT 0,
    start_scan INTEGER DEFAULT 0,
    end_scan INTEGER DEFAULT 0,
    fim_first_check INTEGER DEFAULT 0,
    fim_second_check INTEGER DEFAULT 0,
    fim_third_check INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS sca_policy (
   name TEXT,
   file TEXT,
   id TEXT,
   description TEXT,
   `references` TEXT,
   hash_file TEXT
);

CREATE TABLE IF NOT EXISTS sca_scan_info (
   id INTEGER PRIMARY KEY,
   start_scan INTEGER,
   end_scan INTEGER,
   policy_id TEXT REFERENCES sca_policy (id),
   pass INTEGER,
   fail INTEGER,
   invalid INTEGER,
   total_checks INTEGER,
   score INTEGER,
   hash TEXT
);

CREATE TABLE IF NOT EXISTS sca_check (
   scan_id INTEGER REFERENCES sca_scan_info (id),
   id INTEGER PRIMARY KEY,
   policy_id TEXT REFERENCES sca_policy (id),
   title TEXT,
   description TEXT,
   rationale TEXT,
   remediation TEXT,
   file TEXT,
   process TEXT,
   directory TEXT,
   registry TEXT,
   command TEXT,
   `references` TEXT,
   result TEXT,
   reason TEXT,
   condition TEXT
);

CREATE INDEX IF NOT EXISTS policy_id_index ON sca_check (policy_id);

CREATE TABLE IF NOT EXISTS sca_check_rules (
  id_check INTEGER REFERENCES sca_check (id),
  `type` TEXT,
  rule TEXT,
  PRIMARY KEY (id_check, `type`, rule)
);

CREATE INDEX IF NOT EXISTS rules_id_check_index ON sca_check_rules (id_check);

CREATE TABLE IF NOT EXISTS sca_check_compliance (
   id_check INTEGER REFERENCES sca_check (id),
  `key` TEXT,
  `value` TEXT,
   PRIMARY KEY (id_check, `key`, `value`)
);

CREATE INDEX IF NOT EXISTS comp_id_check_index ON sca_check_compliance (id_check);

CREATE TABLE IF NOT EXISTS sync_info (
    component TEXT PRIMARY KEY,
    last_attempt INTEGER DEFAULT 0,
    last_completion INTEGER DEFAULT 0,
    n_attempts INTEGER DEFAULT 0,
    n_completions INTEGER DEFAULT 0,
    last_manager_checksum TEXT NOT NULL DEFAULT '',
    last_agent_checksum TEXT NOT NULL DEFAULT ''
);

INSERT INTO metadata (key, value) VALUES ('db_version', '16');
INSERT INTO scan_info (module) VALUES ('fim');
INSERT INTO scan_info (module) VALUES ('syscollector');
INSERT INTO sync_info (component) VALUES ('fim');
INSERT INTO sync_info (component) VALUES ('fim_file');
INSERT INTO sync_info (component) VALUES ('fim_registry');
INSERT INTO sync_info (component) VALUES ('fim_registry_key');
INSERT INTO sync_info (component) VALUES ('fim_registry_value');
INSERT INTO sync_info (component) VALUES ('syscollector-processes');
INSERT INTO sync_info (component) VALUES ('syscollector-packages');
INSERT INTO sync_info (component) VALUES ('syscollector-hotfixes');
INSERT INTO sync_info (component) VALUES ('syscollector-ports');
INSERT INTO sync_info (component) VALUES ('syscollector-netproto');
INSERT INTO sync_info (component) VALUES ('syscollector-netaddress');
INSERT INTO sync_info (component) VALUES ('syscollector-netinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-hwinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-osinfo');
INSERT INTO sync_info (component) VALUES ('syscollector-users');
INSERT INTO sync_info (component) VALUES ('syscollector-groups');
INSERT INTO sync_info (component) VALUES ('syscollector-browser-extensions');
INSERT INTO sync_info (component) VALUES ('syscollector-services');

COMMIT;
