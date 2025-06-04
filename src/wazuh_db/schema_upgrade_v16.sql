/*
 * SQL Schema for upgrading databases
 * Copyright (C) 2015, Wazuh Inc.
 *
 * June 2, 2025.
 *
 * This program is a free software, you can redistribute it
 * and/or modify it under the terms of GPLv2.
*/

BEGIN;

CREATE TABLE IF NOT EXISTS sys_users (
    scan_id INTEGER,
    scan_time TEXT,
    user_id TEXT,
    user_name TEXT,
    user_full_name TEXT,
    user_home TEXT,
    user_shell TEXT,
    user_type TEXT,
    user_created TEXT,
    user_group_id INTEGER,
    user_group_id_signed INTEGER,
    user_groups TEXT,
    user_uid_signed INTEGER,
    user_uuid TEXT,
    user_is_hidden INTEGER,
    user_is_remoted INTEGER,
    user_password_status TEXT,
    user_password_hash_algorithm TEXT,
    user_password_last_change INTEGER,
    user_password_min_days_between_changes INTEGER,
    user_password_max_days_between_changes INTEGER,
    user_password_warning_days_before_expiration INTEGER,
    user_password_inactive_days INTEGER,
    user_password_expiration_date INTEGER,
    user_password_last_set_time REAL,
    user_auth_failures_count INTEGER,
    user_auth_failures_timestamp REAL,
    user_roles TEXT,
    user_last_login TEXT,
    user_host_ip TEXT,
    user_process_pid INTEGER,
    user_login_status INTEGER,
    user_login_type TEXT,
    user_login_tty TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (user_id)
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
    group_namespace_pid INTEGER,
    group_users TEXT,
    checksum TEXT NOT NULL CHECK (checksum <> ''),
    PRIMARY KEY (group_id)
);

INSERT INTO sync_info (component) VALUES ('syscollector-users');
INSERT INTO sync_info (component) VALUES ('syscollector-groups');

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 16);

COMMIT;