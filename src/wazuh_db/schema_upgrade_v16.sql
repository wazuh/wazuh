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

INSERT INTO sync_info (component) VALUES ('syscollector-users');
INSERT INTO sync_info (component) VALUES ('syscollector-groups');
INSERT INTO sync_info (component) VALUES ('syscollector-browser-extensions');
INSERT INTO sync_info (component) VALUES ('syscollector-services');

INSERT OR REPLACE INTO metadata (key, value) VALUES ('db_version', 16);

COMMIT;
