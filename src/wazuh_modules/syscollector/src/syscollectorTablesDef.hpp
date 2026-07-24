/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

// Every dbsync table carries container_id ('' for host rows) as the leading
// primary-key member so host and container inventories can share tables while
// scoped DBSync transactions diff them independently. container_json stores
// the serialized container/kubernetes context so DELETED events remain
// self-contained after the container is gone.
constexpr auto CONTAINER_ID_COLUMN   { "container_id" };
constexpr auto CONTAINER_JSON_COLUMN { "container_json" };
constexpr auto HOST_CONTAINER_ID     { "" };

constexpr auto OS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_osinfo (
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
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
    os_type TEXT,
    os_kernel_name TEXT,
    os_kernel_release TEXT,
    os_kernel_version TEXT,
    os_distribution_release TEXT,
    os_full TEXT,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, os_name, os_version)) WITHOUT ROWID;)"
};

constexpr auto HW_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hwinfo (
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
    serial_number TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_speed DOUBLE,
    memory_total INTEGER,
    memory_free INTEGER,
    memory_used INTEGER,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, serial_number)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hotfixes(
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
    hotfix_name TEXT,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, hotfix_name)) WITHOUT ROWID;)"
};

constexpr auto PACKAGES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_packages(
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
    name TEXT,
    version_ TEXT,
    vendor TEXT,
    installed TEXT,
    path TEXT,
    architecture TEXT,
    category TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    type TEXT,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, name,version_,architecture,type,path)) WITHOUT ROWID;)"
};

constexpr auto PROCESSES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_processes (
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
    pid TEXT,
    name TEXT,
    state TEXT,
    parent_pid BIGINT,
    utime BIGINT,
    stime BIGINT,
    command_line TEXT,
    args TEXT,
    args_count BIGINT,
    start TEXT,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, pid)) WITHOUT ROWID;)"
};

constexpr auto PORTS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_ports (
       container_id TEXT DEFAULT '',
       container_json TEXT DEFAULT '',
       network_transport TEXT,
       source_ip TEXT,
       source_port BIGINT,
       destination_ip TEXT,
       destination_port BIGINT,
       host_network_egress_queue BIGINT,
       host_network_ingress_queue BIGINT,
       file_inode BIGINT,
       interface_state TEXT,
       process_pid BIGINT,
       process_name TEXT,
       sync INTEGER DEFAULT 0,
       checksum TEXT,
       version INTEGER NOT NULL DEFAULT 1,
       PRIMARY KEY (container_id, file_inode, network_transport, source_ip, source_port)) WITHOUT ROWID;)"
};

constexpr auto NETIFACE_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_iface (
       container_id TEXT DEFAULT '',
       container_json TEXT DEFAULT '',
       interface_name TEXT,
       interface_alias TEXT,
       interface_type TEXT,
       interface_state TEXT,
       interface_mtu INTEGER,
       host_mac TEXT,
       host_network_egress_packages INTEGER,
       host_network_ingress_packages INTEGER,
       host_network_egress_bytes INTEGER,
       host_network_ingress_bytes INTEGER,
       host_network_egress_errors INTEGER,
       host_network_ingress_errors INTEGER,
       host_network_egress_drops INTEGER,
       host_network_ingress_drops INTEGER,
       sync INTEGER DEFAULT 0,
       checksum TEXT,
       version INTEGER NOT NULL DEFAULT 1,
       PRIMARY KEY (container_id, interface_name,interface_alias,interface_type)) WITHOUT ROWID;)"
};

constexpr auto NETPROTO_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_protocol (
       container_id TEXT DEFAULT '',
       container_json TEXT DEFAULT '',
       interface_name TEXT,
       network_type TEXT,
       network_gateway TEXT,
       network_dhcp INTEGER,
       network_metric TEXT,
       sync INTEGER DEFAULT 0,
       checksum TEXT,
       version INTEGER NOT NULL DEFAULT 1,
       PRIMARY KEY (container_id, interface_name,network_type)) WITHOUT ROWID;)"
};

constexpr auto NETADDR_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_address (
       container_id TEXT DEFAULT '',
       container_json TEXT DEFAULT '',
       interface_name TEXT,
       network_type INTEGER,
       network_ip TEXT,
       network_netmask TEXT,
       network_broadcast TEXT,
       sync INTEGER DEFAULT 0,
       checksum TEXT,
       version INTEGER NOT NULL DEFAULT 1,
       PRIMARY KEY (container_id, interface_name,network_type,network_ip)) WITHOUT ROWID;)"
};

constexpr auto USERS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_users (
        container_id TEXT DEFAULT '',
        container_json TEXT DEFAULT '',
        user_name TEXT,
        user_full_name TEXT,
        user_home TEXT,
        user_id BIGINT,
        user_uid_signed BIGINT,
        user_uuid TEXT,
        user_groups TEXT,
        user_group_id BIGINT,
        user_group_id_signed BIGINT,
        user_created TEXT,
        user_roles TEXT,
        user_shell TEXT,
        user_type TEXT,
        user_is_hidden INTEGER,
        user_is_remote INTEGER,
        user_last_login TEXT,
        user_auth_failed_count BIGINT,
        user_auth_failed_timestamp TEXT,
        user_password_last_change BIGINT,
        user_password_expiration_date TEXT,
        user_password_hash_algorithm TEXT,
        user_password_inactive_days INTEGER,
        user_password_max_days_between_changes INTEGER,
        user_password_min_days_between_changes INTEGER,
        user_password_status TEXT,
        user_password_warning_days_before_expiration INTEGER,
        process_pid BIGINT,
        host_ip TEXT,
        login_status INTEGER,
        login_tty TEXT,
        login_type TEXT,
        sync INTEGER DEFAULT 0,
        checksum TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (container_id, user_name)) WITHOUT ROWID;)"
};

constexpr auto GROUPS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_groups (
    container_id TEXT DEFAULT '',
    container_json TEXT DEFAULT '',
    group_id BIGINT,
    group_name TEXT,
    group_description TEXT,
    group_id_signed BIGINT,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    sync INTEGER DEFAULT 0,
    checksum TEXT,
    version INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (container_id, group_name)) WITHOUT ROWID;)"
};

constexpr auto SERVICES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_services (
        container_id TEXT DEFAULT '',
        container_json TEXT DEFAULT '',
        service_id TEXT,
        service_name TEXT,
        service_description TEXT,
        service_type TEXT,
        service_state TEXT,
        service_sub_state TEXT,
        service_enabled TEXT,
        service_start_type TEXT,
		service_restart TEXT,
		service_frequency BIGINT,
		service_starts_on_mount INTEGER,
		service_starts_on_path_modified TEXT,
		service_starts_on_not_empty_directory TEXT,
		service_inetd_compatibility INTEGER,
        process_pid BIGINT,
        process_executable TEXT,
        process_args TEXT,
		process_user_name TEXT,
		process_group_name TEXT,
		process_working_dir TEXT,
		process_root_dir TEXT,
        file_path TEXT,
        service_address TEXT,
        log_file_path TEXT,
        error_log_file_path TEXT,
        service_exit_code INTEGER,
        service_win32_exit_code INTEGER,
        service_following TEXT,
        service_object_path TEXT,
        service_target_ephemeral_id BIGINT,
        service_target_type TEXT,
        service_target_address TEXT,
        sync INTEGER DEFAULT 0,
        checksum TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (container_id, service_id, file_path)) WITHOUT ROWID;)"
};

constexpr auto BROWSER_EXTENSIONS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_browser_extensions (
        container_id TEXT DEFAULT '',
        container_json TEXT DEFAULT '',
        browser_name TEXT,
        user_id TEXT,
        package_name TEXT,
        package_id TEXT,
        package_version_ TEXT,
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
        sync INTEGER DEFAULT 0,
        checksum TEXT,
        version INTEGER NOT NULL DEFAULT 1,
        PRIMARY KEY (container_id, browser_name,user_id,browser_profile_path,package_name,package_version_)) WITHOUT ROWID;)"
};

constexpr auto TABLE_METADATA_SQL_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS table_metadata (
    table_name TEXT PRIMARY KEY,
    last_sync_time INTEGER NOT NULL
    );)"
};

constexpr auto NET_IFACE_TABLE              { "dbsync_network_iface"        };
constexpr auto NET_PROTOCOL_TABLE           { "dbsync_network_protocol"     };
constexpr auto NET_ADDRESS_TABLE            { "dbsync_network_address"      };
constexpr auto PACKAGES_TABLE               { "dbsync_packages"             };
constexpr auto HOTFIXES_TABLE               { "dbsync_hotfixes"             };
constexpr auto PORTS_TABLE                  { "dbsync_ports"                };
constexpr auto PROCESSES_TABLE              { "dbsync_processes"            };
constexpr auto OS_TABLE                     { "dbsync_osinfo"               };
constexpr auto HW_TABLE                     { "dbsync_hwinfo"               };
constexpr auto USERS_TABLE                  { "dbsync_users"                };
constexpr auto GROUPS_TABLE                 { "dbsync_groups"               };
constexpr auto SERVICES_TABLE               { "dbsync_services"             };
constexpr auto BROWSER_EXTENSIONS_TABLE     { "dbsync_browser_extensions"   };

constexpr auto METADATA_TABLE               { "table_metadata"              };

// Primary key fields for each table (used for ORDER BY clauses)
// These must match the PRIMARY KEY definitions in the CREATE TABLE statements above
constexpr auto OS_PK_FIELDS                 { "container_id, os_name, os_version" };
constexpr auto HW_PK_FIELDS                 { "container_id, serial_number" };
constexpr auto HOTFIXES_PK_FIELDS           { "container_id, hotfix_name" };
constexpr auto PACKAGES_PK_FIELDS           { "container_id, name, version_, architecture, type, path" };
constexpr auto PROCESSES_PK_FIELDS          { "container_id, pid" };
constexpr auto PORTS_PK_FIELDS              { "container_id, file_inode, network_transport, source_ip, source_port" };
constexpr auto NET_IFACE_PK_FIELDS          { "container_id, interface_name, interface_alias, interface_type" };
constexpr auto NET_PROTOCOL_PK_FIELDS       { "container_id, interface_name, network_type" };
constexpr auto NET_ADDRESS_PK_FIELDS        { "container_id, interface_name, network_type, network_ip" };
constexpr auto USERS_PK_FIELDS              { "container_id, user_name" };
constexpr auto GROUPS_PK_FIELDS             { "container_id, group_name" };
constexpr auto SERVICES_PK_FIELDS           { "container_id, service_id, file_path" };
constexpr auto BROWSER_EXTENSIONS_PK_FIELDS { "container_id, browser_name, user_id, browser_profile_path, package_name, package_version_" };

// Simplified ordering fields for document limit management
// Most tables use first PK field only, but some use multiple for better stability
constexpr auto OS_ORDER_BY                  { "os_name" };
constexpr auto HW_ORDER_BY                  { "serial_number" };
constexpr auto HOTFIXES_ORDER_BY            { "hotfix_name" };
constexpr auto PACKAGES_ORDER_BY            { "name, type" };  // Use name+type for stability
constexpr auto PROCESSES_ORDER_BY           { "pid" };
constexpr auto PORTS_ORDER_BY               { "file_inode" };
constexpr auto NET_IFACE_ORDER_BY           { "interface_name" };
constexpr auto NET_PROTOCOL_ORDER_BY        { "interface_name" };
constexpr auto NET_ADDRESS_ORDER_BY         { "interface_name" };
constexpr auto USERS_ORDER_BY               { "user_name" };
constexpr auto GROUPS_ORDER_BY              { "group_name" };
constexpr auto SERVICES_ORDER_BY            { "service_id" };
constexpr auto BROWSER_EXTENSIONS_ORDER_BY  { "browser_name" };
