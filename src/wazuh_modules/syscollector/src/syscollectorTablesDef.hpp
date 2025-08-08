/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#pragma once

constexpr auto OS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_osinfo (
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
    os_kernel_name TEXT,
    os_kernel_release TEXT,
    os_kernel_version TEXT,
    os_distribution_release TEXT,
    os_full TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)) WITHOUT ROWID;)"
};

constexpr auto HW_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hwinfo (
    serial_number TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_speed DOUBLE,
    memory_total INTEGER,
    memory_free INTEGER,
    memory_used INTEGER,
    checksum TEXT,
    PRIMARY KEY (serial_number)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hotfixes(
    hotfix_name TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix_name)) WITHOUT ROWID;)"
};

constexpr auto PACKAGES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
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
    checksum TEXT,
    PRIMARY KEY (name,version,architecture,type,path)) WITHOUT ROWID;)"
};

constexpr auto PROCESSES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    parent_pid BIGINT,
    utime BIGINT,
    stime BIGINT,
    command_line TEXT,
    args TEXT,
    args_count BIGINT,
    start BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)) WITHOUT ROWID;)"
};

constexpr auto PORTS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_ports (
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
       checksum TEXT,
       PRIMARY KEY (file_inode, network_transport, source_ip, source_port)) WITHOUT ROWID;)"
};

constexpr auto NETIFACE_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_iface (
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
       checksum TEXT,
       PRIMARY KEY (interface_name,interface_alias,interface_type)) WITHOUT ROWID;)"
};

constexpr auto NETPROTO_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_protocol (
       interface_name TEXT,
       network_type TEXT,
       network_gateway TEXT,
       network_dhcp TEXT NOT NULL CHECK (network_dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
       network_metric TEXT,
       checksum TEXT,
       PRIMARY KEY (interface_name,network_type)) WITHOUT ROWID;)"
};

constexpr auto NETADDR_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_address (
       interface_name TEXT,
       network_protocol INTEGER,
       network_ip TEXT,
       network_netmask TEXT,
       network_broadcast TEXT,
       checksum TEXT,
       PRIMARY KEY (interface_name,network_protocol,network_ip)) WITHOUT ROWID;)"
};

constexpr auto USERS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_users (
        user_name TEXT,
        user_full_name TEXT,
        user_home TEXT,
        user_id BIGINT,
        user_uid_signed BIGINT,
        user_uuid TEXT,
        user_groups TEXT,
        user_group_id BIGINT,
        user_group_id_signed BIGINT,
        user_created DOUBLE,
        user_roles TEXT,
        user_shell TEXT,
        user_type TEXT,
        user_is_hidden INTEGER,
        user_is_remote INTEGER,
        user_last_login BIGINT,
        user_auth_failed_count BIGINT,
        user_auth_failed_timestamp DOUBLE,
        user_password_last_change DOUBLE,
        user_password_expiration_date INTEGER,
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
        checksum TEXT,
        PRIMARY KEY (user_name)) WITHOUT ROWID;)"
};

constexpr auto GROUPS_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_groups (
    group_id BIGINT,
    group_name TEXT,
    group_description TEXT,
    group_id_signed BIGINT,
    group_uuid TEXT,
    group_is_hidden INTEGER,
    group_users TEXT,
    checksum TEXT,
    PRIMARY KEY (group_name)) WITHOUT ROWID;)"
};

constexpr auto NET_IFACE_TABLE    { "dbsync_network_iface"    };
constexpr auto NET_PROTOCOL_TABLE { "dbsync_network_protocol" };
constexpr auto NET_ADDRESS_TABLE  { "dbsync_network_address"  };
constexpr auto PACKAGES_TABLE     { "dbsync_packages"         };
constexpr auto HOTFIXES_TABLE     { "dbsync_hotfixes"         };
constexpr auto PORTS_TABLE        { "dbsync_ports"            };
constexpr auto PROCESSES_TABLE    { "dbsync_processes"        };
constexpr auto OS_TABLE           { "dbsync_osinfo"           };
constexpr auto HW_TABLE           { "dbsync_hwinfo"           };
constexpr auto USERS_TABLE        { "dbsync_users"            };
constexpr auto GROUPS_TABLE       { "dbsync_groups"           };
