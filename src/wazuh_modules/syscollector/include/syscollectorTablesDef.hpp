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

constexpr auto OS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_osinfo",
        "component":"syscollector_osinfo",
        "index":"os_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE os_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto OS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_osinfo",
        "first_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["os_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"os_name ASC",
                "count_opt":1
            },
        "component":"syscollector_osinfo",
        "index":"os_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE os_name BETWEEN '?' and '?' ORDER BY os_name",
                "column_list":["os_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
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

constexpr auto HW_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hwinfo",
        "component":"syscollector_hwinfo",
        "index":"serial_number",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE serial_number BETWEEN '?' and '?' ORDER BY serial_number",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE serial_number BETWEEN '?' and '?' ORDER BY serial_number",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE serial_number ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE serial_number BETWEEN '?' and '?' ORDER BY serial_number",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto HW_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_hwinfo",
        "first_query":
            {
                "column_list":["serial_number"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"serial_number DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["serial_number"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"serial_number ASC",
                "count_opt":1
            },
        "component":"syscollector_hwinfo",
        "index":"serial_number",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE serial_number BETWEEN '?' and '?' ORDER BY serial_number",
                "column_list":["serial_number, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
};


constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hotfixes(
    hotfix_name TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix_name)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hotfixes",
        "component":"syscollector_hotfixes",
        "index":"hotfix_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE hotfix_name BETWEEN '?' and '?' ORDER BY hotfix_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE hotfix_name BETWEEN '?' and '?' ORDER BY hotfix_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE hotfix_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE hotfix_name BETWEEN '?' and '?' ORDER BY hotfix_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto HOTFIXES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_hotfixes",
        "first_query":
            {
                "column_list":["hotfix_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["hotfix_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix_name ASC",
                "count_opt":1
            },
        "component":"syscollector_hotfixes",
        "index":"hotfix_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE hotfix_name BETWEEN '?' and '?' ORDER BY hotfix_name",
                "column_list":["hotfix_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
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

constexpr auto PACKAGES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_packages",
        "component":"syscollector_packages",
        "index":"name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE name BETWEEN '?' and '?' ORDER BY name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE name BETWEEN '?' and '?' ORDER BY name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE name BETWEEN '?' and '?' ORDER BY name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PACKAGES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_packages",
        "first_query":
            {
                "column_list":["name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"name ASC",
                "count_opt":1
            },
        "component":"syscollector_packages",
        "index":"name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE name BETWEEN '?' and '?' ORDER BY name",
                "column_list":["name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"
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

constexpr auto PROCESSES_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_processes",
        "component":"syscollector_processes",
        "index":"pid",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE pid ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PROCESSES_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_processes",
        "first_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["pid"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"pid ASC",
                "count_opt":1
            },
        "component":"syscollector_processes",
        "index":"pid",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE pid BETWEEN '?' and '?' ORDER BY pid",
                "column_list":["pid, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto PORTS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_ports",
        "component":"syscollector_ports",
        "index":"file_inode",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE file_inode BETWEEN '?' and '?' ORDER BY file_inode",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE file_inode BETWEEN '?' and '?' ORDER BY file_inode",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE file_inode ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE file_inode BETWEEN '?' and '?' ORDER BY file_inode",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto PORTS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_ports",
        "first_query":
            {
                "column_list":["file_inode"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"file_inode DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["file_inode"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"file_inode ASC",
                "count_opt":1
            },
        "component":"syscollector_ports",
        "index":"file_inode",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE file_inode BETWEEN '?' and '?' ORDER BY file_inode",
                "column_list":["file_inode, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto NETIFACE_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_iface",
        "component":"syscollector_network_iface",
        "index":"interface_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE interface_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETIFACE_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_iface",
        "first_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name ASC",
                "count_opt":1
            },
        "component":"syscollector_network_iface",
        "index":"interface_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["interface_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto NETPROTO_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_protocol",
        "component":"syscollector_network_protocol",
        "index":"interface_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE interface_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETPROTO_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_protocol",
        "first_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name ASC",
                "count_opt":1
            },
        "component":"syscollector_network_protocol",
        "index":"interface_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["interface_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto NETADDRESS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_address",
        "component":"syscollector_network_address",
        "index":"interface_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE interface_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto NETADDRESS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_network_address",
        "first_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["interface_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"interface_name ASC",
                "count_opt":1
            },
        "component":"syscollector_network_address",
        "index":"interface_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE interface_name BETWEEN '?' and '?' ORDER BY interface_name",
                "column_list":["interface_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto USERS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_users",
        "component":"syscollector_users",
        "index":"user_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE user_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto USERS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_users",
        "first_query":
            {
                "column_list":["user_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"user_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["user_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"user_name ASC",
                "count_opt":1
            },
        "component":"syscollector_users",
        "index":"user_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE user_name BETWEEN '?' and '?' ORDER BY user_name",
                "column_list":["user_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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

constexpr auto GROUPS_SYNC_CONFIG_STATEMENT
{
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_groups",
        "component":"syscollector_groups",
        "index":"group_name",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE group_name ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"
};

constexpr auto GROUPS_START_CONFIG_STATEMENT
{
    R"({"table":"dbsync_groups",
        "first_query":
            {
                "column_list":["group_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_name DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["group_name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"group_name ASC",
                "count_opt":1
            },
        "component":"syscollector_groups",
        "index":"group_name",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE group_name BETWEEN '?' and '?' ORDER BY group_name",
                "column_list":["group_name, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"
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
