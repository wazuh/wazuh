/*
 * Wazuh NewSca
 * Copyright (C) 2015, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "hashHelper.h"
#include "json.hpp"
#include "newsca.h"
#include "newsca.hpp"
#include "stringHelper.h"
#include "timeHelper.h"
#include <iostream>

#define TRY_CATCH_TASK(task)                                                                                           \
    do                                                                                                                 \
    {                                                                                                                  \
        try                                                                                                            \
        {                                                                                                              \
            if (!m_stopping)                                                                                           \
            {                                                                                                          \
                task();                                                                                                \
            }                                                                                                          \
        }                                                                                                              \
        catch (const std::exception& ex)                                                                               \
        {                                                                                                              \
            if (m_logFunction)                                                                                         \
            {                                                                                                          \
                m_logFunction(LOG_ERROR, std::string {ex.what()});                                                     \
            }                                                                                                          \
        }                                                                                                              \
    } while (0)

constexpr auto QUEUE_SIZE {4096};

static const std::map<ReturnTypeCallback, std::string> OPERATION_MAP {
    // LCOV_EXCL_START
    {MODIFIED, "MODIFIED"},
    {DELETED, "DELETED"},
    {INSERTED, "INSERTED"},
    {MAX_ROWS, "MAX_ROWS"},
    {DB_ERROR, "DB_ERROR"},
    {SELECTED, "SELECTED"},
    // LCOV_EXCL_STOP
};

constexpr auto OS_SQL_STATEMENT {
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
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
    os_display_version TEXT,
    checksum TEXT,
    PRIMARY KEY (os_name)) WITHOUT ROWID;)"};

constexpr auto OS_SYNC_CONFIG_STATEMENT {
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
    )"};

constexpr auto OS_START_CONFIG_STATEMENT {
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
        })"};

constexpr auto HW_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_hwinfo (
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz DOUBLE,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT,
    PRIMARY KEY (board_serial)) WITHOUT ROWID;)"};

constexpr auto HW_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hwinfo",
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE board_serial ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto HW_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_hwinfo",
        "first_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["board_serial"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"board_serial ASC",
                "count_opt":1
            },
        "component":"syscollector_hwinfo",
        "index":"board_serial",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE board_serial BETWEEN '?' and '?' ORDER BY board_serial",
                "column_list":["board_serial, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"};

constexpr auto HOTFIXES_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_hotfixes(
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)) WITHOUT ROWID;)"};

constexpr auto HOTFIXES_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_hotfixes",
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE hotfix ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto HOTFIXES_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_hotfixes",
        "first_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix ASC",
                "count_opt":1
            },
        "component":"syscollector_hotfixes",
        "index":"hotfix",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "column_list":["hotfix, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"};

constexpr auto PACKAGES_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
    vendor TEXT,
    install_time TEXT,
    location TEXT,
    architecture TEXT,
    groups TEXT,
    description TEXT,
    size BIGINT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name,version,architecture,format,location)) WITHOUT ROWID;)"};
static const std::vector<std::string> PACKAGES_ITEM_ID_FIELDS {"name", "version", "architecture", "format", "location"};

constexpr auto PACKAGES_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_packages",
        "component":"syscollector_packages",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto PACKAGES_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_packages",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_packages",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":100
            }
        })"};

constexpr auto PROCESSES_START_CONFIG_STATEMENT {
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
        })"};

constexpr auto PROCESSES_SYNC_CONFIG_STATEMENT {
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
    )"};

constexpr auto PROCESSES_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_processes (
    pid TEXT,
    name TEXT,
    state TEXT,
    ppid BIGINT,
    utime BIGINT,
    stime BIGINT,
    cmd TEXT,
    argvs TEXT,
    euser TEXT,
    ruser TEXT,
    suser TEXT,
    egroup TEXT,
    rgroup TEXT,
    sgroup TEXT,
    fgroup TEXT,
    priority BIGINT,
    nice BIGINT,
    size BIGINT,
    vm_size BIGINT,
    resident BIGINT,
    share BIGINT,
    start_time BIGINT,
    pgrp BIGINT,
    session BIGINT,
    nlwp BIGINT,
    tgid BIGINT,
    tty BIGINT,
    processor BIGINT,
    checksum TEXT,
    PRIMARY KEY (pid)) WITHOUT ROWID;)"};

constexpr auto PORTS_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_ports",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_ports",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"};

constexpr auto PORTS_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_ports",
        "component":"syscollector_ports",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto PORTS_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_ports (
       protocol TEXT,
       local_ip TEXT,
       local_port BIGINT,
       remote_ip TEXT,
       remote_port BIGINT,
       tx_queue BIGINT,
       rx_queue BIGINT,
       inode BIGINT,
       state TEXT,
       pid BIGINT,
       process TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (inode, protocol, local_ip, local_port)) WITHOUT ROWID;)"};
static const std::vector<std::string> PORTS_ITEM_ID_FIELDS {"inode", "protocol", "local_ip", "local_port"};

constexpr auto NETIFACE_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_network_iface",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_iface",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"};

constexpr auto NETIFACE_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_iface",
        "component":"syscollector_network_iface",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto NETIFACE_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_network_iface (
       name TEXT,
       adapter TEXT,
       type TEXT,
       state TEXT,
       mtu INTEGER,
       mac TEXT,
       tx_packets INTEGER,
       rx_packets INTEGER,
       tx_bytes INTEGER,
       rx_bytes INTEGER,
       tx_errors INTEGER,
       rx_errors INTEGER,
       tx_dropped INTEGER,
       rx_dropped INTEGER,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (name,adapter,type)) WITHOUT ROWID;)"};
static const std::vector<std::string> NETIFACE_ITEM_ID_FIELDS {"name", "adapter", "type"};

constexpr auto NETPROTO_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_network_protocol",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"};

constexpr auto NETPROTO_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_protocol",
        "component":"syscollector_network_protocol",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto NETPROTO_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_network_protocol (
       iface TEXT,
       type TEXT,
       gateway TEXT,
       dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
       metric TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,type)) WITHOUT ROWID;)"};
static const std::vector<std::string> NETPROTO_ITEM_ID_FIELDS {"iface", "type"};

constexpr auto NETADDRESS_START_CONFIG_STATEMENT {
    R"({"table":"dbsync_network_address",
        "first_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id DESC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["item_id"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"item_id ASC",
                "count_opt":1
            },
        "component":"syscollector_network_address",
        "index":"item_id",
        "last_event":"last_event",
        "checksum_field":"checksum",
        "range_checksum_query_json":
            {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["item_id, checksum"],
                "distinct_opt":false,
                "order_by_opt":"",
                "count_opt":1000
            }
        })"};

constexpr auto NETADDRESS_SYNC_CONFIG_STATEMENT {
    R"(
    {
        "decoder_type":"JSON_RANGE",
        "table":"dbsync_network_address",
        "component":"syscollector_network_address",
        "index":"item_id",
        "checksum_field":"checksum",
        "no_data_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "count_field_name":"count",
                "column_list":["count(*) AS count "],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "row_data_query_json": {
                "row_filter":"WHERE item_id ='?'",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "range_checksum_query_json": {
                "row_filter":"WHERE item_id BETWEEN '?' and '?' ORDER BY item_id",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        }
    }
    )"};

constexpr auto NETADDR_SQL_STATEMENT {
    R"(CREATE TABLE dbsync_network_address (
       iface TEXT,
       proto INTEGER,
       address TEXT,
       netmask TEXT,
       broadcast TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,proto,address)) WITHOUT ROWID;)"};
static const std::vector<std::string> NETADDRESS_ITEM_ID_FIELDS {"iface", "proto", "address"};

constexpr auto NET_IFACE_TABLE {"dbsync_network_iface"};
constexpr auto NET_PROTOCOL_TABLE {"dbsync_network_protocol"};
constexpr auto NET_ADDRESS_TABLE {"dbsync_network_address"};
constexpr auto PACKAGES_TABLE {"dbsync_packages"};
constexpr auto HOTFIXES_TABLE {"dbsync_hotfixes"};
constexpr auto PORTS_TABLE {"dbsync_ports"};
constexpr auto PROCESSES_TABLE {"dbsync_processes"};
constexpr auto OS_TABLE {"dbsync_osinfo"};
constexpr auto HW_TABLE {"dbsync_hwinfo"};

static std::string getItemId(const nlohmann::json& item, const std::vector<std::string>& idFields)
{
    Utils::HashData hash;

    for (const auto& field : idFields)
    {
        const auto& value {item.at(field)};

        if (value.is_string())
        {
            const auto& valueString {value.get<std::string>()};
            hash.update(valueString.c_str(), valueString.size());
        }
        else
        {
            const auto& valueNumber {value.get<unsigned long>()};
            const auto valueString {std::to_string(valueNumber)};
            hash.update(valueString.c_str(), valueString.size());
        }
    }
    return Utils::asciiToHex(hash.hash());
}

static void removeKeysWithEmptyValue(nlohmann::json& input)
{
    for (auto& data : input)
    {
        for (auto it = data.begin(); it != data.end();)
        {
            if (it.value().type() == nlohmann::detail::value_t::string &&
                it.value().get_ref<const std::string&>().empty())
            {
                it = data.erase(it);
            }
            else
            {
                ++it;
            }
        }
    }
}

static bool isElementDuplicated(const nlohmann::json& input, const std::pair<std::string, std::string>& keyValue)
{
    const auto it {std::find_if(input.begin(),
                                input.end(),
                                [&keyValue](const auto& elem) { return elem.at(keyValue.first) == keyValue.second; })};
    return it != input.end();
}

void NewSca::notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table)
{
    if (DB_ERROR == result)
    {
        m_logFunction(LOG_ERROR, data.dump());
    }
}

void NewSca::updateChanges(const std::string& table, const nlohmann::json& values)
{
    const auto callback {[this, table](ReturnTypeCallback result, const nlohmann::json& data)
                         {
                             notifyChange(result, data, table);
                         }};
    DBSyncTxn txn {m_spDBSync->handle(), nlohmann::json {table}, 0, QUEUE_SIZE, callback};
    nlohmann::json input;
    input["table"] = table;
    input["data"] = values;
    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

NewSca::NewSca()
    : m_intervalValue {0}
    , m_stopping {true}
{
}

std::string NewSca::getCreateStatement() const
{
    std::string ret;

    ret += OS_SQL_STATEMENT;
    ret += HW_SQL_STATEMENT;
    ret += PACKAGES_SQL_STATEMENT;
    ret += HOTFIXES_SQL_STATEMENT;
    ret += PROCESSES_SQL_STATEMENT;
    ret += PORTS_SQL_STATEMENT;
    ret += NETIFACE_SQL_STATEMENT;
    ret += NETPROTO_SQL_STATEMENT;
    ret += NETADDR_SQL_STATEMENT;
    return ret;
}

void NewSca::registerWithRsync()
{
    const auto reportSyncWrapper {[this](const std::string& dataString)
                                  {
                                      auto jsonData(nlohmann::json::parse(dataString));
                                      auto it {jsonData.find("data")};

                                      if (!m_stopping)
                                      {
                                          if (it != jsonData.end())
                                          {
                                              auto& data {*it};
                                              it = data.find("attributes");

                                              if (it != data.end())
                                              {
                                                  auto& fieldData {*it};
                                                  removeKeysWithEmptyValue(fieldData);
                                                  fieldData["scan_time"] = Utils::getCurrentTimestamp();
                                                  const auto msgToSend {jsonData.dump()};
                                                  m_reportSyncFunction(msgToSend);
                                                  m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + msgToSend);
                                              }
                                              else
                                              {
                                                  m_reportSyncFunction(dataString);
                                                  m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
                                              }
                                          }
                                          else
                                          {
                                              // LCOV_EXCL_START
                                              m_reportSyncFunction(dataString);
                                              m_logFunction(LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
                                              // LCOV_EXCL_STOP
                                          }
                                      }
                                  }};
}

void NewSca::init(const std::shared_ptr<ISysInfo>& spInfo,
                  const std::function<void(const std::string&)> reportDiffFunction,
                  const std::function<void(const std::string&)> reportSyncFunction,
                  const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                  const std::string& dbPath,
                  const std::string& normalizerConfigPath,
                  const std::string& normalizerType,
                  const unsigned int interval)
{
    m_spInfo = spInfo;
    m_reportDiffFunction = reportDiffFunction;
    m_reportSyncFunction = reportSyncFunction;
    m_logFunction = logFunction;
    m_intervalValue = interval;

    std::unique_lock<std::mutex> lock {m_mutex};
    m_stopping = false;
    m_spDBSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement());
    m_spRsync = std::make_unique<RemoteSync>();
    registerWithRsync();
    syncLoop(lock);
}

void NewSca::destroy()
{
    std::unique_lock<std::mutex> lock {m_mutex};
    m_stopping = true;
    m_cv.notify_all();
    lock.unlock();
}

void NewSca::syncLoop(std::unique_lock<std::mutex>& lock)
{
    m_logFunction(LOG_INFO, "Test Module Loop started.");

    while (!m_cv.wait_for(lock, std::chrono::seconds {m_intervalValue}, [&]() { return m_stopping; }))
    {
        m_logFunction(LOG_INFO, "Test Module doing its job.");
    }
    m_spRsync.reset(nullptr);
    m_spDBSync.reset(nullptr);
}

void NewSca::push(const std::string& data)
{
    std::unique_lock<std::mutex> lock {m_mutex};

    if (!m_stopping)
    {
        auto rawData {data};
        Utils::replaceFirst(rawData, "dbsync ", "");
        const auto buff {reinterpret_cast<const uint8_t*>(rawData.c_str())};

        try
        {
            m_spRsync->pushMessage(std::vector<uint8_t> {buff, buff + rawData.size()});
        }
        // LCOV_EXCL_START
        catch (const std::exception& ex)
        {
            m_logFunction(LOG_ERROR, ex.what());
        }
    }

    // LCOV_EXCL_STOP
}
