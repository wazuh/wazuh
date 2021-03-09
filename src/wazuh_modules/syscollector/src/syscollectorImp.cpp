/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 7, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "syscollector.hpp"
#include "json.hpp"
#include <iostream>
#include "stringHelper.h"
#include "hashHelper.h"
#include "timeHelper.h"

#define TRY_CATCH_TASK(task)                                            \
do                                                                      \
{                                                                       \
    try                                                                 \
    {                                                                   \
        if(!m_stopping)                                                 \
        {                                                               \
            task();                                                     \
        }                                                               \
    }                                                                   \
    catch(const std::exception& ex)                                     \
    {                                                                   \
        if(m_logFunction)                                               \
        {                                                               \
            const std::string error{"task: " + std::string{ex.what()}}; \
            m_logFunction(SYS_LOG_ERROR, error);                        \
        }                                                               \
    }                                                                   \
}while(0)

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
    sysname TEXT,
    release TEXT,
    version TEXT,
    os_release TEXT,
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
    board_serial TEXT,
    cpu_name TEXT,
    cpu_cores INTEGER,
    cpu_mhz DOUBLE,
    ram_total INTEGER,
    ram_free INTEGER,
    ram_usage INTEGER,
    checksum TEXT,
    PRIMARY KEY (board_serial)) WITHOUT ROWID;)"
};

constexpr auto HW_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto HW_START_CONFIG_STATEMENT
{
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
        })"
};


constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_hotfixes(
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto HOTFIXES_START_CONFIG_STATEMENT
{
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
        })"
};

constexpr auto PACKAGES_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_packages(
    name TEXT,
    version TEXT,
    vendor TEXT,
    install_time TEXT,
    location TEXT,
    architecture TEXT,
    groups TEXT,
    description TEXT,
    size INTEGER,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    PRIMARY KEY (name,version,architecture)) WITHOUT ROWID;)"
};
static const std::vector<std::string> PACKAGES_ITEM_ID_FIELDS{"name", "version", "architecture"};

constexpr auto PACKAGES_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto PACKAGES_START_CONFIG_STATEMENT
{
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
        })"
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

constexpr auto PROCESSES_SQL_STATEMENT
{
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
    PRIMARY KEY (pid)) WITHOUT ROWID;)"
};

constexpr auto PORTS_START_CONFIG_STATEMENT
{
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
        })"
};

constexpr auto PORTS_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto PORTS_SQL_STATEMENT
{
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
       process_name TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (inode, protocol, local_ip, local_port)) WITHOUT ROWID;)"
};
static const std::vector<std::string> PORTS_ITEM_ID_FIELDS{"inode","protocol","local_ip","local_port"};

constexpr auto NETIFACE_START_CONFIG_STATEMENT
{
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
        })"
};

constexpr auto NETIFACE_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto NETIFACE_SQL_STATEMENT
{
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
       PRIMARY KEY (name,adapter,type)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETIFACE_ITEM_ID_FIELDS{"name","adapter","type"};

constexpr auto NETPROTO_START_CONFIG_STATEMENT
{
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
        })"
};

constexpr auto NETPROTO_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto NETPROTO_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_protocol (
       iface TEXT,
       type TEXT,
       gateway TEXT,
       dhcp TEXT NOT NULL CHECK (dhcp IN ('enabled', 'disabled', 'unknown', 'BOOTP')) DEFAULT 'unknown',
       metric TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,type)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETPROTO_ITEM_ID_FIELDS{"iface", "type"};

constexpr auto NETADDRESS_START_CONFIG_STATEMENT
{
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
        })"
};

constexpr auto NETADDRESS_SYNC_CONFIG_STATEMENT
{
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
    )"
};

constexpr auto NETADDR_SQL_STATEMENT
{
    R"(CREATE TABLE dbsync_network_address (
       iface TEXT,
       proto INTEGER,
       address TEXT,
       netmask TEXT,
       broadcast TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,proto,address)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETADDRESS_ITEM_ID_FIELDS{"iface", "proto", "address"};

constexpr auto NET_IFACE_TABLE    { "dbsync_network_iface"    };
constexpr auto NET_PROTOCOL_TABLE { "dbsync_network_protocol" };
constexpr auto NET_ADDRESS_TABLE  { "dbsync_network_address"  };
constexpr auto PACKAGES_TABLE     { "dbsync_packages"         };
constexpr auto HOTFIXES_TABLE     { "dbsync_hotfixes"         };
constexpr auto PORTS_TABLE        { "dbsync_ports"            };
constexpr auto PROCESSES_TABLE    { "dbsync_processes"        };
constexpr auto OS_TABLE           { "dbsync_osinfo"           };
constexpr auto HW_TABLE           { "dbsync_hwinfo"           };


static std::string getItemId(const nlohmann::json& item, const std::vector<std::string>& idFields)
{
    Utils::HashData hash;
    for (const auto& field : idFields)
    {
        const auto& value{item.at(field)};
        if(value.is_string())
        {
            const auto& valueString{value.get<std::string>()};
            hash.update(valueString.c_str(), valueString.size());
        }
        else
        {
            const auto& valueNumber{value.get<unsigned long>()};
            const auto valueString{std::to_string(valueNumber)};
            hash.update(valueString.c_str(), valueString.size());
        }
    }
    return Utils::asciiToHex(hash.hash());
}

static std::string getItemChecksum(const nlohmann::json& item)
{
    const auto content{item.dump()};
    Utils::HashData hash;
    hash.update(content.c_str(), content.size());
    return Utils::asciiToHex(hash.hash());
}

static void removeKeysWithEmptyValue(nlohmann::json& input)
{
    for (auto &data : input)
    {
        for (auto it = data.begin(); it != data.end(); )
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

void Syscollector::updateAndNotifyChanges(const std::string& table,
                                          const nlohmann::json& values)
{
    const std::map<ReturnTypeCallback, std::string> operationsMap
    {
        // LCOV_EXCL_START
        {MODIFIED, "MODIFIED"},
        {DELETED , "DELETED"},
        {INSERTED, "INSERTED"},
        {MAX_ROWS, "MAX_ROWS"},
        {DB_ERROR, "DB_ERROR"},
        {SELECTED, "SELECTED"},
        // LCOV_EXCL_STOP
    };
    constexpr auto queueSize{4096};
    const auto callback
    {
        [this, &table, &operationsMap](ReturnTypeCallback result, const nlohmann::json& data)
        {
            if(result == DB_ERROR)
            {
                m_logFunction(SYS_LOG_ERROR, data.dump());
            }
            else if(m_notify && !m_stopping)
            {
                if (data.is_array())
                {
                    for (const auto& item : data)
                    {
                        nlohmann::json msg;
                        msg["type"] = table;
                        msg["operation"] = operationsMap.at(result);
                        msg["data"] = item;
                        msg["data"]["scan_time"] = m_scanTime;
                        removeKeysWithEmptyValue(msg["data"]);
                        const auto msgToSend{msg.dump()};
                        m_reportDiffFunction(msgToSend);
                        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Delta sent: " + msgToSend);
                    }
                }
                else
                {
                    // LCOV_EXCL_START
                    nlohmann::json msg;
                    msg["type"] = table;
                    msg["operation"] = operationsMap.at(result);
                    msg["data"] = data;
                    msg["data"]["scan_time"] = m_scanTime;
                    removeKeysWithEmptyValue(msg["data"]);
                    const auto msgToSend{msg.dump()};
                    m_reportDiffFunction(msgToSend);
                    m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Delta sent: " + msgToSend);
                    // LCOV_EXCL_STOP
                }
            }
        }
    };
    DBSyncTxn txn
    {
        m_spDBSync->handle(),
        nlohmann::json{table},
        0,
        queueSize,
        callback
    };
    nlohmann::json jsResult;
    nlohmann::json input;
    input["table"] = table;
    input["data"] = values;
    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

Syscollector::Syscollector()
: m_intervalValue { 0 }
, m_scanOnStart { false }
, m_hardware { false }
, m_os { false }
, m_network { false }
, m_packages { false }
, m_ports { false }
, m_portsAll { false }
, m_processes { false }
, m_hotfixes { false }
, m_stopping { true }
, m_notify { false }
{}

std::string Syscollector::getCreateStatement() const
{
    std::string ret;
    if (m_os)
    {
        ret += OS_SQL_STATEMENT;
    }
    if (m_hardware)
    {
        ret += HW_SQL_STATEMENT;
    }
    if (m_packages)
    {
        ret += PACKAGES_SQL_STATEMENT;
        if (m_hotfixes)
        {
            ret += HOTFIXES_SQL_STATEMENT;
        }
    }
    if (m_processes)
    {
        ret += PROCESSES_SQL_STATEMENT;
    }
    if (m_ports)
    {
        ret += PORTS_SQL_STATEMENT;
    }
    if (m_network)
    {
        ret += NETIFACE_SQL_STATEMENT;
        ret += NETPROTO_SQL_STATEMENT;
        ret += NETADDR_SQL_STATEMENT;
    }
    return ret;
}


void Syscollector::registerWithRsync()
{
    const auto reportSyncWrapper
    {
        [this](const std::string& dataString)
        {
            auto jsonData(nlohmann::json::parse(dataString));
            auto it{jsonData.find("data")};
            if(!m_stopping)
            {
                if(it != jsonData.end())
                {
                    auto& data{*it};
                    it = data.find("attributes");
                    if(it != data.end())
                    {
                        auto &fieldData { *it };
                        removeKeysWithEmptyValue(fieldData);
                        fieldData["scan_time"] = Utils::getCurrentTimestamp();
                        const auto msgToSend{jsonData.dump()};
                        m_reportSyncFunction(msgToSend);
                        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Sync sent: " + msgToSend);
                    }
                    else
                    {
                        m_reportSyncFunction(dataString);
                        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
                    }
                }
                else
                {
                    //LCOV_EXCL_START
                    m_reportSyncFunction(dataString);
                    m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Sync sent: " + dataString);
                    //LCOV_EXCL_STOP
                }
            }
        }
    };

    if (m_os)
    {
        m_spRsync->registerSyncID("syscollector_osinfo",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(OS_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
    }
    if (m_hardware)
    {
        m_spRsync->registerSyncID("syscollector_hwinfo",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(HW_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
    }
    if (m_processes)
    {
        m_spRsync->registerSyncID("syscollector_processes",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PROCESSES_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
    }
    if (m_packages)
    {
        m_spRsync->registerSyncID("syscollector_packages",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PACKAGES_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
        if (m_hotfixes)
        {
            m_spRsync->registerSyncID("syscollector_hotfixes",
                                      m_spDBSync->handle(),
                                      nlohmann::json::parse(HOTFIXES_SYNC_CONFIG_STATEMENT),
                                      reportSyncWrapper);
        }
    }
    if (m_ports)
    {
        m_spRsync->registerSyncID("syscollector_ports",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PORTS_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
    }
    if (m_network)
    {
        m_spRsync->registerSyncID("syscollector_network_iface",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETIFACE_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
        m_spRsync->registerSyncID("syscollector_network_protocol",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETPROTO_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
        m_spRsync->registerSyncID("syscollector_network_address",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETADDRESS_SYNC_CONFIG_STATEMENT),
                                  reportSyncWrapper);
    }
}
void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
                        const std::function<void(const std::string&)> reportDiffFunction,
                        const std::function<void(const std::string&)> reportSyncFunction,
                        const std::function<void(const syscollector_log_level_t, const std::string&)> logFunction,
                        const std::string& dbPath,
                        const std::string& normalizerConfigPath,
                        const std::string& normalizerType,
                        const unsigned int interval,
                        const bool scanOnStart,
                        const bool hardware,
                        const bool os,
                        const bool network,
                        const bool packages,
                        const bool ports,
                        const bool portsAll,
                        const bool processes,
                        const bool hotfixes)
{
    m_spInfo = spInfo;
    m_reportDiffFunction = reportDiffFunction;
    m_reportSyncFunction = reportSyncFunction;
    m_logFunction = logFunction;
    m_intervalValue = interval;
    m_scanOnStart = scanOnStart;
    m_hardware = hardware;
    m_os = os;
    m_network = network;
    m_packages = packages;
    m_ports = ports;
    m_portsAll = portsAll;
    m_processes = processes;
    m_hotfixes = hotfixes;

    std::unique_lock<std::mutex> lock{m_mutex};
    m_stopping = false;
    m_spDBSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, dbPath, getCreateStatement());
    m_spRsync = std::make_unique<RemoteSync>();
    m_spNormalizer = std::make_unique<SysNormalizer>(normalizerConfigPath, normalizerType);
    registerWithRsync();
    syncLoop(lock);
}

void Syscollector::destroy()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_stopping = true;
    m_cv.notify_all();
    lock.unlock();
}

nlohmann::json Syscollector::getHardwareData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->hardware();
    ret[0]["checksum"] = getItemChecksum(ret[0]);
    return ret;
}

void Syscollector::scanHardware()
{
    if (m_hardware)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting hardware scan");
        const auto& hwData{getHardwareData()};
        updateAndNotifyChanges(HW_TABLE, hwData);
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending hardware scan");
    }
}

void Syscollector::syncHardware()
{
    if (m_hardware)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(HW_START_CONFIG_STATEMENT), m_reportSyncFunction);
    }
}

nlohmann::json Syscollector::getOSData()
{
    nlohmann::json ret;
    ret[0] = m_spInfo->os();
    ret[0]["checksum"] = getItemChecksum(ret[0]);
    return ret;
}

void Syscollector::scanOs()
{
    if (m_os)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting os scan");
        const auto& osData{getOSData()};
        updateAndNotifyChanges(OS_TABLE, osData);
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending os scan");
    }
}

void Syscollector::syncOs()
{
    if (m_os)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(OS_START_CONFIG_STATEMENT), m_reportSyncFunction);
    }
}

nlohmann::json Syscollector::getNetworkData()
{
    nlohmann::json ret;
    const auto& networks { m_spInfo->networks() };
    nlohmann::json ifaceTableDataList {};
    nlohmann::json protoTableDataList {};
    nlohmann::json addressTableDataList {};

    if (!networks.is_null())
    {
        const auto& itIface { networks.find("iface") };

        if (networks.end() != itIface)
        {
            for (const auto& item : itIface.value())
            {
                // Split the resulting networks data into the specific DB tables
                // "dbsync_network_iface" table data to update and notify
                nlohmann::json ifaceTableData {};
                ifaceTableData["name"]       = item.at("name");
                ifaceTableData["adapter"]    = item.at("adapter");
                ifaceTableData["type"]       = item.at("type");
                ifaceTableData["state"]      = item.at("state");
                ifaceTableData["mtu"]        = item.at("mtu");
                ifaceTableData["mac"]        = item.at("mac");
                ifaceTableData["tx_packets"] = item.at("tx_packets");
                ifaceTableData["rx_packets"] = item.at("rx_packets");
                ifaceTableData["tx_errors"]  = item.at("tx_errors");
                ifaceTableData["rx_errors"]  = item.at("rx_errors");
                ifaceTableData["tx_bytes"]   = item.at("tx_bytes");
                ifaceTableData["rx_bytes"]   = item.at("rx_bytes");
                ifaceTableData["tx_dropped"] = item.at("tx_dropped");
                ifaceTableData["rx_dropped"] = item.at("rx_dropped");
                ifaceTableData["checksum"]   = getItemChecksum(ifaceTableData);
                ifaceTableData["item_id"]    = getItemId(ifaceTableData, NETIFACE_ITEM_ID_FIELDS);
                ifaceTableDataList.push_back(ifaceTableData);

                // "dbsync_network_protocol" table data to update and notify
                nlohmann::json protoTableData {};
                protoTableData["iface"]   = item.at("name");
                protoTableData["type"]    = item.at("type");
                protoTableData["gateway"] = item.at("gateway");

                if (item.find("IPv4") != item.end())
                {
                    nlohmann::json addressTableData(item.at("IPv4"));
                    protoTableData["dhcp"]    = addressTableData.at("dhcp");
                    protoTableData["metric"]  = addressTableData.at("metric");

                    // "dbsync_network_address" table data to update and notify
                    addressTableData["iface"]     = item.at("name");
                    addressTableData["proto"]     = 0;
                    addressTableData["checksum"]  = getItemChecksum(addressTableData);
                    addressTableData["item_id"]   = getItemId(addressTableData, NETADDRESS_ITEM_ID_FIELDS);
                    addressTableDataList.push_back(addressTableData);
                }

                if (item.find("IPv6") != item.end())
                {
                    nlohmann::json addressTableData(item.at("IPv6"));
                    protoTableData["dhcp"]    = addressTableData.at("dhcp");
                    protoTableData["metric"]  = addressTableData.at("metric");

                    // "dbsync_network_address" table data to update and notify
                    addressTableData["iface"]     = item.at("name");
                    addressTableData["proto"]     = 1;
                    addressTableData["checksum"]  = getItemChecksum(addressTableData);
                    addressTableData["item_id"]   = getItemId(addressTableData, NETADDRESS_ITEM_ID_FIELDS);
                    addressTableDataList.push_back(addressTableData);
                }
                protoTableData["checksum"]  = getItemChecksum(protoTableData);
                protoTableData["item_id"]   = getItemId(protoTableData, NETPROTO_ITEM_ID_FIELDS);
                protoTableDataList.push_back(protoTableData);
            }
            ret[NET_IFACE_TABLE] = ifaceTableDataList;
            ret[NET_PROTOCOL_TABLE] = protoTableDataList;
            ret[NET_ADDRESS_TABLE] = addressTableDataList;
        }
    }
    return ret;
}

void Syscollector::scanNetwork()
{
    if (m_network)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting network scan");
        const auto& networkData{getNetworkData()};
        if (!networkData.is_null())
        {
            const auto itIface { networkData.find(NET_IFACE_TABLE) };
            if (itIface != networkData.end())
            {
                updateAndNotifyChanges(NET_IFACE_TABLE, itIface.value());
            }
            const auto itProtocol { networkData.find(NET_PROTOCOL_TABLE) };
            if (itProtocol != networkData.end())
            {
                updateAndNotifyChanges(NET_PROTOCOL_TABLE, itProtocol.value());
            }
            const auto itAddress { networkData.find(NET_ADDRESS_TABLE) };
            if (itAddress != networkData.end())
            {
                updateAndNotifyChanges(NET_ADDRESS_TABLE, itAddress.value());
            }
        }
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending network scan");
    }
}

void Syscollector::syncNetwork()
{
    if (m_network)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETIFACE_START_CONFIG_STATEMENT), m_reportSyncFunction);
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETPROTO_START_CONFIG_STATEMENT), m_reportSyncFunction);
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETADDRESS_START_CONFIG_STATEMENT), m_reportSyncFunction);
    }
}

nlohmann::json Syscollector::getPackagesData()
{
    nlohmann::json ret;
    nlohmann::json packagesList;
    nlohmann::json hotfixesList;
    const auto& packagesData { m_spInfo->packages() };

    if (!packagesData.is_null())
    {
        const auto& normalizedPackagesData
        {
            m_spNormalizer->normalize("packages", m_spNormalizer->removeExcluded("packages", packagesData))
        };
        for (auto item : normalizedPackagesData)
        {
            item["checksum"] = getItemChecksum(item);
            if(item.find("hotfix") != item.end())
            {
                hotfixesList.push_back(item);
            }
            else
            {
                const auto itemId{ getItemId(item, PACKAGES_ITEM_ID_FIELDS) };
                const auto it
                {
                    std::find_if
                    (
                        packagesList.begin(), packagesList.end(),
                        [&itemId](const auto& elem)
                        {
                            return elem.at("item_id") == itemId;
                        }
                    )
                };
                if(packagesList.end() == it)
                {
                    item["item_id"] = itemId;
                    packagesList.push_back(item);
                }
            }
        }
        ret[HOTFIXES_TABLE] = hotfixesList;
        ret[PACKAGES_TABLE] = packagesList;
    }
    return ret;
}

void Syscollector::scanPackages()
{
    if (m_packages)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting packages scan");
        const auto& packagesData { getPackagesData() };
        if (!packagesData.is_null())
        {
            const auto itPackages { packagesData.find(PACKAGES_TABLE) };
            if (itPackages != packagesData.end())
            {
                updateAndNotifyChanges(PACKAGES_TABLE, itPackages.value());
            }
            if (m_hotfixes)
            {
                const auto itHotFixes { packagesData.find(HOTFIXES_TABLE) };
                if (itHotFixes != packagesData.end())
                {
                    updateAndNotifyChanges(HOTFIXES_TABLE, itHotFixes.value());
                }
            }
        }
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending packages scan");
    }
}

void Syscollector::syncPackages()
{
    if (m_packages)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PACKAGES_START_CONFIG_STATEMENT), m_reportSyncFunction);
        if (m_hotfixes)
        {
            m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(HOTFIXES_START_CONFIG_STATEMENT), m_reportSyncFunction);
        }
    }
}

nlohmann::json Syscollector::getPortsData()
{
    nlohmann::json ret;
    constexpr auto PORT_LISTENING_STATE { "listening" };
    constexpr auto TCP_PROTOCOL { "tcp" };
    const auto& data { m_spInfo->ports() };

    if (!data.is_null())
    {
        const auto& itPorts { data.find("ports") };

        if (data.end() != itPorts)
        {
            for (auto item : itPorts.value())
            {
                const auto isListeningState { item.at("state") == PORT_LISTENING_STATE };
                if(isListeningState)
                {
                    item["checksum"] = getItemChecksum(item);
                    item["item_id"] = getItemId(item, PORTS_ITEM_ID_FIELDS);
                    // Only update and notify "Listening" state ports
                    if (m_portsAll)
                    {
                        // TCP and UDP ports
                        ret.push_back(item);
                    }
                    else
                    {
                        // Only TCP ports
                        const auto isTCPProto { item.at("protocol") == TCP_PROTOCOL };
                        if (isTCPProto)
                        {
                            ret.push_back(item);
                        }
                    }
                }
            }
        }
    }
    return ret;
}

void Syscollector::scanPorts()
{
    if (m_ports)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting ports scan");
        const auto& portsData { getPortsData() };
        updateAndNotifyChanges(PORTS_TABLE, portsData);
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending ports scan");
    }
}

void Syscollector::syncPorts()
{
    if (m_ports)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PORTS_START_CONFIG_STATEMENT), m_reportSyncFunction);
    }
}

nlohmann::json Syscollector::getProcessesData()
{
    nlohmann::json ret;
    const auto& processes{m_spInfo->processes()};
    if (!processes.is_null())
    {
        for (auto item : processes)
        {
            item["checksum"] = getItemChecksum(item);
            ret.push_back(item);
        }
    }
    return ret;
}

void Syscollector::scanProcesses()
{
    if (m_processes)
    {
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Starting processes scan");
        const auto& processesData{getProcessesData()};
        updateAndNotifyChanges(PROCESSES_TABLE, processesData);
        m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Ending processes scan");
    }
}

void Syscollector::syncProcesses()
{
    if (m_processes)
    {
        m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PROCESSES_START_CONFIG_STATEMENT), m_reportSyncFunction);
    }
}

void Syscollector::scan()
{
    m_logFunction(SYS_LOG_INFO, "Starting evaluation.");
    m_scanTime = Utils::getCurrentTimestamp();
    TRY_CATCH_TASK(scanHardware);
    TRY_CATCH_TASK(scanOs);
    TRY_CATCH_TASK(scanNetwork);
    TRY_CATCH_TASK(scanPackages);
    TRY_CATCH_TASK(scanPorts);
    TRY_CATCH_TASK(scanProcesses);
    m_notify = true;
    m_logFunction(SYS_LOG_INFO, "Evaluation finished.");
}

void Syscollector::sync()
{
    m_logFunction(SYS_LOG_DEBUG, "Starting syscollector sync");
    TRY_CATCH_TASK(syncHardware);
    TRY_CATCH_TASK(syncOs);
    TRY_CATCH_TASK(syncNetwork);
    TRY_CATCH_TASK(syncPackages);
    TRY_CATCH_TASK(syncPorts);
    TRY_CATCH_TASK(syncProcesses);
    m_logFunction(SYS_LOG_DEBUG, "Ending syscollector sync");
}

void Syscollector::syncLoop(std::unique_lock<std::mutex>& lock)
{
    m_logFunction(SYS_LOG_INFO, "Module started.");
    if (m_scanOnStart)
    {
        scan();
        sync();
    }
    while(!m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&](){return m_stopping;}))
    {
        scan();
        sync();
    }
    m_spRsync.reset(nullptr);
    m_spDBSync.reset(nullptr);
}

void Syscollector::push(const std::string& data)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    if (!m_stopping)
    {
        auto rawData{data};
        Utils::replaceFirst(rawData, "dbsync ", "");
        const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};
        try
        {
            m_spRsync->pushMessage(std::vector<uint8_t>{buff, buff + rawData.size()});
            m_logFunction(SYS_LOG_DEBUG_VERBOSE, "Message pushed: " + data);
        }
        // LCOV_EXCL_START
        catch(const std::exception& ex)
        {
            m_logFunction(SYS_LOG_ERROR, ex.what());
        }
    }
    // LCOV_EXCL_STOP
}