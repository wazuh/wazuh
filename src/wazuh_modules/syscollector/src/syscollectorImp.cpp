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


#define TRY_CATCH_SCAN(scan)                                            \
do                                                                      \
{                                                                       \
    try                                                                 \
    {                                                                   \
        scan();                                                         \
    }                                                                   \
    catch(const std::exception& ex)                                     \
    {                                                                   \
        if(m_logErrorFunction)                                          \
        {                                                               \
            const std::string error{"scan: " + std::string{ex.what()}}; \
            m_logErrorFunction(error);                                  \
        }                                                               \
    }                                                                   \
}while(0)

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
                "row_filter":" ",
                "column_list":["*"],
                "distinct_opt":false,
                "order_by_opt":""
        },
        "count_range_query_json": {
                "row_filter":"WHERE hotfix BETWEEN '?' and '?' ORDER BY hotfix",
                "count_field_hotfix":"count",
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
    size TEXT,
    priority TEXT,
    multiarch TEXT,
    source TEXT,
    format TEXT,
    checksum TEXT,
    item_id TEXT,
    os_patch TEXT,
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
                "row_filter":" ",
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
                "row_filter":" ",
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
    pid BIGINT,
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
                "row_filter":" ",
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
       PRIMARY KEY (inode, protocol, local_port)) WITHOUT ROWID;)"
};
static const std::vector<std::string> PORTS_ITEM_ID_FIELDS{"inode","protocol","local_port"};

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
                "row_filter":" ",
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
       mtu TEXT,
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
                "row_filter":" ",
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
                "row_filter":" ",
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
       proto TEXT,
       address TEXT,
       netmask TEXT,
       broadcast TEXT,
       checksum TEXT,
       item_id TEXT,
       PRIMARY KEY (iface,proto,address)) WITHOUT ROWID;)"
};
static const std::vector<std::string> NETADDRESS_ITEM_ID_FIELDS{"iface", "proto", "address"};


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

static void updateAndNotifyChanges(const DBSYNC_HANDLE handle,
                                   const std::string& table,
                                   const nlohmann::json& values,
                                   const std::function<void(const std::string&)> reportFunction)
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
        [&table, &operationsMap, reportFunction](ReturnTypeCallback result, const nlohmann::json& data)
        {
            if (data.is_array())
            {
                for (const auto& item : data)
                {
                    nlohmann::json msg;
                    msg["type"] = table;
                    msg["operation"] = operationsMap.at(result);
                    msg["data"] = item;
                    reportFunction(msg.dump());
                }
            }
            else
            {
                // LCOV_EXCL_START
                nlohmann::json msg;
                msg["type"] = table;
                msg["operation"] = operationsMap.at(result);
                msg["data"] = data;
                reportFunction(msg.dump());
                // LCOV_EXCL_STOP
            }
        }
    };
    DBSyncTxn txn
    {
        handle,
        nlohmann::json{table},
        0,
        queueSize,
        callback
    };
    nlohmann::json jsResult;
    nlohmann::json input;
    input["table"] = table;
    input["data"] = values;
    for (auto& item : input["data"])
    {
        const auto content{item.dump()};
        Utils::HashData hash;
        hash.update(content.c_str(), content.size());
        item["checksum"] = Utils::asciiToHex(hash.hash());
    }
    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

std::string Syscollector::getCreateStatement() const
{
    std::string ret;
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

    if (m_processes)
    {
        m_spRsync->registerSyncID("syscollector_processes", 
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PROCESSES_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
    }
    if (m_packages)
    {
        m_spRsync->registerSyncID("syscollector_packages",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PACKAGES_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
        if (m_hotfixes)
        {
            m_spRsync->registerSyncID("syscollector_hotfixes",
                                      m_spDBSync->handle(),
                                      nlohmann::json::parse(HOTFIXES_SYNC_CONFIG_STATEMENT),
                                      m_reportSyncFunction);
        }
    }
    if (m_ports)
    {
        m_spRsync->registerSyncID("syscollector_ports",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(PORTS_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
    }
    if (m_network)
    {
        m_spRsync->registerSyncID("syscollector_network_iface",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETIFACE_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
        m_spRsync->registerSyncID("syscollector_network_protocol",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETPROTO_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
        m_spRsync->registerSyncID("syscollector_network_address",
                                  m_spDBSync->handle(),
                                  nlohmann::json::parse(NETADDRESS_SYNC_CONFIG_STATEMENT),
                                  m_reportSyncFunction);
    }
}
void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
                        const std::function<void(const std::string&)> reportDiffFunction,
                        const std::function<void(const std::string&)> reportSyncFunction,
                        const std::function<void(const std::string&)> logErrorFunction,
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
    m_logErrorFunction = logErrorFunction;
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
    m_running = false;
    m_spDBSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, "syscollector.db", getCreateStatement());
    m_spRsync = std::make_unique<RemoteSync>();
    registerWithRsync();
    syncLoop();
}

void Syscollector::destroy()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_running = true;
    m_cv.notify_all();
    lock.unlock();
}
void Syscollector::scanHardware()
{
    if (m_hardware)
    {
        nlohmann::json msg;
        msg["type"] = "dbsync_hardware";
        msg["operation"] = "MODIFIED";
        msg["data"] = m_spInfo->hardware();
        m_reportDiffFunction(msg.dump());
    }
}
void Syscollector::scanOs()
{
    if(m_os)
    {
        nlohmann::json msg;
        msg["type"] = "dbsync_os";
        msg["operation"] = "MODIFIED";
        msg["data"] = m_spInfo->os();
        m_reportDiffFunction(msg.dump());
    }
}

void Syscollector::scanNetwork()
{
    if (m_network)
    {
        constexpr auto netIfaceTable    { "dbsync_network_iface"    };
        constexpr auto netProtocolTable { "dbsync_network_protocol" };
        constexpr auto netAddressTable  { "dbsync_network_address"  };
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
                    ifaceTableData["tx_dropped"] = item.at("tx_dropped");
                    ifaceTableData["rx_dropped"] = item.at("rx_dropped");
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
                        addressTableData["iface"]   = item.at("name");
                        addressTableData["proto"]   = "IPv4";
                        addressTableDataList.push_back(addressTableData);
                    }

                    if (item.find("IPv6") != item.end())
                    {
                        nlohmann::json addressTableData(item.at("IPv6"));
                        protoTableData["dhcp"]    = addressTableData.at("dhcp");
                        protoTableData["metric"]  = addressTableData.at("metric");

                        // "dbsync_network_address" table data to update and notify
                        addressTableData["iface"] = item.at("name");
                        addressTableData["proto"] = "IPv6";
                        addressTableData["item_id"] = getItemId(addressTableData, NETADDRESS_ITEM_ID_FIELDS);
                        addressTableDataList.push_back(addressTableData);
                    }
                    protoTableData["item_id"] = getItemId(protoTableData, NETPROTO_ITEM_ID_FIELDS);
                    protoTableDataList.push_back(protoTableData);
                }

                updateAndNotifyChanges(m_spDBSync->handle(), netIfaceTable,    ifaceTableDataList, m_reportDiffFunction);
                updateAndNotifyChanges(m_spDBSync->handle(), netProtocolTable, protoTableDataList, m_reportDiffFunction);
                updateAndNotifyChanges(m_spDBSync->handle(), netAddressTable,  addressTableDataList, m_reportDiffFunction);
                m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETIFACE_START_CONFIG_STATEMENT), m_reportSyncFunction);
                m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETPROTO_START_CONFIG_STATEMENT), m_reportSyncFunction);
                m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(NETADDRESS_START_CONFIG_STATEMENT), m_reportSyncFunction);
            }
        }
    }
}

void Syscollector::scanPackages()
{
    if (m_packages)
    {
        constexpr auto tablePackages{"dbsync_packages"};
        nlohmann::json packages;
        nlohmann::json hotfixes;
        const auto& packagesData { m_spInfo->packages() };

        if (!packagesData.is_null())
        {
            for (auto item : packagesData)
            {
                if(item.find("hotfix") != item.end())
                {
                    if (m_hotfixes)
                    {
                        hotfixes.push_back(item);
                    }
                }
                else
                {
                    item["item_id"] = getItemId(item, PACKAGES_ITEM_ID_FIELDS);
                    packages.push_back(item);
                }
            }
            updateAndNotifyChanges(m_spDBSync->handle(), tablePackages, packages, m_reportDiffFunction);
            m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PACKAGES_START_CONFIG_STATEMENT), m_reportSyncFunction);
            if (m_hotfixes)
            {
                constexpr auto tableHotfixes{"dbsync_hotfixes"};
                updateAndNotifyChanges(m_spDBSync->handle(), tableHotfixes, hotfixes, m_reportDiffFunction);
                m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(HOTFIXES_START_CONFIG_STATEMENT), m_reportSyncFunction);
            }
        }
    }
}

void Syscollector::scanPorts()
{
    if (m_ports)
    {
        constexpr auto table{"dbsync_ports"};
        constexpr auto PORT_LISTENING_STATE { "listening" };
        constexpr auto TCP_PROTOCOL { "tcp" };
        const auto& data { m_spInfo->ports() };
        nlohmann::json portsList{};

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
                        // Only update and notify "Listening" state ports
                        if (m_portsAll)
                        {
                            // TCP and UDP ports
                            item["item_id"] = getItemId(item, PORTS_ITEM_ID_FIELDS);
                            portsList.push_back(item);
                        }
                        else
                        {
                            // Only TCP ports
                            const auto isTCPProto { item.at("protocol") == TCP_PROTOCOL };
                            if (isTCPProto)
                            {
                                item["item_id"] = getItemId(item, PORTS_ITEM_ID_FIELDS);
                                portsList.push_back(item);
                            }
                        }
                    }
                }
                updateAndNotifyChanges(m_spDBSync->handle(), table, portsList, m_reportDiffFunction);
                m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PORTS_START_CONFIG_STATEMENT), m_reportSyncFunction);
            }
        }
    }
}

void Syscollector::scanProcesses()
{
    if (m_processes)
    {
        constexpr auto table{"dbsync_processes"};
        const auto& processes{m_spInfo->processes()};
        if (!processes.is_null())
        {
            updateAndNotifyChanges(m_spDBSync->handle(), table, processes, m_reportDiffFunction);
            m_spRsync->startSync(m_spDBSync->handle(), nlohmann::json::parse(PROCESSES_START_CONFIG_STATEMENT), m_reportSyncFunction);
        }
    }
}

void Syscollector::scan()
{
    TRY_CATCH_SCAN(scanHardware);
    TRY_CATCH_SCAN(scanOs);
    TRY_CATCH_SCAN(scanNetwork);
    TRY_CATCH_SCAN(scanPackages);
    TRY_CATCH_SCAN(scanPorts);
    TRY_CATCH_SCAN(scanProcesses);
}

void Syscollector::syncLoop()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    if (m_scanOnStart)
    {
        scan();
    }
    while(!m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&](){return m_running;}))
    {
        scan();
        //sync Rsync
    }
    m_spRsync.reset(nullptr);
    m_spDBSync.reset(nullptr);
}

void Syscollector::push(const std::string& data)
{
    std::unique_lock<std::mutex> lock{m_mutex};
    if (!m_running)
    {
        auto rawData{data};
        Utils::replaceFirst(rawData, "dbsync ", "");
        const auto buff{reinterpret_cast<const uint8_t*>(rawData.c_str())};
        try
        {
            m_spRsync->pushMessage(std::vector<uint8_t>{buff, buff + rawData.size()});
        }
        // LCOV_EXCL_START
        catch(const std::exception& ex)
        {
            m_logErrorFunction(ex.what());
        }
    }
    // LCOV_EXCL_STOP
}
