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
#include <iostream>
#include "syscollectorImp.h"
#include "stringHelper.h"
#include "hashHelper.h"

constexpr auto HOTFIXES_SQL_STATEMENT
{
    R"(CREATE TABLE hotfixes(
    hotfix TEXT,
    checksum TEXT,
    PRIMARY KEY (hotfix)) WITHOUT ROWID;)"
};

constexpr auto HOTFIXES_START_CONFIG_STATEMENT
{
    R"({"table":"hotfixes",
        "first_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix ASC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["hotfix"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"hotfix DESC",
                "count_opt":1
            },
        "component":"hotfixes",
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
    R"(CREATE TABLE packages(
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
    checksum TEXT,
    PRIMARY KEY (name,version,architecture)) WITHOUT ROWID;)"
};

constexpr auto PACKAGES_START_CONFIG_STATEMENT
{
    R"({"table":"packages",
        "first_query":
            {
                "column_list":["name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"name ASC",
                "count_opt":1
            },
        "last_query":
            {
                "column_list":["name"],
                "row_filter":" ",
                "distinct_opt":false,
                "order_by_opt":"name DESC",
                "count_opt":1
            },
        "component":"packages",
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
    R"(CREATE TABLE processes (
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
    PRIMARY KEY (pid));)"
};

constexpr auto PROCESSES_START_CONFIG_STATEMENT
{
    R"({"table":"processes",
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
        "component":"processes",
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

static void updateAndNotifyChanges(const DBSYNC_HANDLE handle,
                                   const std::string& table,
                                   const nlohmann::json& values,
                                   const std::function<void(const std::string&)> reportFunction)
{
    const std::map<ReturnTypeCallback, std::string> operationsMap
    {
        // LCOV_EXCL_START
        {MODIFIED, "MODIFIED"},
        {DELETED , "DELETED "},
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

bool Syscollector::sleepFor()
{
    bool ret{false};
    std::unique_lock<std::mutex> lock{m_mutex};
    if (m_intervalUnit == "s")
    {
        ret = !m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&](){return m_running;});
    }
    else if (m_intervalUnit == "m")
    {
        ret = !m_cv.wait_for(lock, std::chrono::minutes{m_intervalValue}, [&](){return m_running;});
    }
    else if (m_intervalUnit == "h")
    {
        ret = !m_cv.wait_for(lock, std::chrono::hours{m_intervalValue}, [&](){return m_running;});
    }
    else if (m_intervalUnit == "d")
    {
        const auto daysToHours{m_intervalValue * 24ul};
        ret = !m_cv.wait_for(lock, std::chrono::hours{daysToHours}, [&](){return m_running;});
    }
    else
    {
        ret = !m_cv.wait_for(lock, std::chrono::hours{1}, [&](){return m_running;});
    }
    return ret;
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
    return ret;
}

Syscollector::Syscollector(const std::shared_ptr<ISysInfo>& spInfo,
                           const std::function<void(const std::string&)> reportFunction,
                           const std::string& interval,
                           const bool scanOnStart,
                           const bool hardware,
                           const bool os,
                           const bool network,
                           const bool packages,
                           const bool ports,
                           const bool portsAll,
                           const bool processes,
                           const bool hotfixes)
: m_spInfo{spInfo}
, m_reportFunction{reportFunction}
, m_intervalUnit{interval.back()}
, m_intervalValue{std::stoull(interval)}
, m_scanOnStart{scanOnStart}
, m_hardware{hardware}
, m_os{os}
, m_network{network}
, m_packages{packages}
, m_ports{ports}
, m_portsAll{portsAll}
, m_processes{processes}
, m_hotfixes{hotfixes}
, m_running{false}
, m_dbSync{HostType::AGENT, DbEngineType::SQLITE3, "syscollector.db", getCreateStatement()}
, m_thread{std::bind(&Syscollector::syncThread, this)}
{
}

Syscollector::~Syscollector()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    m_running = true;
    m_cv.notify_all();
    lock.unlock();
    if (m_thread.joinable())
    {
        m_thread.join();
    }
}
void Syscollector::scanHardware()
{
    if (m_hardware)
    {
        nlohmann::json msg;
        msg["type"] = "hardware";
        msg["operation"] = "MODIFIED";
        msg["data"] = m_spInfo->hardware();
        m_reportFunction(msg.dump());
    }
}
void Syscollector::scanOs()
{
    if(m_os)
    {
        nlohmann::json msg;
        msg["type"] = "os";
        msg["operation"] = "MODIFIED";
        msg["data"] = m_spInfo->os();
        m_reportFunction(msg.dump());
    }
}
void Syscollector::scanNetwork()
{
    if (m_network)
    {
        const auto& networks{m_spInfo->networks()};
        std::cout << networks.dump() << std::endl;
    }
}
void Syscollector::scanPackages()
{
    if (m_packages)
    {
        constexpr auto tablePackages{"packages"};
        nlohmann::json packages;
        nlohmann::json hotfixes;
        for (const auto& item : m_spInfo->packages())
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
                packages.push_back(item);
            }
        }
        updateAndNotifyChanges(m_dbSync.handle(), tablePackages, packages, m_reportFunction);
        m_rsync.startSync(m_dbSync.handle(), nlohmann::json::parse(PACKAGES_START_CONFIG_STATEMENT), m_reportFunction);
        if (m_hotfixes)
        {
            constexpr auto tableHotfixes{"hotfixes"};
            updateAndNotifyChanges(m_dbSync.handle(), tableHotfixes, hotfixes, m_reportFunction);
            m_rsync.startSync(m_dbSync.handle(), nlohmann::json::parse(HOTFIXES_START_CONFIG_STATEMENT), m_reportFunction);
        }
    }
}
void Syscollector::scanPorts()
{
    if (m_ports)
    {
        const auto& ports{m_spInfo->ports()};
        std::cout << ports.dump() << std::endl;
        if (m_portsAll)
        {
        }
    }
}

void Syscollector::scanProcesses()
{
    if (m_processes)
    {
        constexpr auto table{"processes"};
        updateAndNotifyChanges(m_dbSync.handle(), table, m_spInfo->processes(), m_reportFunction);
        m_rsync.startSync(m_dbSync.handle(), nlohmann::json::parse(PROCESSES_START_CONFIG_STATEMENT), m_reportFunction);
    }
}

void Syscollector::scan()
{
    scanHardware();
    scanOs();
    scanNetwork();
    scanPackages();
    scanPorts();
    scanProcesses();
}

void Syscollector::syncThread()
{
    if (m_scanOnStart)
    {
        scan();
    }
    while(sleepFor())
    {
        scan();
        //sync Rsync
    }
}