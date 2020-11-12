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
#include "syscollectorImp.h"
#include <iostream>

constexpr auto PACKAGES_SQL_STATEMENT
{
    R"(CREATE TABLE packages(
    `name` TEXT,
    `version` TEXT,
    `vendor` TEXT,
    `install_time` TEXT,
    `location` TEXT,
    `architecture` TEXT,
    `groups` TEXT,
    `description` TEXT,
    `size` TEXT,
    `priority` TEXT,
    `multiarch` TEXT,
    `source` TEXT,
    `checksum` TEXT,
    PRIMARY KEY (`name`,'version','architecture')) WITHOUT ROWID;)"
};
constexpr auto PROCESSES_SQL_STATEMENT
{
    R"(CREATE TABLE IF NOT EXISTS processes (
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
    PRIMARY KEY (pid));)"
};

static void updateAndNotifyChanges(const DBSYNC_HANDLE handle, const std::string& table, const nlohmann::json& values)
{
    const std::map<ReturnTypeCallback, std::string> operationsMap
    {
        {MODIFIED, "MODIFIED"},
        {DELETED , "DELETED "},
        {INSERTED, "INSERTED"},
        {MAX_ROWS, "MAX_ROWS"},
        {DB_ERROR, "DB_ERROR"},
        {SELECTED, "SELECTED"},
    };
    constexpr auto queueSize{4096};
    const auto callback
    {
        [&table, &operationsMap](ReturnTypeCallback result, const nlohmann::json& data)
        {
            if (data.is_array())
            {
                for (const auto& item : data)
                {
                    nlohmann::json msg;
                    msg["type"] = table;
                    msg["operation"] = operationsMap.at(result);
                    msg["data"] = item;
                    std::cout << msg.dump() << std::endl;
                }
            }
            else
            {
                nlohmann::json msg;
                msg["type"] = table;
                msg["operation"] = operationsMap.at(result);
                msg["data"] = data;
                std::cout << msg.dump() << std::endl;
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
    }
    if (m_processes)
    {
        ret += PROCESSES_SQL_STATEMENT;
    }
    return ret;
}

Syscollector::Syscollector(const std::shared_ptr<ISysInfo>& spInfo,
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
        const auto& hw{m_spInfo->hardware()};
        std::cout << hw.dump() << std::endl;
    }
}
void Syscollector::scanOs()
{
    if(m_os)
    {
        const auto& os{m_spInfo->os()};
        std::cout << os.dump() << std::endl;
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
    constexpr auto table{"packages"};
    updateAndNotifyChanges(m_dbSync.handle(), table, m_spInfo->packages());
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
    constexpr auto table{"processes"};
    updateAndNotifyChanges(m_dbSync.handle(), table, m_spInfo->processes());
}

void Syscollector::scan()
{
    scanHardware();
    scanOs();
    scanNetwork();
    if (m_packages)
    {
        scanPackages();
    }
    scanPorts();
    if (m_processes)
    {
        scanProcesses();
    }
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
