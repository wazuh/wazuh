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
    PRIMARY KEY (pid));)"
};

constexpr auto OS_SQL_STATEMENT
{
    R"(CREATE TABLE os (
        hostname TEXT,
        architecture TEXT,
        os_name TEXT,
        os_version TEXT,
        os_codename TEXT,
        os_major TEXT,
        os_minor TEXT,
        os_build TEXT,
        os_platform TEXT,
        sysname TEXT,
        release TEXT,
        version TEXT,
        os_release TEXT,
        PRIMARY KEY (os_name)
    );)"
};

constexpr auto HARDWARE_SQL_STATEMENT
{
    R"(CREATE TABLE hardware (
        board_serial TEXT,
        cpu_name TEXT,
        cpu_cores INTEGER CHECK (cpu_cores > 0),
        cpu_mhz BIGINT CHECK (cpu_mhz > 0),
        ram_total BIGINT CHECK (ram_total > 0),
        ram_free BIGINT CHECK (ram_free > 0),
        ram_usage INTEGER CHECK (ram_usage >= 0 AND ram_usage <= 100),
        PRIMARY KEY (board_serial)
    );)"
};

static void updateAndNotifyChanges(const DBSYNC_HANDLE handle, const std::string& table, const nlohmann::json& values)
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
                // LCOV_EXCL_START
                nlohmann::json msg;
                msg["type"] = table;
                msg["operation"] = operationsMap.at(result);
                msg["data"] = data;
                std::cout << msg.dump() << std::endl;
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
    txn.syncTxnRow(input);
    txn.getDeletedRows(callback);
}

bool Syscollector::sleepFor()
{
    std::unique_lock<std::mutex> lock{m_mutex};
    return !m_cv.wait_for(lock, std::chrono::seconds{m_intervalValue}, [&](){return m_running;});;
}

std::string Syscollector::getCreateStatement() const
{
    std::string ret;
    if (m_hardware)
    {
        ret += HARDWARE_SQL_STATEMENT;
    }
    if (m_os)
    {
        ret += OS_SQL_STATEMENT;
    }
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

void Syscollector::init(const std::shared_ptr<ISysInfo>& spInfo,
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
    m_dbSync = std::make_unique<DBSync>(HostType::AGENT, DbEngineType::SQLITE3, "syscollector.db", getCreateStatement());

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
        constexpr auto table{"hardware"};
        updateAndNotifyChanges(m_dbSync->handle(), table, nlohmann::json{m_spInfo->hardware()});
    }
}
void Syscollector::scanOs()
{
    if(m_os)
    {
        constexpr auto table{"os"};
        updateAndNotifyChanges(m_dbSync->handle(), table, nlohmann::json{m_spInfo->os()});
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
        constexpr auto table{"packages"};
        updateAndNotifyChanges(m_dbSync->handle(), table, m_spInfo->packages());
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
        updateAndNotifyChanges(m_dbSync->handle(), table, m_spInfo->processes());
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

void Syscollector::syncLoop()
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
