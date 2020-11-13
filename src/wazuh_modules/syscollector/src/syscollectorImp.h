/*
 * Wazuh SysCollector
 * Copyright (C) 2015-2020, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_IMP_H
#define _SYSCOLLECTOR_IMP_H
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>
#include "sysInfoInterface.h"
#include "json.hpp"
#include "commonDefs.h"
#include "dbsync.hpp"

class Syscollector final
{
public:
    Syscollector(const std::shared_ptr<ISysInfo>& spInfo,
                 const std::string& inverval = "1h",
                 const bool scanOnStart = true,
                 const bool hardware = true,
                 const bool os = true,
                 const bool network = true,
                 const bool packages = true,
                 const bool ports = true,
                 const bool portsAll = true,
                 const bool processes = true,
                 const bool hotfixes = true);
    ~Syscollector();
private:
    std::string getCreateStatement() const;
    bool sleepFor();
    void scanHardware();
    void scanOs();
    void scanNetwork();
    void scanPackages();
    void scanPorts();
    void scanProcesses();
    void scan();
    void syncThread();
    const std::shared_ptr<ISysInfo>                m_spInfo;
    const std::string                              m_intervalUnit;
    const unsigned long long                       m_intervalValue;
    const bool                                     m_scanOnStart;
    const bool                                     m_hardware;
    const bool                                     m_os;
    const bool                                     m_network;
    const bool                                     m_packages;
    const bool                                     m_ports;
    const bool                                     m_portsAll;
    const bool                                     m_processes;
    const bool                                     m_hotfixes;
    bool                                           m_running;
    DBSync                                         m_dbSync;
    std::condition_variable                        m_cv;
    std::mutex                                     m_mutex;
    std::thread                                    m_thread;
};


#endif //_SYSCOLLECTOR_IMP_H