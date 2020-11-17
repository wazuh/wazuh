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
#include "commonDefs.h"
#include "dbsync.hpp"
#include "rsync.hpp"

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED Syscollector final
{
public:
    static Syscollector& instance()
    {
        static Syscollector s_instance;
        return s_instance;
    }

    void init(const std::shared_ptr<ISysInfo>& spInfo,
              const std::function<void(const std::string&)> reportFunction,
              const unsigned int inverval = 3600ul,
              const bool scanOnStart = true,
              const bool hardware = true,
              const bool os = true,
              const bool network = true,
              const bool packages = true,
              const bool ports = true,
              const bool portsAll = true,
              const bool processes = true,
              const bool hotfixes = true);

    void destroy();
private:
    Syscollector() = default;
    ~Syscollector() = default;
    Syscollector(const Syscollector&) = delete;
    Syscollector& operator=(const Syscollector&) = delete;
    
    std::string getCreateStatement() const;
    bool sleepFor();
    void scanHardware();
    void scanOs();
    void scanNetwork();
    void scanPackages();
    void scanPorts();
    void scanProcesses();
    void scan();
    void syncLoop();
    std::shared_ptr<ISysInfo>                      m_spInfo;
    std::function<void(const std::string&)>        m_reportFunction;
    unsigned int                                   m_intervalValue;
    bool                                           m_scanOnStart;
    bool                                           m_hardware;
    bool                                           m_os;
    bool                                           m_network;
    bool                                           m_packages;
    bool                                           m_ports;
    bool                                           m_portsAll;
    bool                                           m_processes;
    bool                                           m_hotfixes;
    bool                                           m_running;
    std::unique_ptr<DBSync>                        m_dbSync;
    RemoteSync                                     m_rsync;
    std::condition_variable                        m_cv;
    std::mutex                                     m_mutex;
};


#endif //_SYSCOLLECTOR_IMP_H