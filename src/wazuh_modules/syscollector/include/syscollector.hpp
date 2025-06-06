/*
 * Wazuh SysCollector
 * Copyright (C) 2015, Wazuh Inc.
 * October 8, 2020.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#ifndef _SYSCOLLECTOR_HPP
#define _SYSCOLLECTOR_HPP
#include <chrono>
#include <thread>
#include <condition_variable>
#include <mutex>
#include <memory>
#include "sysInfoInterface.h"
#include "commonDefs.h"
#include "dbsync.hpp"
#include "rsync.hpp"
#include "syscollectorNormalizer.h"
#include "syscollector.h"

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
                  const std::function<void(const std::string&)> reportDiffFunction,
                  const std::function<void(const std::string&)> reportSyncFunction,
                  const std::function<void(const modules_log_level_t, const std::string&)> logFunction,
                  const std::string& dbPath,
                  const std::string& normalizerConfigPath,
                  const std::string& normalizerType,
                  const unsigned int inverval = 3600ul,
                  const bool scanOnStart = true,
                  const bool hardware = true,
                  const bool os = true,
                  const bool network = true,
                  const bool packages = true,
                  const bool ports = true,
                  const bool portsAll = true,
                  const bool processes = true,
                  const bool hotfixes = true,
                  const bool groups = true,
                  const bool notifyOnFirstScan = false);

        void destroy();
        void push(const std::string& data);
    private:
        Syscollector();
        ~Syscollector() = default;
        Syscollector(const Syscollector&) = delete;
        Syscollector& operator=(const Syscollector&) = delete;

        std::string getCreateStatement() const;
        nlohmann::json getOSData();
        nlohmann::json getHardwareData();
        nlohmann::json getNetworkData();
        nlohmann::json getPortsData();
        nlohmann::json getGroupsData();

        void registerWithRsync();
        void updateChanges(const std::string& table,
                           const nlohmann::json& values);
        void notifyChange(ReturnTypeCallback result,
                          const nlohmann::json& data,
                          const std::string& table);
        void scanHardware();
        void scanOs();
        void scanNetwork();
        void scanPackages();
        void scanHotfixes();
        void scanPorts();
        void scanProcesses();
        void scanGroups();
        void syncOs();
        void syncHardware();
        void syncNetwork();
        void syncPackages();
        void syncHotfixes();
        void syncPorts();
        void syncProcesses();
        void syncGroups();
        void scan();
        void sync();
        void syncLoop(std::unique_lock<std::mutex>& lock);
        std::shared_ptr<ISysInfo>                                               m_spInfo;
        std::function<void(const std::string&)>                                 m_reportDiffFunction;
        std::function<void(const std::string&)>                                 m_reportSyncFunction;
        std::function<void(const modules_log_level_t, const std::string&)>      m_logFunction;
        unsigned int                                                            m_intervalValue;
        bool                                                                    m_scanOnStart;
        bool                                                                    m_hardware;
        bool                                                                    m_os;
        bool                                                                    m_network;
        bool                                                                    m_packages;
        bool                                                                    m_ports;
        bool                                                                    m_portsAll;
        bool                                                                    m_processes;
        bool                                                                    m_hotfixes;
        bool                                                                    m_stopping;
        bool                                                                    m_notify;
        bool                                                                    m_groups;
        std::unique_ptr<DBSync>                                                 m_spDBSync;
        std::unique_ptr<RemoteSync>                                             m_spRsync;
        std::condition_variable                                                 m_cv;
        std::mutex                                                              m_mutex;
        std::unique_ptr<SysNormalizer>                                          m_spNormalizer;
        std::string                                                             m_scanTime;
};


#endif //_SYSCOLLECTOR_HPP
