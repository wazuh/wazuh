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
#include <optional>

#include "sysInfoInterface.h"
#include "commonDefs.h"
#include "dbsync.hpp"
#include "syscollectorNormalizer.hpp"
#include "syscollector.h"
#include "iagent_sync_protocol.hpp"

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
                  const std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> persistDiffFunction,
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
                  const bool users = true,
                  const bool services = true,
                  const bool browserExtensions = true,
                  const bool notifyOnFirstScan = false);

        void start();
        void destroy();

        // Sync protocol methods
        void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, MQ_Functions mqFuncs);
        bool syncModule(Mode mode, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version);
        bool parseResponseBuffer(const uint8_t* data, size_t length);
        bool notifyDataClean(const std::vector<std::string>& indices, std::chrono::seconds timeout, unsigned int retries, size_t maxEps);
        void deleteDatabase();
        std::string query(const std::string& jsonQuery);
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
        nlohmann::json getUsersData();
        nlohmann::json getServicesData();
        nlohmann::json getBrowserExtensionsData();

        std::pair<nlohmann::json, uint64_t> ecsData(const nlohmann::json& data, const std::string& table, bool createFields = true);
        nlohmann::json ecsSystemData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsHardwareData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsHotfixesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsPackageData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsProcessesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsPortData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkInterfaceData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkProtocolData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsNetworkAddressData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsUsersData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsGroupsData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsServicesData(const nlohmann::json& originalData, bool createFields = true);
        nlohmann::json ecsBrowserExtensionsData(const nlohmann::json& originalData, bool createFields = true);

        std::string getPrimaryKeys(const nlohmann::json& data, const std::string& table);
        std::string calculateHashId(const nlohmann::json& data, const std::string& table);
        nlohmann::json addPreviousFields(nlohmann::json& current, const nlohmann::json& previous);

        void updateChanges(const std::string& table,
                           const nlohmann::json& values);
        void notifyChange(ReturnTypeCallback result,
                          const nlohmann::json& data,
                          const std::string& table);
        void processEvent(ReturnTypeCallback result,
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
        void scanUsers();
        void scanServices();
        void scanBrowserExtensions();
        void scan();
        void syncLoop(std::unique_lock<std::mutex>& lock);

        void setJsonField(nlohmann::json& target,
                          const nlohmann::json& source,
                          const std::string& keyPath,
                          const std::string& jsonKey,
                          bool createFields,
                          bool is_boolean = false);
        void setJsonFieldArray(nlohmann::json& target,
                               const nlohmann::json& source,
                               const std::string& destPath,
                               const std::string& sourceKey,
                               bool createFields);

        std::shared_ptr<ISysInfo>                                                m_spInfo;
        std::function<void(const std::string&)>                                  m_reportDiffFunction;
        std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> m_persistDiffFunction;
        std::function<void(const modules_log_level_t, const std::string&)>       m_logFunction;
        unsigned int                                                             m_intervalValue;
        bool                                                                     m_scanOnStart;
        bool                                                                     m_hardware;
        bool                                                                     m_os;
        bool                                                                     m_network;
        bool                                                                     m_packages;
        bool                                                                     m_ports;
        bool                                                                     m_portsAll;
        bool                                                                     m_processes;
        bool                                                                     m_hotfixes;
        bool                                                                     m_stopping;
        bool                                                                     m_initialized;
        bool                                                                     m_notify;
        bool                                                                     m_groups;
        bool                                                                     m_users;
        bool                                                                     m_services;
        bool                                                                     m_browserExtensions;
        std::unique_ptr<DBSync>                                                  m_spDBSync;
        std::condition_variable                                                  m_cv;
        std::mutex                                                               m_mutex;
        std::unique_ptr<SysNormalizer>                                           m_spNormalizer;
        std::unique_ptr<IAgentSyncProtocol>                                      m_spSyncProtocol;
};


#endif //_SYSCOLLECTOR_HPP
