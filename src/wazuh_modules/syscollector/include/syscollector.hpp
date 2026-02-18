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
#include <atomic>

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

        using AgentdQueryFunc = std::function<bool(const char*, char*, size_t)>;

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

        /**
         * @brief Set agentd query function for agentd communication (cross-platform)
         *
         * This function is used to send commands to agentd and receive JSON responses.
         * Works on both Unix/Linux (socket) and Windows (agcom_dispatch).
         * Should be set before calling start().
         *
         * @param queryFunc Function to query agentd (returns JSON string or nullptr)
         */
        void setAgentdQueryFunction(AgentdQueryFunc queryFunc);

        void start();
        void destroy();

        // Sync protocol methods
        void initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, const std::string& syncDbPathVD, MQ_Functions mqFuncs, std::chrono::seconds syncEndDelay,
                              std::chrono::seconds timeout, unsigned int retries,
                              size_t maxEps, uint32_t integrityInterval);
        bool syncModule(Mode mode);
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data, uint64_t version, bool isDataContext = false);
        bool parseResponseBuffer(const uint8_t* data, size_t length);
        bool parseResponseBufferVD(const uint8_t* data, size_t length);
        bool notifyDataClean(const std::vector<std::string>& indices);
        void deleteDatabase();
        std::string query(const std::string& jsonQuery);
        bool notifyDisableCollectorsDataClean();
        void deleteDisableCollectorsData();

        // Mutex access for external synchronization (e.g., from wm_sync_module)
        void lockScanMutex();
        void unlockScanMutex();

        // Recovery functions
        void runRecoveryProcess();

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

        /**
         * @brief Fetches all items from a VD table (OS, Packages, or Hotfixes) excluding specified IDs
         * @param tableName Name of the table to query ("dbsync_osinfo", "dbsync_packages", "dbsync_hotfixes")
         * @param excludeIds Set of hash IDs to exclude from results (items already in DataValue)
         * @param forceAll If true, fetch all records regardless of document limits (ignores sync flag)
         * @return Vector of JSON objects representing all rows in the table (excluding specified IDs)
         */
        std::vector<nlohmann::json> fetchAllFromTable(const std::string& tableName, const std::set<std::string>& excludeIds, bool forceAll = false);

        /**
         * @brief Determines which DataContext items to include based on platform-specific rules
         * @param operation The operation type (CREATE, MODIFY, DELETE_)
         * @param index The index being modified (system, packages, hotfixes)
         * @return Vector of table names that should be included as DataContext
         */
        std::vector<std::string> getDataContextTables(Operation operation, const std::string& index);

        /**
         * @brief Checks if the first VD sync has been completed
         * @return true if first VD sync is done, false if this is the first scan (VDFIRST)
         */
        bool isVDFirstSyncDone() const;

        /**
         * @brief Processes VD DataContext after scan completes
         * @details Queries the VD sync protocol database for pending DataValue items,
         *          applies platform-specific rules to determine what DataContext to include,
         *          and submits the DataContext items to the sync protocol
         */
        void processVDDataContext();
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
        void syncLoop(std::unique_lock<std::mutex>& scan_lock);
        bool pause();
        void resume();
        int flush();
        int getMaxVersion();
        int setVersion(int version);

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

        bool hasDataInTable(const std::string& tableName);
        void checkDisabledCollectorsIndicesWithData();
        void clearTablesForIndices(const std::vector<std::string>& indices);
        bool handleNotifyDataClean();

        // Recovery functions
        /**
         * @brief Checks if a full sync is required by calculating the checksum-of-checksums for a table and comparing it with the manager's
         * @param table_name The table to check
         * @returns true if a full sync is required, false if a delta sync is sufficient
         */
        bool checkIfFullSyncRequired(const std::string& tableName);

        /**
         * @brief Get the last_sync_time for a given table.
         *
         * @param tableName Name of the table to query.
         * @return int64_t The last sync timestamp (UNIX format), or 0 if not found.
         */
        int64_t getLastSyncTime(const std::string& tableName);

        /**
         * @brief Update the last_sync_time for a given table.
         *
         * @param tableName Name of the table to update.
         * @param timestamp The sync timestamp to set (UNIX format).
         */
        void updateLastSyncTime(const std::string& tableName, int64_t timestamp);

        /**
         * @brief Check if the integrity interval has elapsed for a given table.
         *
         * @param tableName Name of the table to check.
         * @param integrityInterval Integrity check interval in seconds.
         * @return true if interval has elapsed, false otherwise.
         */
        bool recoveryIntervalHasEllapsed(const std::string& tableName, int64_t integrityInterval);

        /**
         * @brief Validates a JSON message against schema and logs validation errors
         *
         * This helper function encapsulates the common pattern of schema validation
         * used across different parts of syscollector. It validates the message against
         * the schema for the given index and logs detailed error messages if validation fails.
         *
         * @param data JSON string to validate
         * @param index Index name for schema lookup (e.g., "wazuh-states-inventory-packages")
         * @param context Context string for logging (e.g., "table: dbsync_packages")
         * @return true if validation passed or validator not initialized, false if validation failed
         */
        bool validateSchemaAndLog(const std::string& data, const std::string& index, const std::string& context) const;

        /**
         * @brief Deletes failed items from DBSync in a batch transaction
         *
         * This helper function encapsulates the common pattern of deleting items that failed
         * schema validation. It uses a DBSync transaction to ensure all deletions are atomic
         * and properly committed to disk.
         *
         * @param failedItems Vector of (table_name, json_data) pairs to delete
         */
        void deleteFailedItemsFromDB(const std::vector<std::pair<std::string, nlohmann::json>>& failedItems) const;

        /**
         * @brief Updates sync flag for items in database
         *
         * This helper function updates the sync flag (0 or 1) for all items in the vector.
         * It uses a DBSync transaction to ensure all updates are atomic and properly committed to disk.
         *
         * @param itemsToUpdate Vector of (table_name, json_data) pairs to update
         * @param syncValue Value to set for sync flag (0 or 1)
         */
        void updateSyncFlagInDB(const std::vector<std::pair<std::string, nlohmann::json>>& itemsToUpdate, int syncValue) const;

        /**
         * @brief Promotes unsynced items with deterministic ordering
         *
         * Selects up to maxToPromote items with sync=0, ordered by the table's ordering fields
         * (using ORDER BY with COLLATE NOCASE), generates INSERT events, and marks them as sync=1.
         * Used by both setDocumentLimits and promoteItemsAfterScan to avoid code duplication.
         *
         * @param index Index name (e.g., "packages")
         * @param tableName Table name (e.g., "dbsync_packages")
         * @param maxToPromote Maximum number of items to promote
         * @param reason Descriptive reason for logging purposes
         * @return Number of items actually promoted
         */
        size_t promoteUnsyncedItems(const std::string& index,
                                    const std::string& tableName,
                                    size_t maxToPromote,
                                    const std::string& reason);

        /**
         * @brief Promotes items after scan to fill available slots
         *
         * After a scan completes, calculates available space (limit - currentCount) for each index
         * and promotes unsynced items with deterministic ordering to fill those slots.
         * Uses the database as source of truth for current counts (m_documentCounts already reflects deletes).
         * Generates INSERT events for promoted items and marks them as sync=1.
         */
        void promoteItemsAfterScan();

        /**
         * @brief Gets simplified ordering fields for a table
         *
         * Returns the field(s) to use for simplified ordering when managing document limits.
         * Most tables use only the first PK field, but some (like packages) use multiple
         * fields for more stable ordering (e.g., "name, type").
         *
         * @param tableName Name of the table (e.g., "dbsync_packages")
         * @return Ordering field(s) as string (e.g., "name, type"), empty if table unknown
         */
        std::string getFirstPrimaryKeyField(const std::string& tableName) const;

        /**
         * @brief Builds ORDER BY clause with COLLATE NOCASE for case-insensitive ordering
         *
         * Constructs an ORDER BY clause from comma-separated field names with COLLATE NOCASE
         * for case-insensitive ordering. This ensures consistent ordering across different cases.
         *
         * @param fields Comma-separated field names (e.g., "name, type")
         * @param ascending True for ASC order (default), false for DESC order
         * @return ORDER BY clause string (e.g., "name COLLATE NOCASE, type COLLATE NOCASE ASC")
         */
        std::string buildOrderByClause(const std::string& fields, bool ascending = true) const;

        /**
         * @brief Sets document limits for configured indices
         *
         * @param limits JSON object mapping index names to limit values (0 = unlimited)
         * @return true if limits were set successfully, false otherwise
         */
        bool setDocumentLimits(const nlohmann::json& limits);

        /**
         * @brief Fetches document limits from agentd
         *
         * Queries agentd for document limits configuration for the syscollector module.
         * Sends the command "getdoclimits syscollector" to agentd.
         *
         * Works on both Unix/Linux (via socket) and Windows (via agcom_dispatch).
         *
         * If agentd is not available or limits are not configured for
         * syscollector, returns an empty optional.
         *
         * Expected response format from agentd:
         * "ok {\"wazuh-states-inventory-packages\": 10000, ...}"
         *
         * @return Optional JSON with limits if available, empty optional otherwise
         */
        std::optional<nlohmann::json> fetchDocumentLimitsFromAgentd();

        /**
         * @brief Initializes document counts from database for all tables
         */
        void initializeDocumentCounts();

        /**
         * @brief Checks if document limit has been reached for a given table/index
         *
         * @param table Table name to check
         * @param data JSON data for the record
         * @param result Callback result type (INSERTED, MODIFIED, DELETED)
         * @return true if within limit and should process, false if limit reached
         */
        bool checkDocumentLimit(const std::string& table, const nlohmann::json& data, ReturnTypeCallback result);

        std::shared_ptr<ISysInfo>                                                m_spInfo;
        std::function<void(const std::string&)>                                  m_reportDiffFunction;
        std::function<void(const std::string&, Operation_t, const std::string&, const std::string&, uint64_t)> m_persistDiffFunction;
        std::function<void(const modules_log_level_t, const std::string&)>       m_logFunction;

        AgentdQueryFunc                                                          m_agentdQuery;
        unsigned int                                                             m_intervalValue;
        uint32_t                                                                 m_integrityIntervalValue;
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
        std::atomic<bool>                                                        m_paused;
        std::atomic<bool>                                                        m_scanning;
        std::atomic<bool>                                                        m_syncing;
        bool                                                                     m_groups;
        bool                                                                     m_users;
        bool                                                                     m_services;
        bool                                                                     m_browserExtensions;
        unsigned int                                                             m_dataCleanRetries;
        bool                                                                     m_allCollectorsDisabled;
        bool                                                                     m_vdSyncEnabled;
        std::unique_ptr<DBSync>                                                  m_spDBSync;
        std::condition_variable                                                  m_cv;
        std::mutex                                                               m_scan_mutex;
        std::condition_variable                                                  m_pauseCv;
        std::mutex                                                               m_pauseMutex;
        std::unique_ptr<SysNormalizer>                                           m_spNormalizer;
        std::unique_ptr<IAgentSyncProtocol>                                      m_spSyncProtocol;
        std::vector<std::string>                                                 m_disabledCollectorsIndicesWithData;
        std::unique_ptr<IAgentSyncProtocol>                                      m_spSyncProtocolVD;
        std::vector<std::pair<std::string, nlohmann::json>>*                     m_failedItems;  // Pointer to list of items that failed validation (for deferred deletion)
        std::vector<std::pair<std::string, nlohmann::json>>*                     m_itemsToUpdateSync;  // Pointer to list of items that passed limit check (for deferred sync=1 update)

        // Document limits configuration (0 = unlimited)
        std::map<std::string, size_t>                                            m_documentLimits;

        // Current document counts per index (tracks items with sync=1)
        std::map<std::string, size_t>                                            m_documentCounts;

        // Mutex for thread-safe access to limits and counts
        std::mutex                                                               m_limitsMutex;
};


#endif //_SYSCOLLECTOR_HPP
