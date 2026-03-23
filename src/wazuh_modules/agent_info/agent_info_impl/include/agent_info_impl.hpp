#pragma once

#include "iagent_sync_protocol.hpp"
#include "sysInfoInterface.h"

#include <commonDefs.h>
#include <idbsync.hpp>
#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include <ipersistent_queue.hpp>

#include <json.hpp>

#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

// Type definition for module query callback function
// Returns 0 on success, -1 on error. Response must be freed by caller.
using module_query_callback_t = std::function<int(const std::string& module_name, const std::string& query, char** response)>;

class AgentInfoImpl
{
    public:
        /// @brief Structure to represent a module query response
        struct ModuleResponse
        {
            bool success;              ///< True if operation succeeded (error code 0)
            std::string response;      ///< Raw response string
            int errorCode;             ///< Parsed error code (0 if success)
            bool isModuleUnavailable;  ///< True if error indicates module is unavailable (50-53)
        };

        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param reportDiffFunction Function to report stateless diffs
        /// @param logFunction Function to log messages
        /// @param queryModuleFunction Function to query other modules
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param sysInfo Pointer to ISysInfo for system information gathering
        /// @param fileIO Pointer to IFileIOUtils for file I/O operations
        /// @param fileSystem Pointer to IFileSystemWrapper for file system operations
        AgentInfoImpl(std::string dbPath,
                      std::function<void(const std::string&)> reportDiffFunction = nullptr,
                      std::function<void(const modules_log_level_t, const std::string&)> logFunction = nullptr,
                      module_query_callback_t queryModuleFunction = nullptr,
                      std::shared_ptr<IDBSync> dbSync = nullptr,
                      std::shared_ptr<ISysInfo> sysInfo = nullptr,
                      std::shared_ptr<IFileIOUtils> fileIO = nullptr,
                      std::shared_ptr<IFileSystemWrapper> fileSystem = nullptr);
        ~AgentInfoImpl();

        void start(int interval, int integrityInterval = 86400, std::function<bool()> shouldContinue = nullptr);
        void stop();

        /// @brief Initialize the synchronization protocol with only in-memory synchronization
        /// @param moduleName Name of the module
        /// @param mqFuncs Message queue functions
        void initSyncProtocol(const std::string& moduleName, const MQ_Functions& mqFuncs);

        /// @brief Set synchronization parameters
        /// @param syncEndDelay Delay for synchronization end message in seconds
        /// @param timeout Response timeout in seconds
        /// @param retries Number of retries
        /// @param maxEps Maximum events per second
        void setSyncParameters(uint32_t syncEndDelay, uint32_t timeout, uint32_t retries, long maxEps);

        /// @brief Parse sync protocol response buffer
        /// @param data Pointer to the response data buffer
        /// @param length Size of the response data buffer
        /// @return true if parsing succeeds, false otherwise
        bool parseResponseBuffer(const uint8_t* data, size_t length);

        /// @brief Process a database event and emit notifications
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        void processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);

        /// @brief Convert data to ECS format
        /// @param data Original data
        /// @param table Table name
        /// @return ECS-formatted data
        nlohmann::json ecsData(const nlohmann::json& data, const std::string& table) const;

    private:
        /// @brief Determine if a stateless event should be generated based on changed fields
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        /// @return true if stateless event should be generated, false otherwise
        bool shouldGenerateStatelessEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table) const;

        /// @brief Categorize metadata changes to determine sync flag routing
        /// Sets m_clusterNameChanged as side effect; returns true if non-cluster metadata changed
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data from DBSync callback
        /// @return true if non-cluster-name, non-cluster-node metadata changed
        bool categorizeMetadataChanges(ReturnTypeCallback result, const nlohmann::json& data);

        /// @brief Update the global metadata provider with current agent metadata
        /// @param agentMetadata Agent metadata JSON
        /// @param groups List of agent groups
        void updateMetadataProvider(const nlohmann::json& agentMetadata, const std::vector<std::string>& groups);

        /// @brief Coordinate modules for version synchronization
        /// This method manages the coordination process: pause, flush, sync versions, set version, sync table, resume
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return true if coordination was successful, false otherwise
        bool coordinateModules(const std::string& table);

        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief Populate agent metadata table
        void populateAgentMetadata();

        /// @brief Read agent ID and name from client.keys file
        /// @param agentId Output parameter for agent ID
        /// @param agentName Output parameter for agent name
        /// @return true if successful, false otherwise
        bool readClientKeys(std::string& agentId, std::string& agentName) const;

        /// @brief Read agent groups from merged.mg file
        /// @return Vector of group names
        std::vector<std::string> readAgentGroups() const;

        /// @brief Update changes in database and emit events
        /// @param table Table name
        /// @param values Values to sync
        /// @return true if changes detected, false otherwise
        bool updateChanges(const std::string& table, const nlohmann::json& values);

        /// @brief Update db_metadata table with current in-memory state
        void updateDbMetadata();

        /// @brief Set sync flag in database for a specific table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @param value Flag value (true/false)
        void setSyncFlag(const std::string& table, bool value);

        /// @brief Load sync flags from database to memory
        void loadSyncFlags();

        /// @brief Reset sync flag for a specific table in database and memory
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        void resetSyncFlag(const std::string& table);

        /// @brief Check if integrity check should be performed for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @param integrityInterval Integrity check interval in seconds
        /// @return true if integrity check should be performed
        bool shouldPerformIntegrityCheck(const std::string& table, int integrityInterval);

        /// @brief Update last integrity check time for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        void updateLastIntegrityTime(const std::string& table);

        /// @brief Perform delta synchronization for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return true if successful
        bool performDeltaSync(const std::string& table);

        /// @brief Perform integrity check synchronization for a table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @return true if successful
        bool performIntegritySync(const std::string& table);

        /// @brief Helper to create JSON command messages
        /// @param command Command name
        /// @param params Optional parameters map
        /// @return JSON command string
        std::string createJsonCommand(const std::string& command,
                                      const std::map<std::string, nlohmann::json>& params = {}) const;

        /// @brief Helper to query module with retries and error handling
        /// @param moduleName Module name
        /// @param jsonMessage JSON message to send
        /// @return Module response with parsed information
        ModuleResponse queryModuleWithRetry(const std::string& moduleName, const std::string& jsonMessage);

        /// @brief Helper to resume all paused modules
        /// @param pausedModules Set of paused module names to resume
        void resumePausedModules(const std::set<std::string>& pausedModules);

        /// @brief Poll FIM module for pause completion
        /// @param moduleName Module name (should be FIM)
        /// @return true if pause completed successfully, false otherwise
        bool pollFimPauseCompletion(const std::string& moduleName);

        /// @brief Poll FIM module for flush completion
        /// @param moduleName Module name (should be FIM)
        /// @return true if flush completed successfully, false otherwise
        bool pollFimFlushCompletion(const std::string& moduleName);

        /// @brief Pause all coordination modules
        /// @param pausedModules Output parameter for successfully paused modules
        /// @return true if at least one module was paused successfully
        bool pauseCoordinationModules(std::set<std::string>& pausedModules);

        /// @brief Flush all paused modules
        /// @param pausedModules Set of paused modules to flush
        /// @return true if all flushes succeeded, false otherwise
        bool flushPausedModules(const std::set<std::string>& pausedModules);

        /// @brief Get versions from all paused modules and calculate new version
        /// @param pausedModules Set of paused modules
        /// @param incrementVersion Whether to increment version (true for metadata, false for groups)
        /// @param moduleVersions Output parameter for module versions
        /// @return Calculated new version, or -1 on error
        int calculateNewVersion(const std::set<std::string>& pausedModules,
                                bool incrementVersion,
                                std::map<std::string, int>& moduleVersions);

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Pointer to ISysInfo for system information gathering
        std::shared_ptr<ISysInfo> m_sysInfo;

        /// @brief Pointer to IFileIOUtils for file I/O operations
        std::shared_ptr<IFileIOUtils> m_fileIO;

        /// @brief Pointer to IFileSystemWrapper for file system operations
        std::shared_ptr<IFileSystemWrapper> m_fileSystem;

        /// @brief Function to report stateless diffs
        std::function<void(const std::string&)> m_reportDiffFunction;

        /// @brief Function to log messages
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;

        /// @brief Function to query other modules
        module_query_callback_t m_queryModuleFunction;

        /// @brief Sync protocol for agent synchronization
        std::unique_ptr<IAgentSyncProtocol> m_spSyncProtocol;

        /// @brief Sync configuration: delay for synchronization end message in seconds
        uint32_t m_syncEndDelay = 1;

        /// @brief Sync configuration: response timeout in seconds
        uint32_t m_syncResponseTimeout = 30;

        /// @brief Sync configuration: number of retries
        uint32_t m_syncRetries = 5;

        /// @brief Sync configuration: maximum events per second
        long m_syncMaxEps = 10;

        /// @brief Flag to track if module has been stopped
        bool m_stopped = false;

        /// @brief Condition variable for efficient sleep/wake mechanism
        std::condition_variable m_cv;

        /// @brief Mutex for condition variable synchronization
        std::mutex m_mutex;

        /// @brief Flag indicating if metadata needs to be synchronized
        bool m_shouldSyncMetadata = false;

        /// @brief Flag indicating if groups need to be synchronized
        bool m_shouldSyncGroups = false;

        /// @brief Last metadata integrity check timestamp (Unix epoch seconds)
        int64_t m_lastMetadataIntegrity = 0;

        /// @brief Last groups integrity check timestamp (Unix epoch seconds)
        int64_t m_lastGroupsIntegrity = 0;

        /// @brief Flag indicating if this is the first run (database just created)
        bool m_isFirstRun = true;

        /// @brief Flag indicating if this is the first groups run (first population with data)
        bool m_isFirstGroupsRun = true;

        /// @brief Mutex for synchronizing access to sync flags
        std::mutex m_syncFlagsMutex;

        /// @brief Mutex for synchronizing access to m_dBSync (prevents race conditions during cleanup/transactions)
        std::mutex m_dbSyncMutex;

        /// @brief Flag set during updateChanges callback when cluster_name changed
        bool m_clusterNameChanged = false;
};
