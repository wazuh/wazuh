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
#include <memory>
#include <mutex>
#include <string>
#include <vector>

// Type definition for module query callback function
// Returns 0 on success, -1 on error. Response must be freed by caller.
using module_query_callback_t = std::function<int(const std::string& module_name, const std::string& query, char** response)>;

class AgentInfoImpl
{
    public:
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

        void start(int interval, std::function<bool()> shouldContinue = nullptr);
        void stop();

        /// @brief Set whether this instance is running on an agent or manager
        /// @param value True if running on an agent, false if on a manager
        void setIsAgent(bool value);

        /// @brief Initialize the synchronization protocol
        /// @param moduleName Name of the module
        /// @param syncDbPath Path to sync database
        /// @param mqFuncs Message queue functions
        void
        initSyncProtocol(const std::string& moduleName, const std::string& syncDbPath, const MQ_Functions& mqFuncs);

        /// @brief Set synchronization parameters
        /// @param timeout Response timeout in seconds
        /// @param retries Number of retries
        /// @param maxEps Maximum events per second
        void setSyncParameters(uint32_t timeout, uint32_t retries, long maxEps);

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

        /// @brief Calculate checksum for metadata
        /// @param metadata Metadata JSON object
        /// @return Checksum string
        std::string calculateMetadataChecksum(const nlohmann::json& metadata) const;

        /// @brief Convert data to ECS format
        /// @param data Original data
        /// @param table Table name
        /// @return ECS-formatted data
        nlohmann::json ecsData(const nlohmann::json& data, const std::string& table) const;

    private:
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
        void updateChanges(const std::string& table, const nlohmann::json& values);

        /// @brief Set sync flag in database for a specific table
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        /// @param value Flag value (true/false)
        void setSyncFlag(const std::string& table, bool value);

        /// @brief Load sync flags from database to memory
        void loadSyncFlags();

        /// @brief Reset sync flag for a specific table in database and memory
        /// @param table Table name (AGENT_METADATA_TABLE or AGENT_GROUPS_TABLE)
        void resetSyncFlag(const std::string& table);

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

        /// @brief True if the module is running on an agent, false if on a manager
        bool m_isAgent = true;

        /// @brief Flag indicating if metadata needs to be synchronized
        bool m_shouldSyncMetadata = false;

        /// @brief Flag indicating if groups need to be synchronized
        bool m_shouldSyncGroups = false;

        /// @brief Mutex for synchronizing access to sync flags
        std::mutex m_syncFlagsMutex;
};
