#pragma once

#include "sysInfoInterface.h"
#include <idbsync.hpp>
#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include <ipersistent_queue.hpp>
#include <commonDefs.h>
#include <json.hpp>

#include <functional>
#include <memory>
#include <string>
#include <vector>

class AgentInfoImpl
{
    public:
        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param reportDiffFunction Function to report stateless diffs
        /// @param persistDiffFunction Function to persist stateful diffs
        /// @param logFunction Function to log messages
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param sysInfo Pointer to ISysInfo for system information gathering
        /// @param fileIO Pointer to IFileIOUtils for file I/O operations
        /// @param fileSystem Pointer to IFileSystemWrapper for file system operations
        AgentInfoImpl(std::string dbPath,
                      std::function<void(const std::string&)> reportDiffFunction = nullptr,
                      std::function<void(const std::string&, Operation, const std::string&, const std::string&)> persistDiffFunction = nullptr,
                      std::function<void(const modules_log_level_t, const std::string&)> logFunction = nullptr,
                      std::shared_ptr<IDBSync> dbSync = nullptr,
                      std::shared_ptr<ISysInfo> sysInfo = nullptr,
                      std::shared_ptr<IFileIOUtils> fileIO = nullptr,
                      std::shared_ptr<IFileSystemWrapper> fileSystem = nullptr);
        ~AgentInfoImpl();

        void start();
        void stop();

        /// @brief Persist a difference to the synchronization protocol
        /// @param id Unique identifier for the difference
        /// @param operation Type of operation (CREATE, MODIFY, DELETE)
        /// @param index Index or table name
        /// @param data Data payload
        void persistDifference(const std::string& id, Operation operation, const std::string& index, const std::string& data);

        /// @brief Process a database event and emit notifications
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        void processEvent(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);

        /// @brief Notify change by calling report and persist callbacks
        /// @param result Type of change (INSERTED, MODIFIED, DELETED)
        /// @param data Event data
        /// @param table Table name
        void notifyChange(ReturnTypeCallback result, const nlohmann::json& data, const std::string& table);

        /// @brief Calculate checksum for metadata
        /// @param metadata Metadata JSON object
        /// @return Checksum string
        std::string calculateMetadataChecksum(const nlohmann::json& metadata) const;

        /// @brief Calculate hash ID for a row
        /// @param data Row data
        /// @param table Table name
        /// @return Hash ID string
        std::string calculateHashId(const nlohmann::json& data, const std::string& table) const;

        /// @brief Convert data to ECS format
        /// @param data Original data
        /// @param table Table name
        /// @return ECS-formatted data
        nlohmann::json ecsData(const nlohmann::json& data, const std::string& table) const;

    private:
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

        /// @brief Function to persist stateful diffs
        std::function<void(const std::string&, Operation, const std::string&, const std::string&)> m_persistDiffFunction;

        /// @brief Function to log messages
        std::function<void(const modules_log_level_t, const std::string&)> m_logFunction;

        /// @brief Flag to track if module has been stopped
        bool m_stopped = false;
};
