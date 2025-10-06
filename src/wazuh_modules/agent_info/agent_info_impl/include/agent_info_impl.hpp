#pragma once

#include "sysInfoInterface.h"
#include <idbsync.hpp>
#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>

#include <memory>
#include <string>

class AgentInfoImpl
{
    public:
        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param sysInfo Pointer to ISysInfo for system information gathering
        /// @param fileIO Pointer to IFileIOUtils for file I/O operations
        /// @param fileSystem Pointer to IFileSystemWrapper for file system operations
        AgentInfoImpl(std::string dbPath,
                      std::shared_ptr<IDBSync> dbSync = nullptr,
                      std::shared_ptr<ISysInfo> sysInfo = nullptr,
                      std::shared_ptr<IFileIOUtils> fileIO = nullptr,
                      std::shared_ptr<IFileSystemWrapper> fileSystem = nullptr);
        ~AgentInfoImpl();

        void start();
        void stop();

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

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Pointer to ISysInfo for system information gathering
        std::shared_ptr<ISysInfo> m_sysInfo;

        /// @brief Pointer to IFileIOUtils for file I/O operations
        std::shared_ptr<IFileIOUtils> m_fileIO;

        /// @brief Pointer to IFileSystemWrapper for file system operations
        std::shared_ptr<IFileSystemWrapper> m_fileSystem;

        /// @brief Flag to track if module has been stopped
        bool m_stopped = false;
};
