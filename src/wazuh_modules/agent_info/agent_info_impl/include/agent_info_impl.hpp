#pragma once

#include "sysInfoInterface.h"
#include <idbsync.hpp>

#include <memory>
#include <string>

class AgentInfoImpl
{
    public:
        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param dbSync Pointer to IDBSync for database synchronization
        /// @param sysInfo Pointer to ISysInfo for system information gathering
        AgentInfoImpl(std::string dbPath,
                      std::shared_ptr<IDBSync> dbSync = nullptr,
                      std::shared_ptr<ISysInfo> sysInfo = nullptr);
        ~AgentInfoImpl();

        void start();
        void stop();

    private:
        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Pointer to ISysInfo for system information gathering
        std::shared_ptr<ISysInfo> m_sysInfo;

        /// @brief Flag to track if module has been stopped
        bool m_stopped = false;
};
