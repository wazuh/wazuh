#pragma once

#include <idbsync.hpp>

#include <memory>
#include <string>

class AgentInfoImpl
{
    public:
        /// @brief Constructor
        /// @param dbPath Path to the database file
        /// @param dbSync Pointer to IDBSync for database synchronization
        AgentInfoImpl(std::string dbPath,
                      std::shared_ptr<IDBSync> dbSync = nullptr);
        ~AgentInfoImpl();

        void start();
        void stop();

    private:
        /// @brief Get the create statement for the database
        std::string GetCreateStatement() const;

        /// @brief Pointer to IDBSync
        std::shared_ptr<IDBSync> m_dBSync;

        /// @brief Flag to track if module has been stopped
        bool m_stopped = false;
};
