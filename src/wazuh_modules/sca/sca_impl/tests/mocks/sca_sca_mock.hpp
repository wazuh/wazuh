#pragma once

#include <sca_impl.hpp>

#include <mock_dbsync.hpp>
#include <mock_filesystem_wrapper.hpp>
#include "iagent_sync_protocol.hpp"

class SCAMock : public SecurityConfigurationAssessment
{
    public:
        SCAMock(std::shared_ptr<IDBSync> dBSync = nullptr, std::shared_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr)
            : SecurityConfigurationAssessment("db_path", dBSync, fileSystemWrapper)
        {}

        std::vector<std::unique_ptr<ISCAPolicy>>& GetPolicies()
        {
            return m_policies;
        }

        /// @brief Set the sync protocol for testing
        /// @param syncProtocol Shared pointer to the sync protocol mock
        void setSyncProtocol(std::shared_ptr<IAgentSyncProtocol> syncProtocol)
        {
            m_spSyncProtocol = std::move(syncProtocol);
        }

        /// @brief Set sync in progress flag for testing
        /// @param inProgress Whether sync is in progress
        void setSyncInProgress(bool inProgress)
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_syncInProgress.store(inProgress);
        }

        /// @brief Notify pause condition variable (to simulate sync completion)
        void notifySyncComplete()
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_syncInProgress.store(false);
            m_pauseCv.notify_all();
        }

        /// @brief Testing helper to lock pause mutex from test thread.
        void lockPauseMutex()
        {
            m_pauseMutex.lock();
        }

        /// @brief Testing helper to unlock pause mutex from test thread.
        void unlockPauseMutex()
        {
            m_pauseMutex.unlock();
        }
};
