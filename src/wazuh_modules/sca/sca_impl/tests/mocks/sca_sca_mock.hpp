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

        /// @brief Mark a flush as sending or done, waking waiters the way executeFlushSync() does.
        void setFlushInProgressForTest(bool inProgress)
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_flushInProgress.store(inProgress);
            m_pauseCv.notify_all();
        }

        /// @brief Mark a recovery DataClean as running or done, waking waiters the way it does.
        void setRecoveryInProgressForTest(bool inProgress)
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_recoveryInProgress.store(inProgress);
            m_pauseCv.notify_all();
        }

        /// @brief Whether a recovery DataClean holds its slot.
        bool recoveryInProgressForTest() const
        {
            return m_recoveryInProgress.load();
        }

        /// @brief Agent id change resends started so far.
        uint32_t identityResyncAttemptsForTest() const
        {
            return m_identityResyncAttempts.load();
        }

        /// @brief Mark Run() as past its initialization (or not), which the identity resend waits for.
        void setRunInitializedForTest(bool initialized)
        {
            std::lock_guard<std::mutex> lock(m_pauseMutex);
            m_runInitialized.store(initialized);
            m_pauseCv.notify_all();
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

        /// @brief Testing helper to drive the flush path synchronously (bypasses the async controller).
        /// @return 0 on success, -1 on error.
        int callExecuteFlushSync()
        {
            return executeFlushSync();
        }

        /// @brief Testing helper to drive full recovery synchronously.
        /// @return true on success, false on failure.
        bool callPerformRecovery()
        {
            return performRecovery();
        }

        /// @brief Whether a scan has ever completed (issue 38428's persisted
        /// "first scan owed" tracking) -- exposed for tests.
        bool getFirstScanCompletedForTest() const
        {
            return m_firstScanCompleted.load();
        }
};
