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
};
