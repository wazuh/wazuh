#pragma once

#include <agent_info_impl.hpp>

#include <memory>
#include <string>
#include <utility>

/// @brief Test-only subclass exposing the seams AgentInfoImpl doesn't need in production:
/// injecting a sync protocol mock and forwarding the private performIntegritySync() so its
/// SyncModuleResult classification (issue #38621) can be exercised directly.
class AgentInfoImplMock : public AgentInfoImpl
{
    public:
        using AgentInfoImpl::AgentInfoImpl;

        /// @brief Swaps the sync protocol for an injected instance (e.g. a gmock) so tests can
        /// drive SyncModuleResult classification without a live transport.
        void setSyncProtocol(std::unique_ptr<IAgentSyncProtocol> syncProtocol)
        {
            m_spSyncProtocol = std::move(syncProtocol);
        }

        bool callPerformIntegritySync(const std::string& table)
        {
            return performIntegritySync(table);
        }
};
