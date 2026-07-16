#pragma once

#include "../cache/i_metadata_store.hpp"
#include "../cgroup/i_cgroup_resolver.hpp"
#include "../core/i_on_demand_refresher.hpp"
#include "../core/logger.hpp"
#include "../core/retry_policy.hpp"
#include "i_query_handler.hpp"

#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    /// One cold-path metadata source: which runtime hints it can answer for,
    /// and the connector slice that fetches on demand.
    struct RefresherBinding
    {
        bool docker {false}; ///< true: answers docker-hinted ids; false: containerd/cri-o (Kubernetes).
        IOnDemandRefresher* refresher {nullptr};
    };

    /// Answers enrichment queries with the three-outcome contract. The cold-cache
    /// loop (bounded retries, then pending) lives here and nowhere else; the
    /// connectors contain zero retry logic for this path. Cold-path fetches are
    /// routed to the binding matching the resolver's runtime hint; an unknown
    /// hint tries every binding.
    class QueryService final : public IQueryHandler
    {
    public:
        using Sleeper = std::function<void(std::chrono::milliseconds)>;

        QueryService(IMetadataStore& store,
                     std::vector<RefresherBinding> refreshers,
                     const ICgroupResolver& resolver,
                     RetryPolicy coldCacheRetry,
                     std::string connectorName,
                     Logger logger,
                     Sleeper sleeper = nullptr);

        [[nodiscard]] QueryResponse handle(const QueryRequest& request) override;

    private:
        [[nodiscard]] QueryResponse resolve(const QueryRequest& request);
        [[nodiscard]] QueryResponse coldResolve(std::uint64_t cgroupInode);

        IMetadataStore& m_store;
        std::vector<RefresherBinding> m_refreshers;
        const ICgroupResolver& m_resolver;
        RetryPolicy m_coldCacheRetry;
        std::string m_connectorName;
        Logger m_logger;
        Sleeper m_sleeper;
    };

} // namespace wazuh::container_instances
