#pragma once

#include "../cache/i_metadata_store.hpp"
#include "../cgroup/i_cgroup_resolver.hpp"
#include "../core/i_container_connector.hpp"
#include "../core/i_on_demand_refresher.hpp"
#include "../core/logger.hpp"
#include "i_kubernetes_api_client.hpp"
#include "i_workload_index_source.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <unordered_map>

namespace wazuh::container_instances
{

    /// Keeps the store fresh from the apiserver: list-then-watch with the standard
    /// 410 -> re-list fallback. Watch reconnects are bounded (3 attempts, warning
    /// each); after that the connector fails the watch as mandated and falls back
    /// to degraded periodic re-list with a cool-down so enrichment self-heals
    /// after apiserver outages.
    class KubernetesConnector final
        : public IContainerConnector
        , public IOnDemandRefresher
    {
    public:
        KubernetesConnector(IKubernetesApiClient& client,
                            const ICgroupResolver& resolver,
                            IMetadataStore& store,
                            const IWorkloadIndexSource& workloadIndex,
                            std::string nodeName,
                            Logger logger);

        void run(const StopController& stop) override;

        [[nodiscard]] RefreshOutcome refreshOne(const std::string& containerId, std::uint64_t cgroupInode) override;

    private:
        /// Full reconcile from m_podsByUid: join with the cgroup scan, resolve the
        /// ownership chain, extract host/kata verdicts. Connector thread only.
        void reconcile();

        void handleWatchEvent(const PodWatchEvent& event);

        IKubernetesApiClient& m_client;
        const ICgroupResolver& m_resolver;
        IMetadataStore& m_store;
        const IWorkloadIndexSource& m_workloadIndex;
        std::string m_nodeName;
        Logger m_logger;

        /// Connector-thread state (watch sink and reconcile run on it exclusively).
        std::unordered_map<std::string, PodSnapshot> m_podsByUid;
        std::string m_resourceVersion;
        std::chrono::steady_clock::time_point m_lastReconcile {};
        std::uint64_t m_ownersGeneration {0};
        bool m_reconcilePending {false};
    };

} // namespace wazuh::container_instances
