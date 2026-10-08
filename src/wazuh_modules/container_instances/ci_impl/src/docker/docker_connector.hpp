#pragma once

#include "../cache/i_metadata_store.hpp"
#include "../cgroup/i_cgroup_resolver.hpp"
#include "../core/cache_entry.hpp"
#include "../core/i_container_connector.hpp"
#include "../core/i_on_demand_refresher.hpp"
#include "../core/logger.hpp"
#include "i_docker_api_client.hpp"

#include <chrono>
#include <cstdint>
#include <mutex>
#include <set>
#include <tuple>

namespace wazuh::container_instances
{

    /// Keeps the store fresh from a local Docker daemon: version negotiation,
    /// full seed, then /events with reconcile-on-event. On stream disconnect it
    /// resumes with since=<last event ts> AND re-seeds fully — Docker's `since` is
    /// second-granular and daemon restarts can drop events.
    class DockerConnector final
        : public IContainerConnector
        , public IOnDemandRefresher
    {
    public:
        /// `idleReconcileInterval` is how often a snapshot is taken with nothing
        /// pending. Injectable only so a test need not sleep through the real
        /// one; production always uses the default.
        DockerConnector(IDockerApiClient& client,
                        const ICgroupResolver& resolver,
                        IMetadataStore& store,
                        SourceId source,
                        Logger logger,
                        std::chrono::milliseconds idleReconcileInterval = std::chrono::seconds {10});

        void run(const StopController& stop) override;

        [[nodiscard]] RefreshOutcome refreshOne(const std::string& containerId, std::uint64_t cgroupInode) override;

    private:
        /// Full snapshot: list + inspect each + join with the cgroup scan.
        void reSeed();

        void handleEvent(const DockerEvent& event);

        /// Trailing edge of the reconcile debounce; see the definition.
        void flushPendingReconcile();

        IDockerApiClient& m_client;
        const ICgroupResolver& m_resolver;
        IMetadataStore& m_store;
        SourceId m_source;
        Logger m_logger;

        /// (id, action, timeNano) of recent events: dedupe across since= resume
        /// overlap. Pruned by timestamp, guarded for refreshOne concurrency.
        std::mutex m_eventDedupeMutex;
        std::set<std::tuple<std::string, std::string, std::int64_t>> m_seenEvents;

        std::chrono::steady_clock::time_point m_lastReconcile {};

        /// Set when an event arrived inside the debounce window, cleared by
        /// reSeed(). Touched only from the connector's own thread — events and
        /// the stream's idle tick are both delivered on it — so it needs no
        /// synchronisation, unlike m_seenEvents above which refreshOne() also
        /// reaches from an IPC worker.
        bool m_reconcilePending {false};

        /// See the constructor: how often a reconcile runs with nothing pending,
        /// so that applySnapshot() — the only place anything expires — keeps
        /// being called on a host that has gone quiet.
        std::chrono::milliseconds m_idleReconcileInterval;
    };

} // namespace wazuh::container_instances
