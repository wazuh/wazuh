#pragma once

#include "../core/logger.hpp"
#include "../core/stop_controller.hpp"
#include "i_kubernetes_api_client.hpp"
#include "i_workload_index_source.hpp"

#include <atomic>
#include <chrono>
#include <memory>
#include <mutex>
#include <thread>

namespace wazuh::container_instances
{

    /// Polls apps/v1 + batch/v1 workloads on its own thread (fixed decision:
    /// polling, not watch — workload churn is slow relative to pod lifecycle).
    class OwnershipPoller final : public IWorkloadIndexSource
    {
    public:
        OwnershipPoller(IKubernetesApiClient& client, std::chrono::seconds interval, Logger logger);
        ~OwnershipPoller() override;

        OwnershipPoller(const OwnershipPoller&) = delete;
        OwnershipPoller& operator=(const OwnershipPoller&) = delete;
        OwnershipPoller(OwnershipPoller&&) = delete;
        OwnershipPoller& operator=(OwnershipPoller&&) = delete;

        void start(const StopController& stop);
        void join();

        [[nodiscard]] std::shared_ptr<const WorkloadIndex> latest() const override;
        [[nodiscard]] std::uint64_t generation() const override;

    private:
        void runLoop(const StopController& stop);

        IKubernetesApiClient& m_client;
        std::chrono::seconds m_interval;
        Logger m_logger;
        std::thread m_thread;

        mutable std::mutex m_mutex;
        std::shared_ptr<const WorkloadIndex> m_latest;
        std::atomic<std::uint64_t> m_generation {0};
    };

} // namespace wazuh::container_instances
