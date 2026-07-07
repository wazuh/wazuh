#include "ownership_poller.hpp"

#include <utility>

namespace wazuh::container_instances
{

    OwnershipPoller::OwnershipPoller(IKubernetesApiClient& client, std::chrono::seconds interval, Logger logger)
        : m_client(client)
        , m_interval(interval)
        , m_logger(std::move(logger))
    {
    }

    OwnershipPoller::~OwnershipPoller()
    {
        join();
    }

    void OwnershipPoller::start(const StopController& stop)
    {
        m_thread = std::thread([this, &stop] { runLoop(stop); });
    }

    void OwnershipPoller::join()
    {
        if (m_thread.joinable())
        {
            m_thread.join();
        }
    }

    std::shared_ptr<const WorkloadIndex> OwnershipPoller::latest() const
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_latest;
    }

    std::uint64_t OwnershipPoller::generation() const
    {
        return m_generation.load(std::memory_order_acquire);
    }

    void OwnershipPoller::runLoop(const StopController& stop)
    {
        while (!stop.isStopRequested())
        {
            try
            {
                auto index = std::make_shared<const WorkloadIndex>(m_client.listWorkloads());
                {
                    std::lock_guard<std::mutex> lock(m_mutex);
                    m_latest = std::move(index);
                }
                m_generation.fetch_add(1, std::memory_order_release);
            }
            catch (const std::exception& error)
            {
                m_logger(LogLevel::warn, std::string {"Workload ownership poll failed: "} + error.what());
            }

            if (!stop.waitFor(m_interval))
            {
                return;
            }
        }
    }

} // namespace wazuh::container_instances
