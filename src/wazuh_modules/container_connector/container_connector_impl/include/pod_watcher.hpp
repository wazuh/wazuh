#pragma once

#include "container_connector_impl.hpp"
#include "stop_controller.hpp"

#include <chrono>
#include <memory>
#include <thread>

namespace wazuh::container_connector {

class KubernetesClient;
class MetadataCache;

/// @brief Background poller that periodically lists pods on the node and reconciles
/// the metadata cache.
///
/// Polling cadence:
///   - On success: kBaseInterval (5s) between polls.
///   - On error:   exponential backoff up to kMaxBackoff (60s).
///
/// Cancellation: every wait between polls goes through StopController::WaitFor(),
/// so a stop request unblocks the thread within the wait granularity (not the
/// next interval). Start() spawns the worker; Stop() requests the stop and joins.
class PodWatcher final
{
public:
    PodWatcher(KubernetesClient*               client,
               MetadataCache*                  cache,
               std::shared_ptr<StopController> stop,
               std::chrono::seconds            poll_interval,
               LogCallback                     log);

    ~PodWatcher();

    PodWatcher(const PodWatcher&)            = delete;
    PodWatcher& operator=(const PodWatcher&) = delete;
    PodWatcher(PodWatcher&&)                 = delete;
    PodWatcher& operator=(PodWatcher&&)      = delete;

    void Start();
    void Stop();

private:
    void RunLoop();
    void Log(int level, const std::string& msg) const;

    KubernetesClient*               client_;
    MetadataCache*                  cache_;
    std::shared_ptr<StopController> stop_;
    std::chrono::seconds            poll_interval_;
    LogCallback                     log_;

    std::thread thread_;
    bool        running_{false};

    static constexpr auto kMaxBackoff = std::chrono::seconds(300);
};

} // namespace wazuh::container_connector
