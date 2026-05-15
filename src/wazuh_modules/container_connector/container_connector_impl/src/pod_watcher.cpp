#include "pod_watcher.hpp"

#include "cgroup_resolver.hpp"
#include "kubernetes_client.hpp"
#include "logging_helper.h"
#include "metadata_cache.hpp"

#include <exception>
#include <utility>

namespace wazuh::container_connector {

PodWatcher::PodWatcher(KubernetesClient*               client,
                       MetadataCache*                  cache,
                       std::shared_ptr<StopController> stop,
                       LogCallback                     log)
    : client_(client)
    , cache_(cache)
    , stop_(std::move(stop))
    , log_(std::move(log))
{
}

PodWatcher::~PodWatcher()
{
    Stop();
}

void PodWatcher::Log(int level, const std::string& msg) const
{
    if (log_) {
        log_(level, msg);
    }
}

void PodWatcher::Start()
{
    if (running_) return;
    running_ = true;
    thread_  = std::thread([this] { RunLoop(); });
}

void PodWatcher::Stop()
{
    if (!running_) return;
    // The thread observes stop_->IsStopRequested() inside its WaitFor loop and exits
    // promptly. We do not need a per-watcher cancel signal because the polling unit
    // of work (one HTTP GET) is short and bounded by the 5s timeout in KubernetesClient.
    if (thread_.joinable()) {
        thread_.join();
    }
    running_ = false;
}

void PodWatcher::RunLoop()
{
    auto current_interval = kBaseInterval;
    bool first_iteration  = true;

    while (!stop_->IsStopRequested()) {
        if (!first_iteration) {
            // Wait BEFORE the next iteration so a successful poll waits the base
            // interval and a failed one waits the backoff that was just set.
            if (!stop_->WaitFor(current_interval)) {
                break;  // stop requested during the wait
            }
        }
        first_iteration = false;

        try {
            auto pods = client_->ListPodsOnNode();

            // Resolve cgroup_id by asking the kernel directly via /proc/*/cgroup.
            // One pass builds the map for every running container on the node;
            // we then look up each container by its CRI id. Agnostic to driver,
            // runtime, kubelet config and outer-Docker wraps.
            const auto cgroup_map = BuildCgroupIdMap();
            for (auto& snap : pods) {
                if (!snap.pod) continue;
                for (auto& c : snap.containers) {
                    if (c.cgroup_id == 0 && !c.container_id.empty()) {
                        const auto it = cgroup_map.find(c.container_id);
                        if (it != cgroup_map.end()) {
                            c.cgroup_id = it->second;
                        }
                    }
                }
            }

            cache_->Reconcile(std::move(pods));

            // Reset interval on a successful round.
            current_interval = kBaseInterval;
        } catch (const std::exception& ex) {
            Log(LOG_WARNING, std::string{"Pod poll failed: "} + ex.what() +
                                 " — backing off to " +
                                 std::to_string(current_interval.count()) + "s before retry.");
            // Exponential backoff capped at kMaxBackoff.
            auto doubled = std::chrono::seconds(current_interval.count() * 2);
            current_interval = (doubled < kMaxBackoff) ? doubled : kMaxBackoff;
        } catch (...) {
            Log(LOG_WARNING, "Pod poll failed: unknown exception. Backing off.");
            auto doubled = std::chrono::seconds(current_interval.count() * 2);
            current_interval = (doubled < kMaxBackoff) ? doubled : kMaxBackoff;
        }
    }

    Log(LOG_DEBUG, "PodWatcher loop exiting.");
}

} // namespace wazuh::container_connector
