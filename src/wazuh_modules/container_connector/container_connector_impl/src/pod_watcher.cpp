#include "pod_watcher.hpp"

#include "cgroup_resolver.hpp"
#include "kubernetes_client.hpp"
#include "logging_helper.h"
#include "metadata_cache.hpp"

#include <algorithm>
#include <exception>
#include <utility>

namespace wazuh::container_connector {

PodWatcher::PodWatcher(KubernetesClient*               client,
                       MetadataCache*                  cache,
                       std::shared_ptr<StopController> stop,
                       std::chrono::seconds            poll_interval,
                       LogCallback                     log)
    : client_(client)
    , cache_(cache)
    , stop_(std::move(stop))
    , poll_interval_(poll_interval)
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
    auto current_interval = poll_interval_;
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

            size_t pod_count        = 0;
            size_t total_containers = 0;
            for (const auto& snap : pods) {
                if (!snap.pod) continue;
                ++pod_count;
                total_containers += snap.containers.size();
                std::string owners;
                for (const auto& ref : snap.pod->owner_refs) {
                    if (!owners.empty()) owners += ", ";
                    owners += ref.kind + "/" + ref.name;
                }
                Log(LOG_DEBUG, "K8s pod: ns='" + snap.pod->namespace_ + "' name='" +
                               snap.pod->pod_name + "' uid=" + snap.pod->pod_uid +
                               " containers=" + std::to_string(snap.containers.size()) +
                               (owners.empty() ? "" : " owners=[" + owners + "]"));
                for (const auto& c : snap.containers) {
                    const auto short_id = c.container_id.substr(
                        0, std::min<size_t>(12, c.container_id.size()));
                    Log(LOG_DEBUG, "  container: name='" + c.name + "' image='" + c.image +
                                   "' id=" + short_id +
                                   " restarts=" + std::to_string(c.restart_count) +
                                   " cgroup=" + std::to_string(c.cgroup_id));
                }
            }

            cache_->Reconcile(std::move(pods));
            Log(LOG_INFO, "K8s snapshot synced: " + std::to_string(pod_count) + " pod(s), " +
                          std::to_string(total_containers) + " container(s).");

            // Reset interval on a successful round.
            current_interval = poll_interval_;
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
