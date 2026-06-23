#include "docker_watcher.hpp"

#include "cgroup_resolver.hpp"
#include "docker_client.hpp"
#include "docker_meta.hpp"
#include "docker_metadata_cache.hpp"
#include "logging_helper.h"

#include <exception>
#include <memory>
#include <utility>

namespace wazuh::container_connector {

DockerWatcher::DockerWatcher(DockerClient*                   client,
                             DockerMetadataCache*            cache,
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

DockerWatcher::~DockerWatcher()
{
    Stop();
}

void DockerWatcher::Log(int level, const std::string& msg) const
{
    if (log_) log_(level, msg);
}

void DockerWatcher::Start()
{
    if (running_) return;
    running_ = true;
    thread_  = std::thread([this] { RunLoop(); });
}

void DockerWatcher::Stop()
{
    if (!running_) return;
    if (thread_.joinable()) thread_.join();
    running_ = false;
}

void DockerWatcher::RunLoop()
{
    auto current_interval = poll_interval_;
    bool first_iteration  = true;

    while (!stop_->IsStopRequested())
    {
        if (!first_iteration)
        {
            if (!stop_->WaitFor(current_interval)) break;
        }
        first_iteration = false;

        try
        {
            SyncSnapshot();
            current_interval = poll_interval_;
        }
        catch (const std::exception& ex)
        {
            Log(LOG_WARNING, std::string{"Docker poll failed: "} + ex.what() +
                             " — backing off to " + std::to_string(current_interval.count()) + "s.");
            const auto doubled = std::chrono::seconds(current_interval.count() * 2);
            current_interval   = (doubled < kMaxBackoff) ? doubled : kMaxBackoff;
        }
        catch (...)
        {
            Log(LOG_WARNING, "Docker poll failed: unknown exception. Backing off.");
            const auto doubled = std::chrono::seconds(current_interval.count() * 2);
            current_interval   = (doubled < kMaxBackoff) ? doubled : kMaxBackoff;
        }
    }

    Log(LOG_DEBUG, "DockerWatcher loop exiting.");
}

void DockerWatcher::SyncSnapshot()
{
    auto containers = client_->ListContainers();
    const auto cgroup_map = BuildCgroupIdMap();

    std::vector<std::shared_ptr<DockerContainerInfo>> snapshot;
    snapshot.reserve(containers.size());

    for (auto& info : containers)
    {
        const auto it = cgroup_map.find(info.container_id);
        if (it != cgroup_map.end()) info.cgroup_id = it->second;
        snapshot.push_back(std::make_shared<DockerContainerInfo>(std::move(info)));
    }

    for (const auto& info : snapshot)
    {
        std::string nets;
        for (const auto& ep : info->networks) {
            if (!nets.empty()) nets += ", ";
            nets += ep.network_name + ":" + ep.ip_address;
        }
        std::string labels;
        for (const auto& [k, v] : info->labels) {
            if (!labels.empty()) labels += ", ";
            labels += k + "=" + v;
        }
        const auto short_id = info->container_id.substr(
            0, std::min<size_t>(12, info->container_id.size()));
        Log(LOG_DEBUG, "Docker container: name='" + info->name + "' image='" + info->image +
                       "' id=" + short_id + " state=" + info->state.status +
                       " restarts=" + std::to_string(info->state.restart_count) +
                       " cgroup=" + std::to_string(info->cgroup_id) +
                       (nets.empty()   ? "" : " networks=[" + nets    + "]") +
                       (labels.empty() ? "" : " labels=["   + labels  + "]"));
    }

    const auto count = snapshot.size();
    cache_->Reconcile(std::move(snapshot));
    Log(LOG_INFO, "Docker snapshot synced: " + std::to_string(count) + " containers.");
}

} // namespace wazuh::container_connector
