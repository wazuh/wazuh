#include "docker_metadata_cache.hpp"

#include "logging_helper.h"

#include <utility>
#include <vector>

namespace wazuh::container_connector {

DockerMetadataCache::DockerMetadataCache(std::shared_ptr<StopController> stop, LogCallback log)
    : stop_(std::move(stop))
    , log_(std::move(log))
{
}

void DockerMetadataCache::Log(int level, const std::string& msg) const
{
    if (log_) log_(level, msg);
}

void DockerMetadataCache::OnContainerAdded(ContainerCallback cb)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    on_added_.push_back(std::move(cb));
}

void DockerMetadataCache::OnContainerRemoved(ContainerCallback cb)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    on_removed_.push_back(std::move(cb));
}

void DockerMetadataCache::FireAdded(std::shared_ptr<const DockerContainerInfo> info)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    for (auto& cb : on_added_) cb(info);
}

void DockerMetadataCache::FireRemoved(std::shared_ptr<const DockerContainerInfo> info)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    for (auto& cb : on_removed_) cb(info);
}

void DockerMetadataCache::Reconcile(std::vector<std::shared_ptr<DockerContainerInfo>> containers)
{
    std::unordered_map<std::string, std::shared_ptr<const DockerContainerInfo>> next_by_container_id;
    std::unordered_map<uint64_t,    std::shared_ptr<const DockerContainerInfo>> next_by_cgroup_id;

    std::vector<std::shared_ptr<const DockerContainerInfo>> to_emit_added;
    std::vector<std::shared_ptr<const DockerContainerInfo>> to_emit_removed;

    {
        std::shared_lock<std::shared_mutex> lk(mutex_);

        for (auto& info : containers)
        {
            if (!info || info->container_id.empty()) continue;
            auto shared = std::static_pointer_cast<const DockerContainerInfo>(info);

            if (by_container_id_.find(shared->container_id) == by_container_id_.end())
                to_emit_added.push_back(shared);

            next_by_container_id.emplace(shared->container_id, shared);
            if (shared->cgroup_id != 0)
                next_by_cgroup_id.emplace(shared->cgroup_id, shared);
        }

        for (const auto& [id, existing] : by_container_id_)
        {
            if (next_by_container_id.find(id) == next_by_container_id.end())
                to_emit_removed.push_back(existing);
        }
    }

    {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        by_container_id_ = std::move(next_by_container_id);
        by_cgroup_id_    = std::move(next_by_cgroup_id);
    }

    for (const auto& sp : to_emit_added)   FireAdded(sp);
    for (const auto& sp : to_emit_removed) FireRemoved(sp);
}

std::shared_ptr<const DockerContainerInfo> DockerMetadataCache::LookupByCgroupId(uint64_t cgroup_id) const
{
    if (cgroup_id == 0) return nullptr;
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = by_cgroup_id_.find(cgroup_id);
    return (it != by_cgroup_id_.end()) ? it->second : nullptr;
}

std::shared_ptr<const DockerContainerInfo> DockerMetadataCache::LookupByContainerId(const std::string& id) const
{
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = by_container_id_.find(id);
    return (it != by_container_id_.end()) ? it->second : nullptr;
}

size_t DockerMetadataCache::Size() const
{
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return by_container_id_.size();
}

} // namespace wazuh::container_connector
