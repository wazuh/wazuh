#pragma once

#include "container_connector_impl.hpp"
#include "docker_meta.hpp"
#include "stop_controller.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_connector {

/// @brief Thread-safe cache mapping container identifiers to Docker container metadata.
///
/// Indexed by container_id (primary) and cgroup_id (hot path for eBPF FIM events).
/// Reconcile() is called by DockerWatcher on each poll with the full container snapshot.
/// It atomically replaces all maps and fires on_added/on_removed callbacks for the diff.
/// Lifecycle callbacks fire synchronously from the writer's thread.
class DockerMetadataCache final
{
public:
    using ContainerCallback = std::function<void(std::shared_ptr<const DockerContainerInfo>)>;

    DockerMetadataCache(std::shared_ptr<StopController> stop, LogCallback log);
    ~DockerMetadataCache() = default;

    DockerMetadataCache(const DockerMetadataCache&)            = delete;
    DockerMetadataCache& operator=(const DockerMetadataCache&) = delete;
    DockerMetadataCache(DockerMetadataCache&&)                 = delete;
    DockerMetadataCache& operator=(DockerMetadataCache&&)      = delete;

    void OnContainerAdded(ContainerCallback cb);
    void OnContainerRemoved(ContainerCallback cb);

    /// Replace the cache content with the given snapshot.
    /// Fires on_added for containers new in the snapshot and on_removed for containers
    /// absent from it. Idempotent: if the snapshot is identical no callbacks fire.
    void Reconcile(std::vector<std::shared_ptr<DockerContainerInfo>> containers);

    std::shared_ptr<const DockerContainerInfo> LookupByCgroupId(uint64_t cgroup_id) const;
    std::shared_ptr<const DockerContainerInfo> LookupByContainerId(const std::string& id) const;

    size_t Size() const;

private:
    void FireAdded(std::shared_ptr<const DockerContainerInfo> info);
    void FireRemoved(std::shared_ptr<const DockerContainerInfo> info);
    void Log(int level, const std::string& msg) const;

    std::shared_ptr<StopController> stop_;
    LogCallback                     log_;

    mutable std::shared_mutex mutex_;
    std::unordered_map<std::string, std::shared_ptr<const DockerContainerInfo>> by_container_id_;
    std::unordered_map<uint64_t,    std::shared_ptr<const DockerContainerInfo>> by_cgroup_id_;

    std::mutex                     callbacks_mutex_;
    std::vector<ContainerCallback> on_added_;
    std::vector<ContainerCallback> on_removed_;
};

} // namespace wazuh::container_connector
