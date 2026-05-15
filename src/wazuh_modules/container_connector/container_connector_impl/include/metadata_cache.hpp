#pragma once

#include "container_connector_impl.hpp"
#include "container_meta.hpp"
#include "stop_controller.hpp"

#include <functional>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_connector {

/// @brief Thread-safe cache mapping kernel-observable identifiers to container metadata.
///
/// Primary lookup is by cgroup_id (the hot path for FIM eBPF events in T-K5).
/// Secondary indexes by container_id and by (pod_uid, container_name) support
/// lifecycle paths driven from the Kubernetes side.
///
/// Writers (only PodWatcher today) call Reconcile() to apply a full state snapshot.
/// Reconcile diffs against the current set and fires on_added/on_removed callbacks
/// for new and removed containers respectively. Callbacks are invoked synchronously
/// from the writer's thread; subscribers must not block.
class MetadataCache final
{
public:
    using ContainerCallback = std::function<void(std::shared_ptr<const ContainerInPod>)>;

    MetadataCache(std::shared_ptr<StopController> stop, LogCallback log);
    ~MetadataCache() = default;

    MetadataCache(const MetadataCache&)            = delete;
    MetadataCache& operator=(const MetadataCache&) = delete;
    MetadataCache(MetadataCache&&)                 = delete;
    MetadataCache& operator=(MetadataCache&&)      = delete;

    void OnContainerAdded(ContainerCallback cb);
    void OnContainerRemoved(ContainerCallback cb);

    /// Replace the cache content with the given snapshots.
    /// Fires on_added for containers new in `snapshots` and on_removed for containers
    /// removed since the last call. Idempotent: if the snapshot is identical no
    /// callbacks fire.
    void Reconcile(std::vector<PodSnapshot> snapshots);

    std::shared_ptr<const ContainerInPod> LookupByCgroupId(uint64_t cgroup_id) const;
    std::shared_ptr<const ContainerInPod> LookupByContainerId(const std::string& container_id) const;
    std::shared_ptr<const ContainerInPod> LookupByPodContainer(const std::string& pod_uid,
                                                               const std::string& container_name) const;

    size_t Size() const;

private:
    void Log(int level, const std::string& msg) const;

    std::shared_ptr<StopController> stop_;
    LogCallback                     log_;

    mutable std::shared_mutex mutex_;
    std::unordered_map<uint64_t,    std::shared_ptr<const ContainerInPod>> by_cgroup_;
    std::unordered_map<std::string, std::shared_ptr<const ContainerInPod>> by_container_id_;
    std::unordered_map<std::string, std::shared_ptr<const ContainerInPod>> by_pod_container_;
    std::unordered_map<std::string, std::vector<std::shared_ptr<const ContainerInPod>>> containers_by_pod_;

    std::mutex                     callbacks_mutex_;
    std::vector<ContainerCallback> on_added_;
    std::vector<ContainerCallback> on_removed_;
};

} // namespace wazuh::container_connector
