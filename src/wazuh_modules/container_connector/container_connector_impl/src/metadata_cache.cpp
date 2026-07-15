#include "metadata_cache.hpp"

#include "logging_helper.h"

#include <utility>

namespace wazuh::container_connector {

namespace {

std::string PodContainerKey(const std::string& pod_uid, const std::string& container_name)
{
    return pod_uid + "/" + container_name;
}

} // namespace

MetadataCache::MetadataCache(std::shared_ptr<StopController> stop, LogCallback log)
    : stop_(std::move(stop))
    , log_(std::move(log))
{
}

void MetadataCache::Log(int level, const std::string& msg) const
{
    if (log_) {
        log_(level, msg);
    }
}

void MetadataCache::OnContainerAdded(ContainerCallback cb)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    on_added_.push_back(std::move(cb));
}

void MetadataCache::OnContainerRemoved(ContainerCallback cb)
{
    std::lock_guard<std::mutex> lk(callbacks_mutex_);
    on_removed_.push_back(std::move(cb));
}

void MetadataCache::Reconcile(std::vector<PodSnapshot> snapshots)
{
    // Build the next maps locally first; swap atomically under the writer lock.
    std::unordered_map<uint64_t,    std::shared_ptr<const ContainerInPod>> next_by_cgroup;
    std::unordered_map<std::string, std::shared_ptr<const ContainerInPod>> next_by_container_id;
    std::unordered_map<std::string, std::shared_ptr<const ContainerInPod>> next_by_pod_container;
    std::unordered_map<std::string, std::vector<std::shared_ptr<const ContainerInPod>>> next_containers_by_pod;

    std::vector<std::shared_ptr<const ContainerInPod>> to_emit_added;
    std::vector<std::shared_ptr<const ContainerInPod>> to_emit_removed;

    {
        // Reader lock for the diff is enough since we hold the only writer reference
        // (Reconcile is single-writer by contract).
        std::shared_lock<std::shared_mutex> lk(mutex_);

        for (auto& snap : snapshots) {
            if (!snap.pod) continue;
            const auto& pod_uid = snap.pod->pod_uid;
            for (auto& c : snap.containers) {
                // Ensure the back-ref points to our shared PodInfo.
                c.pod = snap.pod;
                if (c.container_id.empty()) {
                    // Without a CRI ID we cannot key the container; skip and log.
                    Log(LOG_DEBUG, "Reconcile: skipping container '" + c.name +
                                       "' of pod '" + pod_uid + "' — empty container_id.");
                    continue;
                }

                auto sp = std::make_shared<const ContainerInPod>(std::move(c));

                // Fire 'added' if this container_id wasn't tracked before.
                if (by_container_id_.find(sp->container_id) == by_container_id_.end()) {
                    to_emit_added.push_back(sp);
                }

                if (sp->cgroup_id != 0) {
                    next_by_cgroup.emplace(sp->cgroup_id, sp);
                }
                next_by_container_id.emplace(sp->container_id, sp);
                next_by_pod_container.emplace(PodContainerKey(sp->pod->pod_uid, sp->name), sp);
                next_containers_by_pod[sp->pod->pod_uid].push_back(sp);
            }
        }

        // Containers that existed but are not in the snapshot anymore -> removed.
        for (const auto& [container_id, existing] : by_container_id_) {
            if (next_by_container_id.find(container_id) == next_by_container_id.end()) {
                to_emit_removed.push_back(existing);
            }
        }
    }

    {
        std::unique_lock<std::shared_mutex> lk(mutex_);
        by_cgroup_           = std::move(next_by_cgroup);
        by_container_id_     = std::move(next_by_container_id);
        by_pod_container_    = std::move(next_by_pod_container);
        containers_by_pod_   = std::move(next_containers_by_pod);
    }

    // Snapshot the callback vectors so we don't hold callbacks_mutex_ during emission.
    std::vector<ContainerCallback> added_callbacks;
    std::vector<ContainerCallback> removed_callbacks;
    {
        std::lock_guard<std::mutex> lk(callbacks_mutex_);
        added_callbacks   = on_added_;
        removed_callbacks = on_removed_;
    }

    for (const auto& sp : to_emit_added) {
        for (const auto& cb : added_callbacks) {
            try { cb(sp); }
            catch (const std::exception& ex) {
                Log(LOG_WARNING, std::string{"on_added callback threw: "} + ex.what());
            } catch (...) {
                Log(LOG_WARNING, "on_added callback threw unknown exception.");
            }
        }
    }
    for (const auto& sp : to_emit_removed) {
        for (const auto& cb : removed_callbacks) {
            try { cb(sp); }
            catch (const std::exception& ex) {
                Log(LOG_WARNING, std::string{"on_removed callback threw: "} + ex.what());
            } catch (...) {
                Log(LOG_WARNING, "on_removed callback threw unknown exception.");
            }
        }
    }
}

std::shared_ptr<const ContainerInPod> MetadataCache::LookupByCgroupId(uint64_t cgroup_id) const
{
    if (cgroup_id == 0) return nullptr;
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = by_cgroup_.find(cgroup_id);
    return (it == by_cgroup_.end()) ? nullptr : it->second;
}

std::shared_ptr<const ContainerInPod> MetadataCache::LookupByContainerId(const std::string& container_id) const
{
    if (container_id.empty()) return nullptr;
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = by_container_id_.find(container_id);
    return (it == by_container_id_.end()) ? nullptr : it->second;
}

std::shared_ptr<const ContainerInPod> MetadataCache::LookupByPodContainer(const std::string& pod_uid,
                                                                           const std::string& container_name) const
{
    if (pod_uid.empty() || container_name.empty()) return nullptr;
    std::shared_lock<std::shared_mutex> lk(mutex_);
    auto it = by_pod_container_.find(PodContainerKey(pod_uid, container_name));
    return (it == by_pod_container_.end()) ? nullptr : it->second;
}

size_t MetadataCache::Size() const
{
    std::shared_lock<std::shared_mutex> lk(mutex_);
    return by_container_id_.size();
}

} // namespace wazuh::container_connector
