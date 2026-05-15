#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace wazuh::container_connector {

struct OwnerRef
{
    std::string kind;
    std::string name;
};

/// @brief Pod-level metadata, shared by every container that lives in the pod.
struct PodInfo
{
    std::string                          pod_uid;
    std::string                          pod_name;
    std::string                          namespace_;
    std::string                          node_name;
    std::map<std::string, std::string>   labels;
    std::map<std::string, std::string>   annotations;
    std::vector<OwnerRef>                owner_refs;
};

/// @brief Per-container record stored in the cache.
///
/// Holds a back-reference to its PodInfo so any join (e.g. "given a cgroup_id, what
/// namespace/pod_name does it belong to") is a single hash lookup followed by
/// dereferencing the shared_ptr.
///
/// cgroup_id is resolved on a best-effort basis in T-K3 (left as 0 if unresolvable);
/// T-K5 will tighten the cgroupfs path resolution.
struct ContainerInPod
{
    std::string  container_id;   ///< CRI ID without the runtime prefix.
    std::string  name;           ///< Kubernetes container name (e.g. "nginx").
    std::string  image;
    std::string  image_id;
    int          restart_count{0};
    uint64_t     cgroup_id{0};   ///< 0 => not resolved.

    std::shared_ptr<PodInfo> pod;
};

/// @brief Snapshot of a pod plus the containers we currently track for it.
struct PodSnapshot
{
    std::shared_ptr<PodInfo>    pod;
    std::vector<ContainerInPod> containers;
};

} // namespace wazuh::container_connector
