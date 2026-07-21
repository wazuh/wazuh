#pragma once

#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One container network attachment (Docker: its own bridge/overlay
/// network; Kubernetes: the pod's IP, since containers in a pod share one
/// network namespace).
struct NetworkEndpoint
{
    std::string name;
    std::string ip;
};

/// @brief One bind mount / volume mount into the container's rootfs.
struct OciMountEntry
{
    std::string source;
    std::string destination;
    bool        read_only{false};
};

/// @brief One entry in a Kubernetes object's ownerReferences chain (e.g. a Pod
/// owned by a ReplicaSet owned by a Deployment).
struct OwnerReference
{
    std::string kind;
    std::string name;
    std::string uid;
};

/// @brief Kubernetes-only enrichment. Present only when the container's
/// container_instances record resolved to a Pod; absent for Docker-origin
/// containers, which have no such concepts.
struct KubernetesContext
{
    std::string pod_uid;
    std::string pod_name;
    std::string k8s_namespace;
    std::string node_name;
    std::map<std::string, std::string> annotations;
    std::vector<OwnerReference>        owner_refs;
};

/// @brief Generic container runtime context (Docker, containerd, CRI-O, ...),
/// resolved once per container via container_instances and shared (through
/// ContainerContextPtr) across every row produced for that container, rather
/// than copying labels/network/mounts once per file/process/package row.
struct ContainerContext
{
    std::string runtime;       ///< "docker" or "kubernetes" (container_instances' data-source label).
    std::string name;
    std::string image;
    std::string image_digest;
    int         restart_count{0};
    std::map<std::string, std::string> labels;
    std::vector<NetworkEndpoint>       network;
    std::vector<OciMountEntry>         oci_mounts;
    std::optional<KubernetesContext>   kubernetes; ///< absent for Docker-origin containers.
};

/// Immutable after construction: one instance is shared by every row emitted
/// for the same container within a baseline run.
using ContainerContextPtr = std::shared_ptr<const ContainerContext>;

} // namespace wazuh::container_baseline
