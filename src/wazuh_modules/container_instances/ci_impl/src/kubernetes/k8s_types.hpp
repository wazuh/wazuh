#pragma once

#include "../core/container_record.hpp"

#include <cstdint>
#include <map>
#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_instances
{

    struct PodContainer
    {
        std::string containerId; ///< Runtime prefix (docker://, containerd://) already stripped.
        std::string name;
        std::string image;
        std::string imageDigest;
        int restartCount {0};
        std::vector<OciMount> mounts;

        /// From containerStatuses[].state. A completed Job or a container in
        /// CrashLoopBackOff stays in the pod list with no process, which is the
        /// Kubernetes shape of the same problem a stopped Docker container
        /// poses: without this it is indistinguishable from one that was
        /// deleted, and its rows get swept.
        ContainerState state {ContainerState::unknown};

        /// From containerStatuses[].state.running.startedAt. The restart
        /// discriminator: a restart keeps the container id, so without this a
        /// container that restarted looks like one that never moved.
        std::string startedAt;
    };

    struct PodSnapshot
    {
        std::string uid;
        std::string name;
        std::string podNamespace;
        std::string nodeName;
        bool hostNetwork {false};
        bool hostPID {false};
        std::string runtimeClassName;
        std::map<std::string, std::string> labels;
        std::map<std::string, std::string> annotations;
        std::vector<OwnerRef> ownerRefs;
        std::vector<NetworkInterface> podIPs;
        std::vector<PodContainer> containers; ///< Pause/sandbox container never appears here.
    };

    struct PodList
    {
        std::vector<PodSnapshot> pods;
        std::string resourceVersion;
    };

    enum class PodEventType : std::uint8_t
    {
        added,
        modified,
        deleted,
        bookmark,
        error
    };

    struct PodWatchEvent
    {
        PodEventType type {PodEventType::error};
        std::string resourceVersion; ///< From the object's metadata (bookmark included).
        PodSnapshot pod;             ///< Valid for added/modified/deleted.
        long errorCode {0};          ///< Valid for error (410 = expired resourceVersion).
    };

    /// Workload metadata for the ownership chain, keyed "Kind|namespace|name".
    /// Value = that workload's own ownerRefs, enabling ReplicaSet -> Deployment and
    /// Job -> CronJob hops.
    using WorkloadIndex = std::unordered_map<std::string, std::vector<OwnerRef>>;

    [[nodiscard]] inline std::string
    workloadKey(const std::string& kind, const std::string& podNamespace, const std::string& name)
    {
        return kind + "|" + podNamespace + "|" + name;
    }

} // namespace wazuh::container_instances
