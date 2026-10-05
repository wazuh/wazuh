#pragma once

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    enum class ContainerRuntime : std::uint8_t
    {
        kubernetes,
        docker
    };

    /// Lifecycle state, normalised across runtimes.
    ///
    /// Deliberately coarse: consumers only ever ask "does this container have a
    /// process right now", so Docker's created/restarting/removing/paused/exited
    /// /dead and Kubernetes' waiting/running/terminated collapse to two useful
    /// answers plus a sentinel. Anything finer would be vocabulary nobody reads,
    /// and would have to be kept in step with two runtimes' own enums.
    enum class ContainerState : std::uint8_t
    {
        /// The runtime did not say. Treated as `running` wherever the
        /// distinction matters, so an unparsed state can never cause a
        /// container's rows to be swept.
        unknown,

        /// Has a process; a cgroup inode is expected and its absence means the
        /// resolver has not caught up.
        running,

        /// No process, but the container still exists and its filesystem is
        /// still on disk. Its rows are kept.
        stopped
    };

    /// True when the container is expected to have a cgroup inode.
    ///
    /// `unknown` counts as running on purpose: the only thing this gates is
    /// whether a record with no inode is withheld as "not ready yet", and
    /// withholding briefly is recoverable whereas publishing a container that
    /// turns out to have no usable cgroup is not.
    [[nodiscard]] inline bool isRunning(ContainerState state)
    {
        return state != ContainerState::stopped;
    }

    struct OwnerRef
    {
        std::string kind;
        std::string name;
        std::string uid;

        bool operator==(const OwnerRef& other) const
        {
            return kind == other.kind && name == other.name && uid == other.uid;
        }
    };

    struct NetworkInterface
    {
        std::string name;
        std::string ip;

        bool operator==(const NetworkInterface& other) const
        {
            return name == other.name && ip == other.ip;
        }
    };

    struct OciMount
    {
        std::string source;
        std::string destination;
        bool readOnly {false};

        bool operator==(const OciMount& other) const
        {
            return source == other.source && destination == other.destination && readOnly == other.readOnly;
        }
    };

    /// The enrichment record served to FIM / IT Hygiene. Docker populates a subset:
    /// podUid/podName/podNamespace/ownerRefs/annotations stay empty (Kubernetes-only
    /// concepts). `runtime` tells consumers which subset to expect.
    struct ContainerRecord
    {
        ContainerRuntime runtime {ContainerRuntime::docker};
        std::string containerId;
        std::string containerName;
        std::string image;
        std::string imageDigest;
        int restartCount {0};
        std::string podUid;
        std::string podName;
        std::string podNamespace;
        std::string nodeName;
        std::map<std::string, std::string> labels;
        std::map<std::string, std::string> annotations;
        std::vector<OwnerRef> ownerRefs;
        std::vector<NetworkInterface> network;
        std::vector<OciMount> ociMounts;
        /// cgroup v2 inode; 0 = no cgroup to join. For a RUNNING container that
        /// means the resolver has not caught up yet and the record is not ready
        /// to publish; for any other state it is simply what a container with no
        /// process has. `state` is what tells those two apart — before it
        /// existed, zero meant only the first, and a stopped container was
        /// indistinguishable from an unresolved one.
        std::uint64_t cgroupId {0};

        /// When the current run of this container began, verbatim from the
        /// runtime (RFC 3339).
        ///
        /// This is THE restart discriminator, and nothing else in the record
        /// is. A restart keeps the container id, so without it a container that
        /// stopped and started again is indistinguishable from one that never
        /// moved — its files and processes are new, and nothing would say so.
        /// `restartCount` does not serve: it is driven by the restart POLICY,
        /// so a container restarted by hand does not increment it.
        std::string startedAt;

        /// Main process id of the current run, 0 when it has none.
        ///
        /// Carried because the consumers already need it and currently each
        /// rediscover it by walking /proc: the runtime knew it all along.
        int pid {0};

        /// Lifecycle state as the runtime reports it, normalised across Docker
        /// and Kubernetes.
        ///
        /// It exists so a stop can be told from a deletion. A stopped container
        /// keeps its rows — its files and packages are still on disk and still
        /// worth reporting — whereas a deleted one must have them swept, and
        /// without this field the two look identical from outside: both simply
        /// stop having a process.
        ContainerState state {ContainerState::unknown};
    };

    /// Records are immutable after publication so IPC readers can hold one after the
    /// writer has replaced it in the store.
    using ContainerRecordPtr = std::shared_ptr<const ContainerRecord>;

} // namespace wazuh::container_instances
