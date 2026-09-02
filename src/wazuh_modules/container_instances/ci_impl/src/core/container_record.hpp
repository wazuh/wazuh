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
        std::uint64_t cgroupId {0}; ///< cgroup v2 inode; 0 = not yet joined with the resolver output.
    };

    /// Records are immutable after publication so IPC readers can hold one after the
    /// writer has replaced it in the store.
    using ContainerRecordPtr = std::shared_ptr<const ContainerRecord>;

} // namespace wazuh::container_instances
