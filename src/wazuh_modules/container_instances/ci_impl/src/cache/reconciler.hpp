#pragma once

#include "../core/container_record.hpp"

#include <string>
#include <unordered_map>
#include <vector>

namespace wazuh::container_instances
{

    struct ReconcileDelta
    {
        std::vector<ContainerRecord> added;
        std::vector<ContainerRecord> updated;
        std::vector<std::string> removedContainerIds;
    };

    [[nodiscard]] inline bool recordEquals(const ContainerRecord& a, const ContainerRecord& b)
    {
        return a.runtime == b.runtime && a.containerId == b.containerId && a.containerName == b.containerName &&
               a.image == b.image && a.imageDigest == b.imageDigest && a.restartCount == b.restartCount &&
               a.podUid == b.podUid && a.podName == b.podName && a.podNamespace == b.podNamespace &&
               a.nodeName == b.nodeName && a.labels == b.labels && a.annotations == b.annotations &&
               a.ownerRefs == b.ownerRefs && a.network == b.network && a.ociMounts == b.ociMounts &&
               a.cgroupId == b.cgroupId;
    }

    /// Pure full-snapshot diff on the container-id string. The store applies the
    /// delta; keeping the diff free of locks and threads makes the reconcile logic
    /// directly testable.
    [[nodiscard]] inline ReconcileDelta diffSnapshot(const std::unordered_map<std::string, ContainerRecordPtr>& current,
                                                     const std::vector<ContainerRecord>& incoming)
    {
        ReconcileDelta delta;
        std::unordered_map<std::string, bool> seen;
        seen.reserve(incoming.size());

        for (const auto& record : incoming)
        {
            if (record.containerId.empty())
            {
                continue;
            }
            seen.emplace(record.containerId, true);

            const auto it = current.find(record.containerId);
            if (it == current.end())
            {
                delta.added.push_back(record);
            }
            else if (!recordEquals(*it->second, record))
            {
                delta.updated.push_back(record);
            }
        }

        for (const auto& [containerId, record] : current)
        {
            if (seen.find(containerId) == seen.end())
            {
                delta.removedContainerIds.push_back(containerId);
            }
        }

        return delta;
    }

} // namespace wazuh::container_instances
