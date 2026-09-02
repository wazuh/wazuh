#pragma once

#include "k8s_types.hpp"

#include "json.hpp"

#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_instances::k8s
{

    /// "containerd://3f2a..." -> "3f2a...". Unknown/absent prefix left untouched.
    [[nodiscard]] inline std::string stripRuntimePrefix(const std::string& containerId)
    {
        const auto pos = containerId.find("://");
        return (pos == std::string::npos) ? containerId : containerId.substr(pos + 3);
    }

    /// "docker-pullable://repo@sha256:abc" / "repo@sha256:abc" -> "sha256:abc".
    [[nodiscard]] inline std::string extractImageDigest(const std::string& imageId)
    {
        const auto at = imageId.find('@');
        return (at == std::string::npos) ? imageId : imageId.substr(at + 1);
    }

    namespace detail
    {

        [[nodiscard]] inline std::map<std::string, std::string> toStringMap(const nlohmann::json& object)
        {
            std::map<std::string, std::string> result;
            if (object.is_object())
            {
                for (const auto& [key, value] : object.items())
                {
                    if (value.is_string())
                    {
                        result.emplace(key, value.get<std::string>());
                    }
                }
            }
            return result;
        }

        [[nodiscard]] inline std::vector<OwnerRef> parseOwnerRefs(const nlohmann::json& metadata)
        {
            std::vector<OwnerRef> refs;
            for (const auto& ref : metadata.value("ownerReferences", nlohmann::json::array()))
            {
                OwnerRef owner;
                owner.kind = ref.value("kind", "");
                owner.name = ref.value("name", "");
                owner.uid = ref.value("uid", "");
                refs.push_back(std::move(owner));
            }
            return refs;
        }

        /// Joins container volumeMounts with pod volumes: hostPath volumes expose the
        /// host path as source, anything else keeps the volume name.
        [[nodiscard]] inline std::vector<OciMount> parseMounts(const nlohmann::json& containerSpec,
                                                               const nlohmann::json& podSpec)
        {
            std::map<std::string, std::string> volumeSources;
            for (const auto& volume : podSpec.value("volumes", nlohmann::json::array()))
            {
                const auto name = volume.value("name", "");
                if (volume.contains("hostPath"))
                {
                    volumeSources[name] = volume["hostPath"].value("path", name);
                }
                else
                {
                    volumeSources[name] = name;
                }
            }

            std::vector<OciMount> mounts;
            for (const auto& mount : containerSpec.value("volumeMounts", nlohmann::json::array()))
            {
                OciMount entry;
                const auto volumeName = mount.value("name", "");
                const auto source = volumeSources.find(volumeName);
                entry.source = (source != volumeSources.end()) ? source->second : volumeName;
                entry.destination = mount.value("mountPath", "");
                entry.readOnly = mount.value("readOnly", false);
                mounts.push_back(std::move(entry));
            }
            return mounts;
        }

    } // namespace detail

    /// One pod object (from a list or a watch event) -> PodSnapshot. Containers
    /// come from containerStatuses + initContainerStatuses + ephemeralContainerStatuses;
    /// the pause/sandbox container is a runtime implementation detail the API never
    /// reports, so it is filtered by construction.
    [[nodiscard]] inline PodSnapshot parsePod(const nlohmann::json& pod)
    {
        PodSnapshot snapshot;

        const auto& metadata = pod.value("metadata", nlohmann::json::object());
        snapshot.uid = metadata.value("uid", "");
        snapshot.name = metadata.value("name", "");
        snapshot.podNamespace = metadata.value("namespace", "");
        snapshot.labels = detail::toStringMap(metadata.value("labels", nlohmann::json::object()));
        snapshot.annotations = detail::toStringMap(metadata.value("annotations", nlohmann::json::object()));
        snapshot.ownerRefs = detail::parseOwnerRefs(metadata);

        const auto& spec = pod.value("spec", nlohmann::json::object());
        snapshot.nodeName = spec.value("nodeName", "");
        snapshot.hostNetwork = spec.value("hostNetwork", false);
        snapshot.hostPID = spec.value("hostPID", false);
        snapshot.runtimeClassName = spec.value("runtimeClassName", "");

        const auto& status = pod.value("status", nlohmann::json::object());
        for (const auto& podIP : status.value("podIPs", nlohmann::json::array()))
        {
            NetworkInterface iface;
            iface.name = "pod";
            iface.ip = podIP.value("ip", "");
            if (!iface.ip.empty())
            {
                snapshot.podIPs.push_back(std::move(iface));
            }
        }

        // Index container specs by name so statuses can pick up their mounts.
        std::map<std::string, nlohmann::json> specsByName;
        for (const char* specList : {"containers", "initContainers", "ephemeralContainers"})
        {
            for (const auto& containerSpec : spec.value(specList, nlohmann::json::array()))
            {
                specsByName.emplace(containerSpec.value("name", ""), containerSpec);
            }
        }

        for (const char* statusList : {"containerStatuses", "initContainerStatuses", "ephemeralContainerStatuses"})
        {
            for (const auto& containerStatus : status.value(statusList, nlohmann::json::array()))
            {
                PodContainer container;
                container.containerId = stripRuntimePrefix(containerStatus.value("containerID", ""));
                if (container.containerId.empty())
                {
                    continue; // Not started yet: nothing to correlate.
                }
                container.name = containerStatus.value("name", "");
                container.image = containerStatus.value("image", "");
                container.imageDigest = extractImageDigest(containerStatus.value("imageID", ""));
                container.restartCount = containerStatus.value("restartCount", 0);

                const auto specIt = specsByName.find(container.name);
                if (specIt != specsByName.end())
                {
                    container.mounts = detail::parseMounts(specIt->second, spec);
                }

                snapshot.containers.push_back(std::move(container));
            }
        }

        return snapshot;
    }

    /// @throws nlohmann::json::exception on malformed body.
    [[nodiscard]] inline PodList parsePodList(const nlohmann::json& body)
    {
        PodList list;
        list.resourceVersion = body.value("metadata", nlohmann::json::object()).value("resourceVersion", "");
        for (const auto& pod : body.value("items", nlohmann::json::array()))
        {
            list.pods.push_back(parsePod(pod));
        }
        return list;
    }

    /// One watch NDJSON line -> event. nullopt = unparseable line (caller logs and
    /// skips; never throws on stream data).
    [[nodiscard]] inline std::optional<PodWatchEvent> parseWatchLine(std::string_view line)
    {
        const auto parsed = nlohmann::json::parse(line, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return std::nullopt;
        }

        PodWatchEvent event;
        const auto type = parsed.value("type", "");
        const auto& object = parsed.value("object", nlohmann::json::object());

        if (type == "ERROR")
        {
            event.type = PodEventType::error;
            event.errorCode = object.value("code", 0);
            return event;
        }
        if (type == "BOOKMARK")
        {
            event.type = PodEventType::bookmark;
            event.resourceVersion = object.value("metadata", nlohmann::json::object()).value("resourceVersion", "");
            return event;
        }
        if (type == "ADDED")
        {
            event.type = PodEventType::added;
        }
        else if (type == "MODIFIED")
        {
            event.type = PodEventType::modified;
        }
        else if (type == "DELETED")
        {
            event.type = PodEventType::deleted;
        }
        else
        {
            return std::nullopt; // Unknown event type: ignore.
        }

        event.resourceVersion = object.value("metadata", nlohmann::json::object()).value("resourceVersion", "");
        event.pod = parsePod(object);
        return event;
    }

    /// Merges one workload list response (apps/v1 or batch/v1) into the index.
    inline void mergeWorkloadList(const nlohmann::json& body, WorkloadIndex& index)
    {
        const auto kind = body.value("kind", ""); // e.g. "ReplicaSetList".
        const auto itemKind =
            (kind.size() > 4 && kind.substr(kind.size() - 4) == "List") ? kind.substr(0, kind.size() - 4) : kind;

        for (const auto& item : body.value("items", nlohmann::json::array()))
        {
            const auto& metadata = item.value("metadata", nlohmann::json::object());
            const auto key =
                workloadKey(item.value("kind", itemKind), metadata.value("namespace", ""), metadata.value("name", ""));
            index[key] = detail::parseOwnerRefs(metadata);
        }
    }

    /// Walks the ownership chain for one pod: direct ownerRefs plus one transitive
    /// hop through the index (ReplicaSet -> Deployment, Job -> CronJob).
    [[nodiscard]] inline std::vector<OwnerRef> resolveOwnerChain(const PodSnapshot& pod, const WorkloadIndex& index)
    {
        std::vector<OwnerRef> chain = pod.ownerRefs;
        for (const auto& direct : pod.ownerRefs)
        {
            const auto it = index.find(workloadKey(direct.kind, pod.podNamespace, direct.name));
            if (it != index.end())
            {
                for (const auto& transitive : it->second)
                {
                    chain.push_back(transitive);
                }
            }
        }
        return chain;
    }

} // namespace wazuh::container_instances::k8s
