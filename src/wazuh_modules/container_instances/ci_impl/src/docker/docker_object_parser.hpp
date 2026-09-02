#pragma once

#include "docker_types.hpp"

#include "json.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_instances::docker
{

    /// Lifecycle actions the connector reacts to; everything else on /events is noise.
    [[nodiscard]] inline bool isRelevantAction(const std::string& action)
    {
        static constexpr std::array<std::string_view, 5> kRelevant {"start", "die", "destroy", "rename", "update"};
        return std::any_of(
            kRelevant.begin(), kRelevant.end(), [&action](std::string_view relevant) { return action == relevant; });
    }

    /// GET /containers/json response -> summaries. @throws nlohmann::json::exception.
    [[nodiscard]] inline std::vector<ContainerSummary> parseContainerList(const nlohmann::json& body)
    {
        std::vector<ContainerSummary> summaries;
        for (const auto& item : body)
        {
            ContainerSummary summary;
            summary.id = item.value("Id", "");
            if (!summary.id.empty())
            {
                summaries.push_back(std::move(summary));
            }
        }
        return summaries;
    }

    /// GET /containers/{id}/json response -> record (Docker subset: pod/namespace/
    /// owner/annotation fields stay empty). @throws nlohmann::json::exception.
    [[nodiscard]] inline ContainerDetail parseInspect(const nlohmann::json& body)
    {
        ContainerDetail detail;
        ContainerRecord& record = detail.record;
        record.runtime = ContainerRuntime::docker;
        record.containerId = body.value("Id", "");
        record.restartCount = body.value("RestartCount", 0);

        auto name = body.value("Name", "");
        if (!name.empty() && name.front() == '/')
        {
            name.erase(0, 1);
        }
        record.containerName = std::move(name);

        const auto config = body.value("Config", nlohmann::json::object());
        record.image = config.value("Image", "");
        record.imageDigest = body.value("Image", ""); // Image ID (sha256:...).
        // Named local: iterating .items() on a temporary dangles.
        const auto labels = config.value("Labels", nlohmann::json::object());
        for (const auto& [key, value] : labels.items())
        {
            if (value.is_string())
            {
                record.labels.emplace(key, value.get<std::string>());
            }
        }

        const auto networks =
            body.value("NetworkSettings", nlohmann::json::object()).value("Networks", nlohmann::json::object());
        for (const auto& [networkName, settings] : networks.items())
        {
            NetworkInterface iface;
            iface.name = networkName;
            iface.ip = settings.value("IPAddress", "");
            if (!iface.ip.empty())
            {
                record.network.push_back(std::move(iface));
            }
        }

        for (const auto& mount : body.value("Mounts", nlohmann::json::array()))
        {
            OciMount entry;
            entry.source = mount.value("Source", mount.value("Name", ""));
            entry.destination = mount.value("Destination", "");
            entry.readOnly = !mount.value("RW", true);
            record.ociMounts.push_back(std::move(entry));
        }

        return detail;
    }

    /// One /events NDJSON line -> event. nullopt = non-container, irrelevant
    /// action, or unparseable line (caller skips; never throws on stream data).
    [[nodiscard]] inline std::optional<DockerEvent> parseEventLine(std::string_view line)
    {
        const auto parsed = nlohmann::json::parse(line, nullptr, false);
        if (parsed.is_discarded() || !parsed.is_object())
        {
            return std::nullopt;
        }
        if (parsed.value("Type", "") != "container")
        {
            return std::nullopt;
        }

        DockerEvent event;
        event.action = parsed.value("Action", "");
        if (!isRelevantAction(event.action))
        {
            return std::nullopt;
        }

        event.containerId = parsed.value("id", "");
        if (event.containerId.empty())
        {
            event.containerId = parsed.value("Actor", nlohmann::json::object()).value("ID", "");
        }
        if (event.containerId.empty())
        {
            return std::nullopt;
        }

        event.timeNano = parsed.value("timeNano", static_cast<std::int64_t>(0));
        return event;
    }

} // namespace wazuh::container_instances::docker
