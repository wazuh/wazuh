#pragma once

#include "i_cgroup_resolver.hpp"

#include <optional>
#include <regex>
#include <string>
#include <string_view>

namespace wazuh::container_instances
{

    /// Extracts the cgroup v2 unified-hierarchy path from one /proc/<pid>/cgroup
    /// line ("0::/kubepods.slice/.../cri-containerd-abc.scope"). Returns nullopt
    /// for v1 controller lines.
    [[nodiscard]] inline std::optional<std::string> parseCgroupV2Line(std::string_view line)
    {
        constexpr std::string_view prefix {"0::"};
        if (line.substr(0, prefix.size()) != prefix)
        {
            return std::nullopt;
        }
        auto path = line.substr(prefix.size());
        if (!path.empty() && path.back() == '\n')
        {
            path.remove_suffix(1);
        }
        if (path.empty())
        {
            return std::nullopt;
        }
        return std::string {path};
    }

    struct CriMatch
    {
        std::string containerId;
        RuntimeHint hint {RuntimeHint::unknown};
    };

    /// Matches the LEAF basename of a cgroup path against the known container
    /// naming schemes. Leaf-only matching survives outer-Docker wraps
    /// (kind/k3d/minikube). Carried over from the #36095 prototype.
    [[nodiscard]] inline std::optional<CriMatch> extractContainerId(const std::string& cgroupPath)
    {
        static const std::regex scopePattern {R"(^(cri-containerd-|crio-|docker-)([0-9a-f]{12,128})\.scope$)"};
        static const std::regex bareHexPattern {R"(^[0-9a-f]{32,128}$)"}; // cgroupfs driver.

        const auto slash = cgroupPath.find_last_of('/');
        const std::string leaf = (slash == std::string::npos) ? cgroupPath : cgroupPath.substr(slash + 1);

        std::smatch match;
        if (std::regex_match(leaf, match, scopePattern))
        {
            const std::string& runtimePrefix = match[1];
            auto hint = RuntimeHint::unknown;
            if (runtimePrefix == "cri-containerd-")
            {
                hint = RuntimeHint::containerd;
            }
            else if (runtimePrefix == "crio-")
            {
                hint = RuntimeHint::crio;
            }
            else if (runtimePrefix == "docker-")
            {
                hint = RuntimeHint::docker;
            }
            CriMatch result;
            result.containerId = match[2];
            result.hint = hint;
            return result;
        }

        if (std::regex_match(leaf, bareHexPattern))
        {
            CriMatch result;
            result.containerId = leaf;
            result.hint = RuntimeHint::unknown;
            return result;
        }

        return std::nullopt;
    }

} // namespace wazuh::container_instances
