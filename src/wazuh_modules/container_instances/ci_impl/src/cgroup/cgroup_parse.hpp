#pragma once

#include "i_cgroup_resolver.hpp"

#include "cgroup_host_mode.h"

#include <algorithm>
#include <array>
#include <optional>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace wazuh::container_instances
{

    /// One line of /proc/<pid>/cgroup, which is always
    /// "<hierarchy-id>:<controller-list>:<path>".
    ///
    /// The v2 line is the degenerate case: hierarchy 0 and an empty controller
    /// list. Until cgroup v1 support this parser accepted ONLY that case and
    /// returned nullopt for everything else, which is why a v1 host resolved no
    /// containers at all and therefore reported none (#37203 O4).
    struct CgroupLine
    {
        int hierarchyId {0};
        std::string controllers; ///< Empty on the v2 line.
        std::string path;        ///< Relative to that hierarchy's mount point.

        [[nodiscard]] bool isUnified() const
        {
            return hierarchyId == 0 && controllers.empty();
        }
    };

    [[nodiscard]] inline std::optional<CgroupLine> parseCgroupLine(std::string_view line)
    {
        if (!line.empty() && line.back() == '\n')
        {
            line.remove_suffix(1);
        }

        const auto firstColon = line.find(':');
        if (firstColon == std::string_view::npos)
        {
            return std::nullopt;
        }
        const auto secondColon = line.find(':', firstColon + 1);
        if (secondColon == std::string_view::npos)
        {
            return std::nullopt;
        }

        const auto idText = line.substr(0, firstColon);
        if (idText.empty() ||
            !std::all_of(idText.begin(), idText.end(), [](unsigned char c) { return std::isdigit(c) != 0; }))
        {
            return std::nullopt;
        }

        // The path may itself contain ':' — systemd scope names do — so it is
        // everything after the second colon, not the next field.
        const auto path = line.substr(secondColon + 1);
        if (path.empty() || path.front() != '/')
        {
            return std::nullopt;
        }

        CgroupLine parsed;
        parsed.hierarchyId = std::stoi(std::string {idText});
        parsed.controllers = std::string {line.substr(firstColon + 1, secondColon - firstColon - 1)};
        parsed.path = std::string {path};
        return parsed;
    }

    /// Which hierarchy a process's cgroup path was taken from, and where that
    /// hierarchy is mounted relative to the cgroup root.
    struct CgroupSelection
    {
        std::string path;        ///< Path within the hierarchy.
        std::string mountSubdir; ///< "" for v2 at the root, "unified" on hybrid, "memory" on v1.
        std::string controller;  ///< Which controller was chosen; "" when the unified line was used.
    };

    /// On v1 every controller is a SEPARATE mount with its OWN inode, so one of
    /// them has to be picked and the same one picked everywhere — a resolver that
    /// chose per process would file one container's processes under several keys.
    ///
    /// Ordered by how reliably each is mounted and how closely it tracks the
    /// container rather than the host: `memory` and `pids` are per-container on
    /// every runtime, `cpu,cpuacct` is nearly always mounted, and `name=systemd`
    /// is the last resort because it exists even where no controller does.
    inline constexpr std::array<std::string_view, 4> CGROUP_V1_CONTROLLER_PRIORITY {
        "memory", "pids", "cpuacct", "systemd"};

    /// True when `controllers` (a comma-separated list, possibly with `name=`
    /// prefixes) contains `wanted` as a whole element.
    [[nodiscard]] inline bool controllerListContains(std::string_view controllers, std::string_view wanted)
    {
        std::size_t start = 0;
        while (start <= controllers.size())
        {
            const auto comma = controllers.find(',', start);
            auto element =
                controllers.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
            // "name=systemd" is mounted at <root>/systemd, so the name= prefix is
            // part of the mount OPTION and not of the directory.
            if (element.substr(0, 5) == "name=")
            {
                element.remove_prefix(5);
            }
            if (element == wanted)
            {
                return true;
            }
            if (comma == std::string_view::npos)
            {
                break;
            }
            start = comma + 1;
        }
        return false;
    }

    /// The directory a controller line's hierarchy is mounted at, relative to the
    /// cgroup root: the controller list verbatim, minus any `name=` prefixes.
    [[nodiscard]] inline std::string controllerMountSubdir(std::string_view controllers)
    {
        std::string subdir;
        std::size_t start = 0;
        while (start <= controllers.size())
        {
            const auto comma = controllers.find(',', start);
            auto element =
                controllers.substr(start, comma == std::string_view::npos ? std::string_view::npos : comma - start);
            if (element.substr(0, 5) == "name=")
            {
                element.remove_prefix(5);
            }
            if (!subdir.empty())
            {
                subdir += ',';
            }
            subdir.append(element);
            if (comma == std::string_view::npos)
            {
                break;
            }
            start = comma + 1;
        }
        return subdir;
    }

    /// Picks the one hierarchy this process's cgroup will be keyed by.
    ///
    /// `mode` is a HOST CONSTANT, never derived per process: mixing kinds within
    /// one store would reintroduce exactly the ambiguity the split is meant to
    /// remove. On unified and hybrid hosts the v2 line wins outright — it is the
    /// hierarchy whose inode `bpf_get_current_cgroup_id()` reports, so choosing a
    /// v1 controller there would key the store on a number no event carries.
    [[nodiscard]] inline std::optional<CgroupSelection> selectCanonicalCgroup(const std::vector<CgroupLine>& lines,
                                                                              wz_cgroup_mode_t mode)
    {
        if (mode != WZ_CGROUP_MODE_LEGACY)
        {
            for (const auto& line : lines)
            {
                if (line.isUnified())
                {
                    CgroupSelection selection;
                    selection.path = line.path;
                    // On a hybrid host the unified hierarchy is NOT at the cgroup
                    // root; it is mounted beside the v1 controllers. Statting
                    // <root><path> there finds nothing, which is why a hybrid host
                    // resolved no containers even though its ids were usable.
                    selection.mountSubdir = (mode == WZ_CGROUP_MODE_HYBRID) ? "unified" : "";
                    return selection;
                }
            }
            return std::nullopt;
        }

        for (const auto& wanted : CGROUP_V1_CONTROLLER_PRIORITY)
        {
            for (const auto& line : lines)
            {
                if (!line.isUnified() && controllerListContains(line.controllers, wanted))
                {
                    CgroupSelection selection;
                    selection.path = line.path;
                    selection.mountSubdir = controllerMountSubdir(line.controllers);
                    selection.controller = std::string {wanted};
                    return selection;
                }
            }
        }

        // None of the four is mounted. Producing no key leaves the record
        // unlisted exactly as before, and the startup mode log explains why.
        return std::nullopt;
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
