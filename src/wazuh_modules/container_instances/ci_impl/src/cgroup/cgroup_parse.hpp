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
    /// `preferredController` is the controller the SHARED selector
    /// (`wz_cgroup_v1_select_subsys`) chose for this host, and when it is set it
    /// is tried first. The two lists hold the same names but apply different
    /// filters — the shared one also demands a subsystem slot, so it rejects
    /// `name=systemd` while this one accepts it — and a host where they disagree
    /// is a host where the resolver keys on one hierarchy and the eBPF program
    /// reads another. Empty keeps the local order, which is what the fixture
    /// tests use so they need no live host.
    [[nodiscard]] inline std::optional<CgroupSelection> selectCanonicalCgroup(const std::vector<CgroupLine>& lines,
                                                                              wz_cgroup_mode_t mode,
                                                                              std::string_view preferredController = {})
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

        const auto pick = [&lines](std::string_view wanted) -> std::optional<CgroupSelection>
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
            return std::nullopt;
        };

        if (!preferredController.empty())
        {
            if (auto chosen = pick(preferredController))
            {
                return chosen;
            }
        }

        for (const auto& wanted : CGROUP_V1_CONTROLLER_PRIORITY)
        {
            if (auto chosen = pick(wanted))
            {
                return chosen;
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

    /// Matches ONE cgroup path component against the known container naming
    /// schemes. Carried over from the #36095 prototype.
    [[nodiscard]] inline std::optional<CriMatch> matchContainerIdComponent(const std::string& component)
    {
        static const std::regex scopePattern {R"(^(cri-containerd-|crio-|docker-)([0-9a-f]{12,128})\.scope$)"};
        static const std::regex bareHexPattern {R"(^[0-9a-f]{32,128}$)"}; // cgroupfs driver.

        const std::string& leaf = component;

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

    /// Finds the container a cgroup path belongs to, scanning its components
    /// INNERMOST FIRST and stopping at the first match.
    ///
    /// This used to match the leaf basename only, so that an outer-Docker wrap
    /// (kind/k3d/minikube) could not mask the inner container that actually owns
    /// the process. Scanning right to left preserves that property exactly — a
    /// matching leaf is still found first and still wins — while also resolving
    /// the case leaf-only matching could not: a container whose PID 1 is an init
    /// system puts every process in a CHILD cgroup of the container's own, so no
    /// process ever reports the container's cgroup as its leaf.
    ///
    ///     /docker/<id>                                  -> <id>   (unchanged)
    ///     /system.slice/docker-<id>.scope               -> <id>   (unchanged)
    ///     /…/kubelet.slice/…/cri-containerd-<pod>.scope -> <pod>  (unchanged: leaf wins)
    ///     /docker/<id>/init.scope                       -> <id>   (was: nothing)
    ///     /user.slice/user-1000.slice/session-3.scope   -> nothing (unchanged)
    ///
    /// Right-to-left is therefore a strict superset of the old behaviour: it
    /// returns a match wherever the leaf rule did, with the same value, and adds
    /// one only where the leaf rule returned nothing at all.
    [[nodiscard]] inline std::optional<CriMatch> extractContainerId(const std::string& cgroupPath)
    {
        std::size_t end = cgroupPath.size();

        while (end > 0)
        {
            // Skip a trailing separator, then take the component before it.
            if (cgroupPath[end - 1] == '/')
            {
                --end;
                continue;
            }

            const auto slash = cgroupPath.find_last_of('/', end - 1);
            const auto begin = (slash == std::string::npos) ? 0U : slash + 1U;

            if (auto match = matchContainerIdComponent(cgroupPath.substr(begin, end - begin)))
            {
                return match;
            }

            if (begin == 0U)
            {
                break;
            }
            end = begin - 1U; // step over the separator onto the parent component
        }

        return std::nullopt;
    }

} // namespace wazuh::container_instances
