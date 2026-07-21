#pragma once

#include "container_context.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief One process baseline row. Field names mirror syscollector's
/// PROCESSES_SQL_STATEMENT (dbsync_processes) column-for-column, plus the same
/// container-context fields used throughout this module.
struct ProcessBaselineRow
{
    std::string pid;
    std::string name;
    std::string state;
    int64_t     parent_pid{0};
    int64_t     utime{0};
    int64_t     stime{0};
    std::string command_line;
    std::string args;         ///< Remaining argv, space-joined (argv[0] is command_line).
    int64_t     args_count{0};
    std::string start;        ///< Process start time as a Unix epoch-seconds string.

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Enumerate every live process in a container's PID namespace, scoped
/// by cgroup (via ResolvePidsForContainer), and build one baseline row per PID
/// from /proc/<pid>/{stat,cmdline}.
///
/// No exec, no external tooling: this is the same class of host-side /proc read
/// container_instances already relies on for cgroup_id
/// resolution (Angle 2 in the spike). Processes that exit between
/// ResolvePidsForContainer() and the /proc/<pid>/stat read are silently skipped
/// (best-effort snapshot, same race window any /proc-based enumeration has).
std::vector<ProcessBaselineRow> ScanContainerProcesses(const std::string& container_id);

} // namespace wazuh::container_baseline
