#pragma once

#include "container_context.hpp"

#include <sys/types.h>

#include <cstdint>
#include <string>
#include <vector>

namespace wazuh::container_baseline {

/// @brief The container's resource envelope as "virtual hardware", filling the
/// same fields host syscollector emits for physical hardware
/// (wazuh-states-inventory-hardware).
///
/// A container cannot change the node's silicon, so cpu_name/cpu_speed are the
/// shared host values (from /proc/cpuinfo). What *is* container-specific is the
/// cgroup limit: memory.max and cpu.max bound what the container may use. Those
/// map onto memory_total and cpu_cores so the manager — which knows the row is a
/// container's via the container_id block — can treat it as virtual hardware
/// distinct from the node's real hardware row.
struct HardwareBaselineRow
{
    std::string cpu_name;        ///< Physical CPU model (shared host silicon).
    int64_t     cpu_cores{0};    ///< Effective cores from cpu.max (quota/period); host logical count if unlimited.
    double      cpu_speed{0};    ///< MHz (physical host clock).
    int64_t     memory_total{0}; ///< bytes — memory.max, or host MemTotal when unlimited.
    int64_t     memory_free{0};  ///< bytes — memory_total − memory_used.
    int64_t     memory_used{0};  ///< bytes — memory.current.

    std::string        container_id;
    ContainerContextPtr container; ///< null until ApplyIdentity() stamps it.
};

/// @brief Effective core count from a cgroup v2 cpu.max value ("<quota> <period>"
/// or "max <period>"). Partial quotas round up (0.5 cores → 1). Returns 0 for the
/// unlimited "max" case. Exposed for unit testing.
[[nodiscard]] int64_t CoresFromCpuMax(const std::string& cpu_max);

/// @brief Parse a cgroup limit value: a byte count, or "max" → 0 (unlimited).
/// Exposed for unit testing.
[[nodiscard]] int64_t ParseCgroupBytes(const std::string& value);

/// @brief Read the container's cgroup v2 resource envelope (memory.max/current,
/// cpu.max) as one virtual-hardware row. cpu_name/speed come from the shared host
/// /proc/cpuinfo. Unlimited limits fall back to the host total (the container
/// genuinely sees all of it). Empty result if the cgroup is unreadable or the pid
/// is on a v1-only hierarchy.
/// @return 0 or 1 rows.
[[nodiscard]] std::vector<HardwareBaselineRow> ScanContainerHardware(pid_t pid);

} // namespace wazuh::container_baseline
