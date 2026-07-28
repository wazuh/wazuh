#pragma once

#include <chrono>
#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "baseline_rows.hpp"               // ContainerIdentity
#include "container_baseline_scanner.hpp"  // EmittedRow, RowSink

namespace wazuh::container_baseline {

// ponytail: container_id / cgroup_id stay std::string / uint64_t (as the scanners
// and ContainerInstancesClient already use them) rather than strong newtypes —
// C++17 map-key newtypes need hand-written std::hash + conversions at every scanner
// call site, unjustified for the spike prototype. Upgrade to ContainerId/CgroupId
// wrappers if a swap bug ever appears at the IPC boundary.

/// @brief Fingerprint of a previously-emitted row. `content_hash` is all that is
/// needed to detect a MODIFY; the full JSON payload lives in the sync queue, not
/// here (re-storing it would just duplicate the queue).
struct RowFingerprint
{
    std::string   index;
    std::uint64_t content_hash{0};
    std::uint64_t version{1};
};

/// @brief A row to delete: id + index only. A DELETE carries no payload.
struct RowRef
{
    std::string id;
    std::string index;
};

/// @brief The outcome of diffing one container's freshly-scanned rows against its
/// prior state. `empty()` means the container's inventory is unchanged.
struct RowDelta
{
    std::vector<EmittedRow> creates;
    std::vector<EmittedRow> modifies;
    std::vector<RowRef>     deletes;

    [[nodiscard]] bool empty() const
    {
        return creates.empty() && modifies.empty() && deletes.empty();
    }
};

/// @brief Distinguishes "dimension scanned, genuinely empty" from "dimension
/// failed to scan". A failed dimension MUST be excluded from the diff, otherwise a
/// transient /proc/setns error would delete every live row of that dimension and
/// re-create it on the next pass (flapping deletes). Making the failed-but-treated-
/// as-empty state unrepresentable is the whole point of the enum.
enum class CollectStatus
{
    Ok,
    Failed
};

/// @brief One dimension's scan result for one container.
struct CollectorResult
{
    std::string             index;  ///< wazuh-states-inventory-* target index.
    CollectStatus           status{CollectStatus::Ok};
    std::vector<EmittedRow> rows;   ///< Valid only when status == Ok.
};

/// @brief Prior-state fingerprints for one container, keyed by row id.
using FingerprintMap = std::unordered_map<std::string, RowFingerprint>;

/// @brief A reconcile pass targets either every container (periodic) or a single
/// container (eBPF-triggered targeted refresh, #37396).
struct ReconcileScope
{
    std::optional<std::string> single_container_id;  ///< nullopt => all containers.
};

/// @brief Injected clock so debounce/TTL logic is deterministic under test.
using SteadyClock = std::function<std::chrono::steady_clock::time_point()>;

/// @brief Sync-protocol Operation values (mirrors agent_sync_protocol_c_interface_types.h
/// without depending on it, matching EmittedRow's int-typed `operation`).
inline constexpr int kOperationCreate = 0;
inline constexpr int kOperationModify = 1;
inline constexpr int kOperationDelete = 2;

/// @brief Stable, fast content hash over an emitted JSON payload (FNV-1a 64-bit).
/// Feeds change-detection only — not a security digest, so no crypto is warranted.
[[nodiscard]] inline std::uint64_t contentHash(const std::string& json)
{
    std::uint64_t hash = 1469598103934665603ULL;  // FNV offset basis
    for (const unsigned char byte : json)
    {
        hash ^= byte;
        hash *= 1099511628211ULL;  // FNV prime
    }
    return hash;
}

} // namespace wazuh::container_baseline
