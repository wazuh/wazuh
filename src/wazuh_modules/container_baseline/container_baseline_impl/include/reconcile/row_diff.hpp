#pragma once

#include "reconcile_types.hpp"

#include <utility>

namespace wazuh::container_baseline {

/// @brief Pure per-container row diff — the diffSnapshot() pattern
/// (container_instances/ci_impl/src/cache/reconciler.hpp) re-applied at row
/// granularity. Lock-free, clock-free, I/O-free: directly unit-testable.
///
/// The caller MUST exclude rows from failed dimensions before calling (see
/// CollectStatus) — this function trusts `current` to be the complete, valid set
/// for the dimensions it covers.
///
/// @param prior   Fingerprints of the container's previously-emitted rows, by id.
/// @param current Freshly-scanned rows for the container.
/// @return creates (id not in prior), modifies (id present but content changed,
///         version bumped), deletes (id in prior, absent from current).
[[nodiscard]] inline RowDelta diffRows(const FingerprintMap& prior, const std::vector<EmittedRow>& current)
{
    RowDelta delta;

    std::unordered_map<std::string, bool> seen;
    seen.reserve(current.size());

    for (const auto& row : current)
    {
        if (row.id.empty())
        {
            continue;
        }
        seen.emplace(row.id, true);

        const auto it = prior.find(row.id);
        if (it == prior.end())
        {
            EmittedRow create = row;
            create.operation  = kOperationCreate;
            create.version    = 1;
            delta.creates.push_back(std::move(create));
        }
        else if (it->second.content_hash != contentHash(row.json))
        {
            EmittedRow modify = row;
            modify.operation  = kOperationModify;
            modify.version    = it->second.version + 1;
            delta.modifies.push_back(std::move(modify));
        }
        // else: unchanged — no operation emitted.
    }

    for (const auto& [id, fingerprint] : prior)
    {
        if (seen.find(id) == seen.end())
        {
            delta.deletes.push_back(RowRef{id, fingerprint.index});
        }
    }

    return delta;
}

} // namespace wazuh::container_baseline
