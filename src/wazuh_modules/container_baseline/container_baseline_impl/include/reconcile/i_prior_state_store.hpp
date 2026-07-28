#pragma once

#include <cstddef>
#include <string>
#include <unordered_map>
#include <vector>

#include "reconcile/reconcile_types.hpp"

namespace wazuh::container_baseline {

/// @brief Durable memory of the rows previously emitted per container, so the
/// reconciler can compute MODIFY/DELETE deltas and clean up rows of containers
/// that exited while the agent was down.
///
/// Prior-state is a cache, never the source of truth: the sync queue upserts by
/// id, so total loss just triggers one idempotent re-baseline. Correctness rests
/// on the reconciler's emit-first ordering (push to the sink, then applyDelta
/// here) — a crash in between re-emits harmlessly next pass.
class IPriorStateStore
{
public:
    virtual ~IPriorStateStore() = default;

    /// @brief Fingerprints of one container's previously-emitted rows, by row id.
    [[nodiscard]] virtual FingerprintMap load(const std::string& container_id) = 0;

    /// @brief Every container id that currently has stored rows. Used to find
    /// containers that vanished from the live set (their rows must be deleted).
    [[nodiscard]] virtual std::vector<std::string> knownContainerIds() = 0;

    /// @brief Count of currently-tracked rows per index. Seeds the reconciler's
    /// per-index document-limit ceiling (NFR3).
    [[nodiscard]] virtual std::unordered_map<std::string, std::size_t> countByIndex() = 0;

    /// @brief Persist an emitted delta for a container. MUST be called only after
    /// the rows have been handed to the sink (emit-first ordering). Inserts the
    /// creates, updates the modifies, removes the deletes.
    virtual void applyDelta(const std::string& container_id, const RowDelta& delta) = 0;

    /// @brief Drop all stored rows for a container (after its exit deletes are
    /// emitted).
    virtual void purgeContainer(const std::string& container_id) = 0;
};

} // namespace wazuh::container_baseline
