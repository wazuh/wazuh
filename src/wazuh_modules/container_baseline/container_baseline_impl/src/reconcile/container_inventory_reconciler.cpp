#include "reconcile/container_inventory_reconciler.hpp"

#include <iterator>
#include <unordered_set>
#include <utility>

#include "reconcile/row_diff.hpp"

namespace wazuh::container_baseline {

ContainerInventoryReconciler::ContainerInventoryReconciler(
    IContainerLister& lister, IPriorStateStore& store, CollectFn collect, RowSink sink, DocumentLimits limits)
    : m_lister(lister)
    , m_store(store)
    , m_collect(std::move(collect))
    , m_sink(std::move(sink))
    , m_limits(std::move(limits))
{
}

std::size_t ContainerInventoryReconciler::limitFor(const std::string& index) const
{
    const auto it = m_limits.find(index);
    return it == m_limits.end() ? 0 : it->second;
}

ReconcileStats ContainerInventoryReconciler::reconcile(const ReconcileScope& scope)
{
    ReconcileStats stats;

    const auto listing = m_lister.list();
    if (!listing.available)
    {
        // Container Instances unreachable — an empty/failed answer here would
        // otherwise delete the whole container inventory. Skip this pass entirely.
        stats.skipped_unavailable = true;
        return stats;
    }

    const bool targeted  = scope.single_container_id.has_value();
    const bool firstPass = m_first_pass;

    // Per-index ceiling seeded from currently-tracked rows (NFR3). Mutated as
    // creates are admitted and deletes remove rows.
    auto counts = m_store.countByIndex();

    const auto emitDelete = [&](const RowRef& ref) {
        m_sink(EmittedRow {ref.id, kOperationDelete, ref.index, "", 0});
        ++stats.deletes;
        if (const auto it = counts.find(ref.index); it != counts.end() && it->second > 0)
        {
            --it->second;
        }
    };

    std::unordered_set<std::string> live_ids;
    live_ids.reserve(listing.identities.size());
    for (const auto& identity : listing.identities)
    {
        live_ids.insert(identity.container_id);
    }

    // Step 1: container-exit deletes. Periodic passes only, and never on the first
    // pass after (re)start (a live container missing from a warming store must not
    // trigger a delete storm).
    if (!targeted && !firstPass)
    {
        for (const auto& gone : m_store.knownContainerIds())
        {
            if (live_ids.count(gone) != 0)
            {
                continue;
            }
            for (const auto& [id, fingerprint] : m_store.load(gone))
            {
                emitDelete(RowRef {id, fingerprint.index});
            }
            m_store.purgeContainer(gone);
        }
    }

    // Step 2: per-container reconcile.
    for (const auto& identity : listing.identities)
    {
        if (targeted && identity.container_id != *scope.single_container_id)
        {
            continue;
        }

        auto scanned = m_collect(identity);
        if (!scanned)
        {
            continue;  // not addressable — leave prior state intact (anti-flap).
        }

        std::vector<EmittedRow>         current;
        std::unordered_set<std::string> failed_indices;
        for (auto& dimension : *scanned)
        {
            if (dimension.status != CollectStatus::Ok)
            {
                failed_indices.insert(dimension.index);
                continue;
            }
            for (auto& row : dimension.rows)
            {
                current.push_back(std::move(row));
            }
        }

        // Anti-flap: a dimension that failed to scan contributes no rows, so its
        // prior rows must leave the diff too — otherwise "collector errored" would
        // read as "every row in that dimension vanished" and delete them all.
        auto prior = m_store.load(identity.container_id);
        for (auto it = prior.begin(); it != prior.end();)
        {
            it = failed_indices.count(it->second.index) != 0 ? prior.erase(it) : std::next(it);
        }

        auto delta = diffRows(prior, current);
        if (firstPass)
        {
            delta.deletes.clear();  // first-scan-after-reload: CREATE/MODIFY only.
        }

        // Admit creates up to the per-index ceiling; suppressed creates are simply
        // not emitted and not tracked, so they are retried once slots free up.
        // ponytail: blunt "first N tracked rows win" cap, no promotion fairness —
        // upgrade to the dbsync promotion machinery when container dims move there.
        RowDelta applied;
        applied.modifies = std::move(delta.modifies);
        applied.deletes  = std::move(delta.deletes);
        applied.creates.reserve(delta.creates.size());
        for (auto& row : delta.creates)
        {
            const auto limit = limitFor(row.index);
            if (limit > 0 && counts[row.index] >= limit)
            {
                continue;
            }
            ++counts[row.index];
            applied.creates.push_back(std::move(row));
        }

        // Emit-first ordering: hand every row to the sink, THEN persist prior
        // state. A crash in between re-emits harmlessly next pass (idempotent
        // upsert); the reverse order could claim "already sent" for a lost row.
        for (const auto& row : applied.creates)
        {
            m_sink(row);
            ++stats.creates;
        }
        for (const auto& row : applied.modifies)
        {
            m_sink(row);
            ++stats.modifies;
        }
        for (const auto& ref : applied.deletes)
        {
            emitDelete(ref);
        }
        m_store.applyDelta(identity.container_id, applied);
        ++stats.containers_scanned;
    }

    if (!targeted)
    {
        m_first_pass = false;
    }
    return stats;
}

} // namespace wazuh::container_baseline
