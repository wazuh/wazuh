#pragma once

#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "reconcile/i_container_lister.hpp"
#include "reconcile/i_prior_state_store.hpp"
#include "reconcile/reconcile_types.hpp"

namespace wazuh::container_baseline {

/// @brief Scans one container's inventory. Returns nullopt when the container is
/// not addressable (see CollectContainer); the reconciler then skips it.
using CollectFn = std::function<std::optional<std::vector<CollectorResult>>(const ContainerIdentity&)>;

/// @brief Per-index row ceiling (NFR3). 0 (or absent) means unlimited.
using DocumentLimits = std::unordered_map<std::string, std::size_t>;

struct ReconcileStats
{
    int  containers_scanned{0};
    int  creates{0};
    int  modifies{0};
    int  deletes{0};
    bool skipped_unavailable{false};
};

/// @brief The composition root of the container-inventory reconcile layer — the
/// only class that names the collaborators. It turns "the current live container
/// set + a fresh scan of each" into CREATE/MODIFY/DELETE operations against the
/// sync sink, using durable prior state to compute the diff and to clean up
/// containers that exited while the agent was down.
///
/// Single-threaded: driven by Syscollector's scan thread. A targeted reconcile
/// (scope with a single container id) is the seam an eBPF cgroup event (#37396)
/// would drive; it never runs container-exit deletes.
class ContainerInventoryReconciler
{
public:
    ContainerInventoryReconciler(IContainerLister& lister,
                                 IPriorStateStore& store,
                                 CollectFn         collect,
                                 RowSink           sink,
                                 DocumentLimits    limits = {});

    /// @brief Reconcile every live container (scope.single_container_id == nullopt)
    /// or just one (targeted refresh).
    ReconcileStats reconcile(const ReconcileScope& scope);

private:
    [[nodiscard]] std::size_t limitFor(const std::string& index) const;

    IContainerLister& m_lister;
    IPriorStateStore& m_store;
    CollectFn         m_collect;
    RowSink           m_sink;
    DocumentLimits    m_limits;

    // Set false after the first all-container reconcile. While true, deletes are
    // suppressed (CREATE/MODIFY only) — this is the first-scan-after-reload guard
    // that prevents a delete storm before prior state and the live set are known
    // to agree (the db-close/first-sync guards are absent on this branch).
    bool m_first_pass{true};
};

} // namespace wazuh::container_baseline
