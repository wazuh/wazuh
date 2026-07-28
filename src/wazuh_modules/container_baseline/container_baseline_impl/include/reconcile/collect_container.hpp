#pragma once

#include <optional>
#include <vector>

#include "reconcile/reconcile_types.hpp"  // CollectorResult, EmittedRow, ContainerIdentity (transitively)

namespace wazuh::container_baseline {

/// @brief Scan every Syscollector dimension for one container and return the
/// current rows per dimension. The single production seam the reconciler injects
/// as its CollectFn; the pure scanners underneath stay dbsync- and
/// reconcile-ignorant.
///
/// @return nullopt when the container is not addressable (no live PID resolvable) —
/// the reconciler MUST then skip the container and leave its prior state intact,
/// never treating "couldn't scan a live container" as "all its rows are gone".
[[nodiscard]] std::optional<std::vector<CollectorResult>> CollectContainer(const ContainerIdentity& identity);

} // namespace wazuh::container_baseline
