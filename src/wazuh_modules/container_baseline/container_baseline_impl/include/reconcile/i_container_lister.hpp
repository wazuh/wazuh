#pragma once

#include <vector>

#include "baseline_rows.hpp"  // ContainerIdentity

namespace wazuh::container_baseline {

/// @brief Result of enumerating the containers currently known to the Container
/// Instances module.
///
/// `available` separates "the module answered, and this is the full live set"
/// (true, possibly empty) from "the module could not be reached / gave no usable
/// answer" (false). This distinction is load-bearing: ContainerInstancesClient
/// collapses every IPC failure to an empty list, so an empty list alone cannot
/// tell a genuinely container-less host from a transient socket failure. Diffing
/// against a falsely-empty set would delete the entire container inventory. The
/// reconciler therefore skips its pass whenever `available` is false, and only
/// treats a truly-empty `identities` as "every container is gone" when
/// `available` is true.
struct ContainerListing
{
    bool                           available{false};
    std::vector<ContainerIdentity> identities;
};

/// @brief Consumer-owned seam over the Container Instances IPC client. Faked in
/// tests to drive the reconciler with a scripted container set.
class IContainerLister
{
public:
    virtual ~IContainerLister() = default;

    /// @brief Enumerate and resolve every currently-known container.
    [[nodiscard]] virtual ContainerListing list() = 0;
};

} // namespace wazuh::container_baseline
