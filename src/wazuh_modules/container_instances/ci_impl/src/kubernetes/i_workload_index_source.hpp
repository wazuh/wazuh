#pragma once

#include "k8s_types.hpp"

#include <cstdint>
#include <memory>

namespace wazuh::container_instances
{

    /// Latest-value mailbox for the workload ownership index. The poller writes,
    /// the connector reads on its next reconcile — the poller never touches the
    /// metadata store (single-snapshot-writer stays intact).
    class IWorkloadIndexSource
    {
    public:
        virtual ~IWorkloadIndexSource() = default;

        /// nullptr until the first successful poll.
        [[nodiscard]] virtual std::shared_ptr<const WorkloadIndex> latest() const = 0;

        /// Monotonic publish counter (0 = nothing published yet). The connector
        /// re-reconciles when it observes a change, so records pick up ownership
        /// data without waiting for the next pod event.
        [[nodiscard]] virtual std::uint64_t generation() const = 0;
    };

} // namespace wazuh::container_instances
