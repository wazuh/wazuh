#pragma once

#include <cstdint>
#include <string>

namespace wazuh::container_instances
{

    enum class RefreshOutcome : std::uint8_t
    {
        resolved, ///< Metadata fetched and upserted into the store.
        notFound, ///< The runtime does not know this container id (yet).
        error     ///< Transient failure talking to the runtime.
    };

    /// The one slice of a connector the query path is allowed to see (interface
    /// segregation): resolve a single container id on demand during the cold-cache
    /// loop. Docker: one inspect. Kubernetes: the watch cache normally already has
    /// it; otherwise one list.
    class IOnDemandRefresher
    {
    public:
        virtual ~IOnDemandRefresher() = default;

        [[nodiscard]] virtual RefreshOutcome refreshOne(const std::string& containerId, std::uint64_t cgroupInode) = 0;
    };

} // namespace wazuh::container_instances
