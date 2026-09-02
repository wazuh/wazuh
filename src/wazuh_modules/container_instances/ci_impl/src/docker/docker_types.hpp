#pragma once

#include "../core/container_record.hpp"

#include <cstdint>
#include <string>

namespace wazuh::container_instances
{

    struct ContainerSummary
    {
        std::string id;
    };

    /// Docker inspect output, already mapped to the record shape (docker subset:
    /// no pod/namespace/owner fields).
    struct ContainerDetail
    {
        ContainerRecord record;
    };

    struct DockerEvent
    {
        std::string containerId;
        std::string action; ///< start, die, destroy, rename, update (others filtered by the parser).
        std::int64_t timeNano {0};
    };

} // namespace wazuh::container_instances
