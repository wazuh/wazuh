#pragma once

#include "query_types.hpp"

namespace wazuh::container_instances
{

    class IQueryHandler
    {
    public:
        virtual ~IQueryHandler() = default;

        [[nodiscard]] virtual QueryResponse handle(const QueryRequest& request) = 0;
    };

} // namespace wazuh::container_instances
