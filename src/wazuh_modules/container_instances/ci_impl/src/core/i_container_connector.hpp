#pragma once

#include "stop_controller.hpp"

namespace wazuh::container_instances
{

    /// A connector keeps the metadata store fresh for one runtime (Kubernetes or
    /// Docker). Strategy chosen once at startup from <type>; run() blocks on the
    /// connector thread until the stop controller fires.
    class IContainerConnector
    {
    public:
        virtual ~IContainerConnector() = default;

        virtual void run(const StopController& stop) = 0;
    };

} // namespace wazuh::container_instances
