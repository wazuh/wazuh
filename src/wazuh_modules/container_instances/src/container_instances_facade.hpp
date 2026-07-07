#pragma once

#include "../ci_impl/src/core/logger.hpp"

#include "json.hpp"

#include <memory>
#include <mutex>

namespace wazuh::container_instances
{

    /// Composition root: the only place in the module that names concrete types.
    /// Singleton because the C glue owns lifecycle through free functions.
    class ContainerInstancesFacade final
    {
    public:
        static ContainerInstancesFacade& instance();

        /// Parses the configuration, wires every component and spawns the
        /// connector/poller/IPC threads. @throws std::exception on bad config.
        void start(const nlohmann::json& configuration, Logger logger);

        /// Idempotent, reverse-order teardown.
        void stop();

    private:
        ContainerInstancesFacade() = default;

        class Impl;
        std::mutex m_mutex; ///< Guards the pointer only, never a blocking call.
        std::unique_ptr<Impl> m_impl;
    };

} // namespace wazuh::container_instances
