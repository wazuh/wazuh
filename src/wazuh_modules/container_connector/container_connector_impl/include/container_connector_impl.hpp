#pragma once

#include "stop_controller.hpp"

#include <functional>
#include <memory>
#include <string>

namespace wazuh::container_connector {
class KubernetesClient;
class MetadataCache;
class PodWatcher;
class IpcServer;
} // namespace wazuh::container_connector

namespace wazuh::container_connector {

struct KubernetesConfig
{
    bool        enabled{true};
    std::string api_server;   ///< Empty => derived from KUBERNETES_SERVICE_HOST/PORT.
    std::string ca_bundle;    ///< Empty => default service-account ca.crt path.
    std::string token_path;   ///< Empty => default service-account token path.
    std::string node_name;    ///< Empty => derived from $NODE_NAME.
};

struct ModuleConfig
{
    KubernetesConfig kubernetes;
};

/// @brief Log callback supplied by the C glue. Level uses the modules_log_level_t int values.
using LogCallback = std::function<void(int level, const std::string& message)>;

/// @brief Owns every runtime resource of the container-connector module.
///
/// Construction is cheap; resources are acquired in Start() and released in Stop().
/// Stop() is idempotent and is also called from the destructor as a safety net,
/// but well-behaved callers must call Stop() explicitly before destruction.
///
/// Threading contract:
///   - Start() may spawn worker threads but returns immediately.
///   - Stop() cancels all in-flight work, joins every worker thread, then releases
///     resources in reverse order of construction.
///   - WaitForShutdown() blocks the calling thread until Stop() has been observed
///     (either externally or via internal fatal error).
class ContainerConnectorImpl final
{
public:
    ContainerConnectorImpl(ModuleConfig config, LogCallback log);
    ~ContainerConnectorImpl();

    ContainerConnectorImpl(const ContainerConnectorImpl&) = delete;
    ContainerConnectorImpl& operator=(const ContainerConnectorImpl&) = delete;
    ContainerConnectorImpl(ContainerConnectorImpl&&) = delete;
    ContainerConnectorImpl& operator=(ContainerConnectorImpl&&) = delete;

    void Start();
    void Stop();
    void WaitForShutdown();

private:
    void Log(int level, const std::string& msg) const;

    ModuleConfig                    config_;
    LogCallback                     log_;
    std::shared_ptr<StopController> stop_;

    // Component owners, in construction order. Stop() tears them down in REVERSE order.
    std::unique_ptr<KubernetesClient> k8s_client_;
    std::unique_ptr<MetadataCache>    cache_;
    std::unique_ptr<PodWatcher>       pod_watcher_;
    std::unique_ptr<IpcServer>        ipc_server_;

    bool started_{false};
};

} // namespace wazuh::container_connector
