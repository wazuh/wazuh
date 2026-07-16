#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    struct KubernetesConfig
    {
        std::string kubeconfigPath {"/etc/wazuh-agent/container_instances/kubeconfig"};
        std::string nodeName {"container-node-1"};
        std::chrono::seconds ownershipPollInterval {120};
        bool insecureSkipTlsVerify {false};
    };

    struct DockerConfig
    {
        /// One connector (= one enrichment source) per socket. Additional
        /// entries cover exposed DinD daemons.
        std::vector<std::string> socketPaths {"/var/run/docker.sock"};
    };

    /// Validated configuration handed to the facade. Each populated section
    /// becomes one enrichment source (connector); dual-runtime = both set.
    struct ModuleConfig
    {
        std::optional<KubernetesConfig> kubernetes;
        std::optional<DockerConfig> docker;
        std::string ipcSocketPath {"queue/sockets/container_instances"};
    };

} // namespace wazuh::container_instances
