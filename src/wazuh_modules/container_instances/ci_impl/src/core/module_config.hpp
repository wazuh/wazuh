#pragma once

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>

namespace wazuh::container_instances
{

    enum class ConnectorType : std::uint8_t
    {
        kubernetes,
        docker
    };

    struct KubernetesConfig
    {
        std::string kubeconfigPath;
        std::string nodeName;
        std::chrono::seconds ownershipPollInterval {120};
        bool insecureSkipTlsVerify {false};
    };

    struct DockerConfig
    {
        std::string socketPath {"/var/run/docker.sock"};
    };

    /// Validated configuration handed to the facade. The C-side XML parser rejects
    /// illegal combinations, so by construction exactly the block matching `type`
    /// is populated here.
    struct ModuleConfig
    {
        ConnectorType type {ConnectorType::docker};
        std::optional<KubernetesConfig> kubernetes;
        std::optional<DockerConfig> docker;
        std::string ipcSocketPath {"queue/sockets/container_instances"};
    };

} // namespace wazuh::container_instances
