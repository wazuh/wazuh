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
        std::string socketPath {"/var/run/docker.sock"};
    };

    /// Validated configuration handed to the facade. Each populated section
    /// becomes one enrichment source (connector); dual-runtime = both set.
    struct ModuleConfig
    {
        std::optional<KubernetesConfig> kubernetes;
        std::optional<DockerConfig> docker;
        std::string ipcSocketPath {"queue/sockets/container_instances"};

        /// Consumer-bound sockets to notify when the container list changes.
        ///
        /// Named here rather than discovered, because there is no registry by
        /// design: a datagram to a socket nobody bound is a no-op, so listing a
        /// consumer that is not running costs nothing, and the alternative —
        /// consumers registering themselves — is the per-client state this
        /// transport exists to avoid.
        std::vector<std::string> notifySocketPaths {"queue/sockets/syscheck-ci-notify",
                                                    "queue/sockets/syscollector-ci-notify"};

        /// How many containers may report to the manager; <= 0 means unlimited,
        /// which is the shipped default.
        ///
        /// Decided here, for both consumers, because syscheckd and modulesd are
        /// separate processes: two independent answers would show a container's
        /// packages while hiding its files. It arrives with the rest of the
        /// configuration rather than being queried by this module, since the
        /// value comes from the manager and modulesd already has the socket to
        /// ask on.
        int syncedContainerLimit {0};
    };

} // namespace wazuh::container_instances
