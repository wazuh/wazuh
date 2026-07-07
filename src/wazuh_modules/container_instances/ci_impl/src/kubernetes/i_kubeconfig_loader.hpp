#pragma once

#include "kube_credentials.hpp"

#include <stdexcept>
#include <string>

namespace wazuh::container_instances
{

    class KubeconfigError : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    /// Loads and validates a kubeconfig file into KubeCredentials. Called at the
    /// top of every API call so externally rotated tokens/certs are picked up
    /// without restart (fixed decision: no background refresh, no TTL tracking).
    class IKubeconfigLoader
    {
    public:
        virtual ~IKubeconfigLoader() = default;

        /// @throws KubeconfigError on unreadable/malformed/unsupported kubeconfig
        ///         (including `exec` credential plugins).
        [[nodiscard]] virtual KubeCredentials load(const std::string& path) const = 0;
    };

} // namespace wazuh::container_instances
