#pragma once

#include "../core/logger.hpp"
#include "../transport/i_http_transport.hpp"
#include "i_docker_api_client.hpp"

#include <string>

namespace wazuh::container_instances
{

    /// Read-only Docker Engine API client over the local Unix socket. The full
    /// endpoint surface is /version, /containers/json, /containers/{id}/json and
    /// /events — never create/exec/attach (documented privilege contract).
    class DockerApiClient final : public IDockerApiClient
    {
    public:
        DockerApiClient(IHttpTransport& transport, std::string socketPath, Logger logger);

        [[nodiscard]] std::string negotiateVersion() override;
        [[nodiscard]] std::vector<ContainerSummary> listContainers() override;
        [[nodiscard]] ContainerDetail inspect(const std::string& containerId) override;
        [[nodiscard]] StreamOutcome
        streamEvents(std::int64_t sinceSeconds, const DockerEventSink& sink, const StopController& stop) override;

    private:
        [[nodiscard]] HttpRequestSpec specFor(const std::string& resource) const;
        [[nodiscard]] HttpResponse get(const std::string& resource) const;

        /// Thread-safe read: the connector thread negotiates while IPC workers
        /// may already be inspecting on the cold path.
        [[nodiscard]] std::string apiVersion() const;

        IHttpTransport& m_transport;
        std::string m_socketPath;
        Logger m_logger;
        mutable std::mutex m_versionMutex;
        std::string m_apiVersion; ///< Defaults to the module minimum; raised to the daemon's MinAPIVersion.
    };

} // namespace wazuh::container_instances
