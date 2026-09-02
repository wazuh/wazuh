#pragma once

#include "../core/stop_controller.hpp"
#include "docker_types.hpp"

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>
#include <vector>

namespace wazuh::container_instances
{

    class DockerApiError : public std::runtime_error
    {
    public:
        DockerApiError(long httpStatus, const std::string& message)
            : std::runtime_error(message)
            , m_httpStatus(httpStatus)
        {
        }

        /// 0 = transport-level failure (socket missing, daemon down, ...).
        [[nodiscard]] long httpStatus() const noexcept
        {
            return m_httpStatus;
        }

    private:
        long m_httpStatus;
    };

    /// Daemon speaks an API older than the module's minimum: fail clearly, no crash.
    class DockerVersionTooOld : public DockerApiError
    {
    public:
        DockerVersionTooOld(const std::string& daemonVersion, const std::string& minimumVersion)
            : DockerApiError(
                  0, "Docker daemon API v" + daemonVersion + " is below the minimum supported v" + minimumVersion)
        {
        }
    };

    struct StreamOutcome
    {
        enum class Kind : std::uint8_t
        {
            cancelled,
            disconnected
        };

        Kind kind {Kind::disconnected};
        std::string message;
    };

    using DockerEventSink = std::function<void(const DockerEvent&)>;

    class IDockerApiClient
    {
    public:
        virtual ~IDockerApiClient() = default;

        /// GET /version; negotiates down to the minimum supported API version.
        /// @throws DockerVersionTooOld, DockerApiError
        [[nodiscard]] virtual std::string negotiateVersion() = 0;

        /// @throws DockerApiError
        [[nodiscard]] virtual std::vector<ContainerSummary> listContainers() = 0;

        /// @throws DockerApiError (httpStatus 404 = vanished between list and inspect).
        [[nodiscard]] virtual ContainerDetail inspect(const std::string& containerId) = 0;

        /// GET /events?since=<ts>; blocks until cancelled or disconnect.
        [[nodiscard]] virtual StreamOutcome
        streamEvents(std::int64_t sinceSeconds, const DockerEventSink& sink, const StopController& stop) = 0;
    };

} // namespace wazuh::container_instances
