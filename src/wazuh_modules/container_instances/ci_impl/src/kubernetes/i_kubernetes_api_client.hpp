#pragma once

#include "../core/stop_controller.hpp"
#include "k8s_types.hpp"

#include <cstdint>
#include <functional>
#include <stdexcept>
#include <string>

namespace wazuh::container_instances
{

    class KubernetesApiError : public std::runtime_error
    {
    public:
        KubernetesApiError(long httpStatus, const std::string& message)
            : std::runtime_error(message)
            , m_httpStatus(httpStatus)
        {
        }

        /// 0 = transport-level failure (no HTTP status).
        [[nodiscard]] long httpStatus() const noexcept
        {
            return m_httpStatus;
        }

    private:
        long m_httpStatus;
    };

    struct WatchOutcome
    {
        enum class Kind : std::uint8_t
        {
            cancelled,   ///< Stop requested; clean shutdown.
            gone,        ///< 410 (HTTP status or in-stream ERROR event): re-list required.
            disconnected ///< Stream ended or transport error: retry from last resourceVersion.
        };

        Kind kind {Kind::disconnected};
        std::string message;
    };

    using PodEventSink = std::function<void(const PodWatchEvent&)>;

    class IKubernetesApiClient
    {
    public:
        virtual ~IKubernetesApiClient() = default;

        /// GET /api/v1/pods?fieldSelector=spec.nodeName=<node>
        /// @throws KubernetesApiError
        [[nodiscard]] virtual PodList listPods() = 0;

        /// Watch from `resourceVersion`; blocks until cancelled, 410, or disconnect.
        [[nodiscard]] virtual WatchOutcome
        watchPods(const std::string& resourceVersion, const PodEventSink& sink, const StopController& stop) = 0;

        /// apps/v1 + batch/v1 workloads for the ownership chain.
        /// @throws KubernetesApiError
        [[nodiscard]] virtual WorkloadIndex listWorkloads() = 0;
    };

} // namespace wazuh::container_instances
