#pragma once

#include "container_connector_impl.hpp"
#include "container_meta.hpp"
#include "stop_controller.hpp"

#include <memory>
#include <string>
#include <vector>

namespace wazuh::container_connector {

/// @brief Synchronous client over the Kubernetes REST API.
///
/// One-shot calls only; no long-poll watch loop (the PodWatcher in T-K3 polls this
/// client on a cadence). Holds a std::shared_ptr<StopController> so requests can be
/// short-circuited when a stop is observed before the next network round-trip.
class KubernetesClient final
{
public:
    KubernetesClient(KubernetesConfig                config,
                     std::shared_ptr<StopController> stop,
                     LogCallback                     log);

    ~KubernetesClient() = default;

    KubernetesClient(const KubernetesClient&)            = delete;
    KubernetesClient& operator=(const KubernetesClient&) = delete;
    KubernetesClient(KubernetesClient&&)                 = delete;
    KubernetesClient& operator=(KubernetesClient&&)      = delete;

    /// @return The effective HTTPS URL the client targets, or empty string if config
    /// has not been resolved yet (no successful poll attempted).
    const std::string& ApiServer() const noexcept { return effective_api_server_; }
    const std::string& NodeName()  const noexcept { return effective_node_name_;  }

    /// @brief GET /api/v1/pods?fieldSelector=spec.nodeName=<node>
    ///
    /// Parses pod-level metadata (uid, name, namespace, labels, annotations, ownerRefs)
    /// and per-container status entries (container_id without runtime prefix, image,
    /// image_id, restart_count). cgroup_id is left as 0; T-K5 will populate it by
    /// stat-ing the cgroupfs path for each container.
    ///
    /// @throws std::runtime_error on auth/TLS/transport/parsing failure.
    std::vector<PodSnapshot> ListPodsOnNode();

private:
    /// Re-resolves runtime values (API server URL, ca/token paths, node name).
    /// Called at the top of every request so env-var changes (rare but possible
    /// in K8s, e.g. DaemonSet that gets its envs late) are picked up without a
    /// module restart. Throws on missing required fields.
    void        ResolveEffectiveConfig();
    std::string ReadBearerToken() const;
    void        Log(int level, const std::string& msg) const;

    KubernetesConfig                config_;
    std::shared_ptr<StopController> stop_;
    LogCallback                     log_;

    std::string effective_api_server_;
    std::string effective_ca_bundle_;
    std::string effective_token_path_;
    std::string effective_node_name_;
    bool        resolution_logged_{false};
};

} // namespace wazuh::container_connector
