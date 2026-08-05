#pragma once

#include <chrono>
#include <string>

#include "reconcile/i_container_lister.hpp"

namespace wazuh::container_baseline {

/// @brief True when a status() reply shows the Container Instances module is up.
/// The empty-list guard's decision logic (ContainerLister::list() calls this when
/// listContainers() comes back empty, to tell "no containers" from "module
/// unreachable"). Exposed here, not file-local, so it can be unit tested without
/// a real IPC socket.
[[nodiscard]] bool ModuleUp(const std::string& status_json);

/// @brief Concrete IContainerLister over the Container Instances IPC client.
/// Lists container refs, resolves each to a full identity, and probes the
/// module's status when the list is empty to tell "no containers" from "module
/// unreachable" (see ContainerListing::available).
class ContainerLister final : public IContainerLister
{
public:
    explicit ContainerLister(std::string               socket_path,
                             std::chrono::milliseconds timeout = std::chrono::milliseconds {1000});

    [[nodiscard]] ContainerListing list() override;

private:
    std::string               m_socket_path;
    std::chrono::milliseconds m_timeout;
};

} // namespace wazuh::container_baseline
