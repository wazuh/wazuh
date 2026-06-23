#pragma once

#include "container_connector_impl.hpp"
#include "docker_meta.hpp"
#include "stop_controller.hpp"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace wazuh::container_connector {

class DockerHttpClient;

/// @brief High-level Docker Engine API client.
///
/// Wraps DockerHttpClient with JSON parsing. One-shot methods open a new
/// connection per call; StreamEvents keeps one connection open until the
/// stop controller fires or the daemon drops it.
class DockerClient
{
public:
    DockerClient(DockerConfig config, std::shared_ptr<StopController> stop, LogCallback log);
    ~DockerClient();

    DockerClient(const DockerClient&)            = delete;
    DockerClient& operator=(const DockerClient&) = delete;
    DockerClient(DockerClient&&)                 = delete;
    DockerClient& operator=(DockerClient&&)      = delete;

    /// List all running containers, fetching full inspect data for each.
    std::vector<DockerContainerInfo> ListContainers();

    /// Full inspect for a single container. Returns nullopt if it no longer exists.
    std::optional<DockerContainerInfo> InspectContainer(const std::string& id);

    /// Stream container lifecycle events. Calls on_line for each raw JSON event
    /// string, stops when stop fires or on_line returns false.
    void StreamEvents(const std::function<bool(const std::string&)>& on_line,
                      const std::shared_ptr<StopController>&          stop);

private:
    void Log(int level, const std::string& msg) const;

    DockerConfig                      config_;
    std::shared_ptr<StopController>   stop_;
    LogCallback                       log_;
    std::unique_ptr<DockerHttpClient> http_;
};

} // namespace wazuh::container_connector
