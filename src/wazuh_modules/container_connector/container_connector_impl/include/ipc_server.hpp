#pragma once

#include "container_connector_impl.hpp"
#include "stop_controller.hpp"

#include <memory>
#include <string>
#include <thread>

namespace wazuh::container_connector {

class MetadataCache;
class DockerMetadataCache;

/// @brief Unix-domain socket server that exposes the metadata caches to other
/// agent components (syscheckd FIM lookups, logcollector).
///
/// Protocol: line-based JSON. Client sends one JSON object terminated by '\n',
/// server replies with one JSON object terminated by '\n', then closes.
///
/// Supported ops:
///   { "op": "size" }
///   { "op": "lookup_cgroup_id",    "cgroup_id": <uint64> }
///   { "op": "lookup_container_id", "id": "<string>" }
///
/// Lookup ops check the Kubernetes cache first, then the Docker cache.
/// The response includes a "runtime" field ("kubernetes" or "docker") and
/// either a "pod" sub-object (Kubernetes) or a "docker" sub-object (Docker).
///
/// Cancellation: the accept loop polls on both the listening socket and an
/// eventfd. Stop() writes to the eventfd, closes the listening socket, and
/// joins the worker thread — bounded teardown regardless of client activity.
class IpcServer final
{
public:
    IpcServer(std::string                     socket_path,
              MetadataCache*                  cache,
              DockerMetadataCache*            docker_cache,
              std::shared_ptr<StopController> stop,
              LogCallback                     log);

    ~IpcServer();

    IpcServer(const IpcServer&)            = delete;
    IpcServer& operator=(const IpcServer&) = delete;
    IpcServer(IpcServer&&)                 = delete;
    IpcServer& operator=(IpcServer&&)      = delete;

    /// Create the socket, bind, listen, spawn the accept thread. Throws on bind/listen failure.
    void Start();

    /// Signal the worker, close fds, join. Idempotent.
    void Stop();

private:
    void        AcceptLoop();
    void        HandleClient(int client_fd);
    std::string ProcessRequest(const std::string& request_line);
    void        Log(int level, const std::string& msg) const;

    std::string                     socket_path_;
    MetadataCache*                  cache_;
    DockerMetadataCache*            docker_cache_;
    std::shared_ptr<StopController> stop_;
    LogCallback                     log_;

    int         listen_fd_{-1};
    int         wakeup_fd_{-1};
    std::thread thread_;
    bool        running_{false};
};

} // namespace wazuh::container_connector
