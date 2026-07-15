#pragma once

#include "container_connector_impl.hpp"
#include "stop_controller.hpp"

#include <chrono>
#include <memory>
#include <thread>

namespace wazuh::container_connector {

class DockerClient;
class DockerMetadataCache;

/// @brief Polls the Docker daemon periodically and reconciles the DockerMetadataCache.
///
/// On each iteration it calls ListContainers(), resolves cgroup_ids via /proc,
/// and calls DockerMetadataCache::Reconcile() with the full snapshot.
/// On error it backs off exponentially up to kMaxBackoff then retries.
class DockerWatcher final
{
public:
    DockerWatcher(DockerClient*                   client,
                  DockerMetadataCache*            cache,
                  std::shared_ptr<StopController> stop,
                  std::chrono::seconds            poll_interval,
                  LogCallback                     log);
    ~DockerWatcher();

    DockerWatcher(const DockerWatcher&)            = delete;
    DockerWatcher& operator=(const DockerWatcher&) = delete;
    DockerWatcher(DockerWatcher&&)                 = delete;
    DockerWatcher& operator=(DockerWatcher&&)      = delete;

    void Start();
    void Stop();

private:
    void RunLoop();
    void SyncSnapshot();
    void Log(int level, const std::string& msg) const;

    DockerClient*                   client_;
    DockerMetadataCache*            cache_;
    std::shared_ptr<StopController> stop_;
    std::chrono::seconds            poll_interval_;
    LogCallback                     log_;

    std::thread thread_;
    bool        running_{false};

    static constexpr auto kMaxBackoff = std::chrono::seconds(300);
};

} // namespace wazuh::container_connector
