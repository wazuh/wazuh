#include "container_connector_impl.hpp"

#include "docker_client.hpp"
#include "docker_metadata_cache.hpp"
#include "docker_watcher.hpp"
#include "ipc_server.hpp"
#include "kubernetes_client.hpp"
#include "logging_helper.h"
#include "metadata_cache.hpp"
#include "pod_watcher.hpp"

#include <exception>
#include <utility>

namespace {
constexpr const char* kDefaultIpcSocketPath = "/var/ossec/queue/sockets/container_connector";
} // namespace

namespace wazuh::container_connector {

ContainerConnectorImpl::ContainerConnectorImpl(ModuleConfig config, LogCallback log)
    : config_(std::move(config))
    , log_(std::move(log))
    , stop_(std::make_shared<StopController>())
{
}

ContainerConnectorImpl::~ContainerConnectorImpl()
{
    if (started_) {
        Stop();
    }
}

void ContainerConnectorImpl::Log(int level, const std::string& msg) const
{
    if (log_) {
        log_(level, msg);
    }
}

void ContainerConnectorImpl::Start()
{
    if (started_) {
        return;
    }

    const bool any_enabled = config_.kubernetes.enabled || config_.docker.enabled;
    if (!any_enabled) {
        Log(LOG_INFO, "All backends disabled; module remains idle.");
        started_ = true;
        return;
    }

    if (config_.kubernetes.enabled) {
        Log(LOG_INFO, std::string{"Starting Kubernetes connector. node_name='"} +
                      (config_.kubernetes.node_name.empty()
                           ? std::string{"<env $NODE_NAME>"}
                           : config_.kubernetes.node_name) + "'.");

        k8s_client_  = std::make_unique<KubernetesClient>(config_.kubernetes, stop_, log_);
        cache_       = std::make_unique<MetadataCache>(stop_, log_);
        pod_watcher_ = std::make_unique<PodWatcher>(
            k8s_client_.get(), cache_.get(), stop_,
            std::chrono::seconds(config_.kubernetes.poll_interval), log_);
        pod_watcher_->Start();
        Log(LOG_INFO, "PodWatcher started (polling every " +
                      std::to_string(config_.kubernetes.poll_interval) +
                      "s; exponential backoff up to 300s on errors).");
    }

    if (config_.docker.enabled) {
        const auto& sock = config_.docker.socket_path.empty()
                               ? std::string{"/var/run/docker.sock"}
                               : config_.docker.socket_path;
        Log(LOG_INFO, "Starting Docker connector. socket='" + sock + "'.");

        docker_client_  = std::make_unique<DockerClient>(config_.docker, stop_, log_);
        docker_cache_   = std::make_unique<DockerMetadataCache>(stop_, log_);
        docker_watcher_ = std::make_unique<DockerWatcher>(
            docker_client_.get(), docker_cache_.get(), stop_,
            std::chrono::seconds(config_.docker.poll_interval), log_);
        docker_watcher_->Start();
        Log(LOG_INFO, "DockerWatcher started (polling every " +
                      std::to_string(config_.docker.poll_interval) +
                      "s; exponential backoff up to 300s on errors).");
    }

    // IPC server: optional. If bind() fails we log and continue.
    try {
        ipc_server_ = std::make_unique<IpcServer>(
            kDefaultIpcSocketPath,
            cache_.get(),
            docker_cache_.get(),
            stop_,
            log_);
        ipc_server_->Start();
    } catch (const std::exception& ex) {
        Log(LOG_ERROR, std::string{"Failed to start IpcServer: "} + ex.what() +
                           " — module continues without IPC; FIM sync lookups will not work.");
        ipc_server_.reset();
    }

    started_ = true;
}

void ContainerConnectorImpl::Stop()
{
    if (!started_) {
        return;
    }

    Log(LOG_INFO, "Stop requested; tearing down container connector.");

    stop_->RequestStop();

    // Tear down components in REVERSE ORDER of construction. Each component's Stop()
    // observes the global stop_ from its loop, joins its worker thread, and only then
    // its reset() releases resources. No "give up if busy" path: each Stop() always
    // completes the teardown (the wait granularities are bounded by design).
    if (ipc_server_) {
        ipc_server_->Stop();
        ipc_server_.reset();
    }
    if (docker_watcher_) {
        docker_watcher_->Stop();
        docker_watcher_.reset();
    }
    docker_cache_.reset();
    docker_client_.reset();
    if (pod_watcher_) {
        pod_watcher_->Stop();
        pod_watcher_.reset();
    }
    cache_.reset();
    k8s_client_.reset();

    started_ = false;
    Log(LOG_INFO, "Container connector stopped.");
}

void ContainerConnectorImpl::WaitForShutdown()
{
    // Block until RequestStop() is observed. Short timeout keeps the wait
    // responsive to external pollers without busy-waiting.
    while (!stop_->IsStopRequested()) {
        stop_->WaitFor(std::chrono::seconds(1));
    }
}

} // namespace wazuh::container_connector
