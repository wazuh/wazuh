#include "container_connector_impl.hpp"

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

    if (!config_.kubernetes.enabled) {
        Log(LOG_INFO, "Kubernetes backend disabled; module remains idle.");
        started_ = true;
        return;
    }

    Log(LOG_INFO, std::string{"Starting Kubernetes connector. node_name='"} +
                  (config_.kubernetes.node_name.empty()
                       ? std::string{"<env $NODE_NAME>"}
                       : config_.kubernetes.node_name) + "'.");

    // T-K2/T-K3: K8s client + metadata cache + pod watcher.
    // Construction is infallible (config resolution is deferred to the first
    // request). All transient errors — including "not in cluster yet" — are
    // absorbed by the watcher's backoff loop, so the module is always able to
    // recover when the environment becomes valid.
    k8s_client_  = std::make_unique<KubernetesClient>(config_.kubernetes, stop_, log_);
    cache_       = std::make_unique<MetadataCache>(stop_, log_);
    pod_watcher_ = std::make_unique<PodWatcher>(k8s_client_.get(), cache_.get(), stop_, log_);

    pod_watcher_->Start();
    Log(LOG_INFO, "PodWatcher started (polling every 5s; exponential backoff up to 60s on errors).");

    // IPC server: optional. If bind() fails (path read-only, dir missing) we log
    // and continue — the watcher keeps the cache fresh and consumers (FIM) will
    // simply not be able to do sync lookups until the issue is fixed.
    try {
        ipc_server_ = std::make_unique<IpcServer>(kDefaultIpcSocketPath, cache_.get(), stop_, log_);
        ipc_server_->Start();
    } catch (const std::exception& ex) {
        Log(LOG_ERROR, std::string{"Failed to start IpcServer: "} + ex.what() +
                           " — module continues without IPC; FIM sync lookups will not work.");
        ipc_server_.reset();
    }

    // T-K4 will instantiate IpcServer here.
    // Each component owns its own threads and respects stop_.

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
        ipc_server_->Stop();    // eventfd wake + close listen fd + join
        ipc_server_.reset();
    }
    if (pod_watcher_) {
        pod_watcher_->Stop();   // joins the worker thread
        pod_watcher_.reset();
    }
    cache_.reset();             // no threads; safe to release once writers/readers are joined
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
