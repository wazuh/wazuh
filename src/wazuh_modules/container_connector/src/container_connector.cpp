#include "container_connector.hpp"

#include <exception>
#include <string>
#include <utility>

#define WM_CONTAINER_CONNECTOR_LOGTAG "wazuh-modulesd:container-connector"

namespace wazuh::container_connector {

ContainerConnector& ContainerConnector::Instance()
{
    static ContainerConnector inst;
    return inst;
}

void ContainerConnector::Init(ModuleConfig config, LogCallback log)
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (impl_) {
        // Already initialised; ignore. Reinitialisation requires Stop() first.
        return;
    }
    impl_ = std::make_unique<ContainerConnectorImpl>(std::move(config), std::move(log));
}

void ContainerConnector::Start()
{
    std::lock_guard<std::mutex> lk(mutex_);
    if (impl_) {
        impl_->Start();
    }
}

void ContainerConnector::Stop()
{
    std::unique_ptr<ContainerConnectorImpl> taken;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        taken = std::move(impl_);
    }
    if (taken) {
        // Stop() completes teardown; the destructor (running here when `taken`
        // goes out of scope) has no resources left to release.
        taken->Stop();
    }
}

void ContainerConnector::WaitForShutdown()
{
    ContainerConnectorImpl* raw = nullptr;
    {
        std::lock_guard<std::mutex> lk(mutex_);
        raw = impl_.get();
    }
    if (raw) {
        raw->WaitForShutdown();
    }
}

} // namespace wazuh::container_connector

/* -------- C API bridging the singleton above -------- */

namespace {
wazuh::container_connector::LogCallback g_log;
} // anonymous namespace

extern "C" {

void cc_set_log_function(cc_log_callback_t cb)
{
    if (!cb) {
        g_log = nullptr;
        return;
    }
    g_log = [cb](int level, const std::string& msg) {
        cb(static_cast<modules_log_level_t>(level), msg.c_str(), WM_CONTAINER_CONNECTOR_LOGTAG);
    };
}

void cc_init(const cc_config_t* cfg)
{
    if (!cfg) {
        if (g_log) g_log(LOG_ERROR, "cc_init called with null configuration; ignoring.");
        return;
    }
    try {
        wazuh::container_connector::ModuleConfig cppcfg;
        cppcfg.kubernetes.enabled      = (cfg->kubernetes.enabled != 0);
        cppcfg.kubernetes.poll_interval = (cfg->kubernetes.poll_interval > 0)
                                              ? cfg->kubernetes.poll_interval
                                              : 60;
        if (cfg->kubernetes.api_server) cppcfg.kubernetes.api_server = cfg->kubernetes.api_server;
        if (cfg->kubernetes.ca_bundle)  cppcfg.kubernetes.ca_bundle  = cfg->kubernetes.ca_bundle;
        if (cfg->kubernetes.token_path) cppcfg.kubernetes.token_path = cfg->kubernetes.token_path;
        if (cfg->kubernetes.node_name)  cppcfg.kubernetes.node_name  = cfg->kubernetes.node_name;
        cppcfg.docker.enabled       = (cfg->docker.enabled != 0);
        cppcfg.docker.poll_interval = (cfg->docker.poll_interval > 0)
                                          ? cfg->docker.poll_interval
                                          : 60;
        if (cfg->docker.socket_path)    cppcfg.docker.socket_path    = cfg->docker.socket_path;
        wazuh::container_connector::ContainerConnector::Instance().Init(std::move(cppcfg), g_log);
    } catch (const std::exception& ex) {
        if (g_log) g_log(LOG_ERROR, std::string{"cc_init failed: "} + ex.what());
    } catch (...) {
        if (g_log) g_log(LOG_ERROR, "cc_init failed: unknown exception.");
    }
}

void cc_start(void)
{
    try {
        wazuh::container_connector::ContainerConnector::Instance().Start();
    } catch (const std::exception& ex) {
        if (g_log) g_log(LOG_ERROR, std::string{"cc_start failed: "} + ex.what());
    } catch (...) {
        if (g_log) g_log(LOG_ERROR, "cc_start failed: unknown exception.");
    }
}

void cc_wait_for_shutdown(void)
{
    try {
        wazuh::container_connector::ContainerConnector::Instance().WaitForShutdown();
    } catch (...) {
        /* Swallow — we are in the wait loop; logging here would just spam. */
    }
}

void cc_stop(void)
{
    try {
        wazuh::container_connector::ContainerConnector::Instance().Stop();
    } catch (...) {
        /* Best-effort during shutdown. */
    }
}

} // extern "C"
