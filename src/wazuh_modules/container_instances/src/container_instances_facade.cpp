#include "container_instances_facade.hpp"

#include "../ci_impl/src/cache/metadata_store.hpp"
#include "../ci_impl/src/cgroup/inode_reader.hpp"
#include "../ci_impl/src/cgroup/proc_cgroup_resolver.hpp"
#include "../ci_impl/src/core/module_config.hpp"
#include "../ci_impl/src/core/stop_controller.hpp"
#include "../ci_impl/src/docker/docker_api_client.hpp"
#include "../ci_impl/src/docker/docker_connector.hpp"
#include "../ci_impl/src/ipc/ipc_server.hpp"
#include "../ci_impl/src/ipc/query_service.hpp"
#include "../ci_impl/src/kubernetes/kubernetes_api_client.hpp"
#include "../ci_impl/src/kubernetes/kubernetes_connector.hpp"
#include "../ci_impl/src/kubernetes/ownership_poller.hpp"
#include "../ci_impl/src/kubernetes/yaml_kubeconfig_loader.hpp"
#include "../ci_impl/src/transport/curl_http_transport.hpp"

#include "file_io_utils.hpp"
#include "filesystem_wrapper.hpp"

#include <stdexcept>
#include <thread>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        ModuleConfig parseConfig(const nlohmann::json& configuration)
        {
            ModuleConfig config;

            const auto type = configuration.value("type", "");
            if (type == "kubernetes")
            {
                config.type = ConnectorType::kubernetes;
                const auto& block = configuration.value("kubernetes", nlohmann::json::object());
                KubernetesConfig kubernetes; // Defaults from KubernetesConfig apply when tags are absent.
                kubernetes.kubeconfigPath = block.value("kubeconfig", kubernetes.kubeconfigPath);
                kubernetes.nodeName = block.value("node_name", kubernetes.nodeName);
                kubernetes.ownershipPollInterval = std::chrono::seconds {block.value("ownership_poll_interval", 120)};
                kubernetes.insecureSkipTlsVerify = block.value("insecure_skip_tls_verify", false);
                config.kubernetes = std::move(kubernetes);
            }
            else if (type == "docker")
            {
                config.type = ConnectorType::docker;
                const auto& block = configuration.value("docker", nlohmann::json::object());
                DockerConfig docker;
                docker.socketPath = block.value("socket_path", docker.socketPath);
                config.docker = std::move(docker);
            }
            else
            {
                throw std::runtime_error("container_instances: <type> must be 'kubernetes' or 'docker'");
            }

            return config;
        }

    } // namespace

    /// Owns every component. Members declared in construction order; the compiler
    /// destroys them in reverse, which is exactly the required teardown order.
    class ContainerInstancesFacade::Impl
    {
    public:
        Impl(const ModuleConfig& config, Logger logger)
            : m_logger(std::move(logger))
            , m_resolver(m_filesystem, m_fileIO, m_inodeReader, m_logger)
            , m_store(m_logger)
            , m_transport(m_logger)
        {
            const char* connectorName = "docker";
            IOnDemandRefresher* refresher = nullptr;

            if (config.type == ConnectorType::kubernetes)
            {
                connectorName = "kubernetes";
                const auto& kubernetes = config.kubernetes.value();

                m_kubeconfigLoader = std::make_unique<YamlKubeconfigLoader>(m_fileIO, m_logger);
                KubernetesClientConfig clientConfig;
                clientConfig.kubeconfigPath = kubernetes.kubeconfigPath;
                clientConfig.nodeName = kubernetes.nodeName;
                clientConfig.insecureSkipTlsVerify = kubernetes.insecureSkipTlsVerify;
                m_k8sClient = std::make_unique<KubernetesApiClient>(
                    m_transport, *m_kubeconfigLoader, m_fileIO, std::move(clientConfig), m_logger);
                m_ownershipPoller =
                    std::make_unique<OwnershipPoller>(*m_k8sClient, kubernetes.ownershipPollInterval, m_logger);
                auto connector = std::make_unique<KubernetesConnector>(
                    *m_k8sClient, m_resolver, m_store, *m_ownershipPoller, kubernetes.nodeName, m_logger);
                refresher = connector.get();
                m_connector = std::move(connector);
            }
            else
            {
                m_dockerClient =
                    std::make_unique<DockerApiClient>(m_transport, config.docker.value().socketPath, m_logger);
                auto connector = std::make_unique<DockerConnector>(*m_dockerClient, m_resolver, m_store, m_logger);
                refresher = connector.get();
                m_connector = std::move(connector);
            }

            m_queryService = std::make_unique<QueryService>(
                m_store, *refresher, m_resolver, RetryPolicy {}, connectorName, m_logger);
            m_ipcServer = std::make_unique<IpcServer>(*m_queryService, config.ipcSocketPath, m_logger);

            if (m_ownershipPoller)
            {
                m_ownershipPoller->start(m_stop);
            }
            m_connectorThread = std::thread([this] { m_connector->run(m_stop); });

            try
            {
                m_ipcServer->start();
            }
            catch (const std::exception& error)
            {
                // The cache still warms and verdicts accumulate; queries will fail
                // until the agent is restarted with the socket path fixed.
                m_logger(LogLevel::error, std::string {"Enrichment query socket unavailable: "} + error.what());
            }
        }

        Impl(const Impl&) = delete;
        Impl& operator=(const Impl&) = delete;
        Impl(Impl&&) = delete;
        Impl& operator=(Impl&&) = delete;

        ~Impl()
        {
            m_stop.requestStop();
            m_ipcServer->stop(); // Intake stops first.
            if (m_connectorThread.joinable())
            {
                m_connectorThread.join();
            }
            if (m_ownershipPoller)
            {
                m_ownershipPoller->join();
            }
            // Members destroyed in reverse declaration order; the store outlives
            // everything that references it.
        }

    private:
        Logger m_logger;
        StopController m_stop;
        file_system::FileSystemWrapper m_filesystem;
        file_io::FileIOUtils m_fileIO;
        InodeReader m_inodeReader;
        ProcCgroupResolver m_resolver;
        MetadataStore m_store;
        CurlHttpTransport m_transport;

        std::unique_ptr<YamlKubeconfigLoader> m_kubeconfigLoader;
        std::unique_ptr<KubernetesApiClient> m_k8sClient;
        std::unique_ptr<OwnershipPoller> m_ownershipPoller;
        std::unique_ptr<DockerApiClient> m_dockerClient;
        std::unique_ptr<IContainerConnector> m_connector;
        std::unique_ptr<QueryService> m_queryService;
        std::unique_ptr<IpcServer> m_ipcServer;
        std::thread m_connectorThread;
    };

    ContainerInstancesFacade& ContainerInstancesFacade::instance()
    {
        static ContainerInstancesFacade facade;
        return facade;
    }

    void ContainerInstancesFacade::start(const nlohmann::json& configuration, Logger logger)
    {
        std::lock_guard<std::mutex> lock(m_mutex);
        if (m_impl)
        {
            logger(LogLevel::warn, "container_instances already started");
            return;
        }
        m_impl = std::make_unique<Impl>(parseConfig(configuration), std::move(logger));
    }

    void ContainerInstancesFacade::stop()
    {
        std::unique_ptr<Impl> impl;
        {
            std::lock_guard<std::mutex> lock(m_mutex);
            impl = std::move(m_impl);
        }
        impl.reset();
    }

} // namespace wazuh::container_instances
