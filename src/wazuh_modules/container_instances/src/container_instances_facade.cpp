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
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace wazuh::container_instances
{

    namespace
    {

        ModuleConfig parseConfig(const nlohmann::json& configuration)
        {
            ModuleConfig config;

            if (configuration.contains("kubernetes"))
            {
                const auto& block = configuration["kubernetes"];
                KubernetesConfig kubernetes; // Defaults from KubernetesConfig apply when tags are absent.
                kubernetes.kubeconfigPath = block.value("kubeconfig", kubernetes.kubeconfigPath);
                kubernetes.nodeName = block.value("node_name", kubernetes.nodeName);
                kubernetes.ownershipPollInterval = std::chrono::seconds {block.value("ownership_poll_interval", 120)};
                kubernetes.insecureSkipTlsVerify = block.value("insecure_skip_tls_verify", false);
                config.kubernetes = std::move(kubernetes);
            }
            if (configuration.contains("docker"))
            {
                const auto& block = configuration["docker"];
                DockerConfig docker;
                if (block.contains("socket_path"))
                {
                    docker.socketPaths.clear();
                    const auto& paths = block["socket_path"];
                    if (paths.is_array())
                    {
                        for (const auto& path : paths)
                        {
                            if (path.is_string() && !path.get<std::string>().empty())
                            {
                                docker.socketPaths.push_back(path.get<std::string>());
                            }
                        }
                    }
                    else if (paths.is_string())
                    {
                        docker.socketPaths.push_back(paths.get<std::string>());
                    }
                }
                if (docker.socketPaths.empty())
                {
                    docker.socketPaths.push_back("/var/run/docker.sock");
                }
                config.docker = std::move(docker);
            }
            if (!config.kubernetes && !config.docker)
            {
                throw std::runtime_error("container_instances: a kubernetes or docker section is required");
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
            std::vector<RefresherBinding> refreshers;
            std::string connectorNames;

            if (config.kubernetes)
            {
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
                RefresherBinding binding;
                binding.docker = false;
                binding.refresher = connector.get();
                refreshers.push_back(binding);
                m_connectors.push_back(std::move(connector));
                connectorNames = "kubernetes";
            }
            if (config.docker)
            {
                for (const auto& socketPath : config.docker.value().socketPaths)
                {
                    m_dockerClients.push_back(std::make_unique<DockerApiClient>(m_transport, socketPath, m_logger));
                    auto connector = std::make_unique<DockerConnector>(
                        *m_dockerClients.back(), m_resolver, m_store, dockerSource(socketPath), m_logger);
                    RefresherBinding binding;
                    binding.docker = true;
                    binding.refresher = connector.get();
                    refreshers.push_back(binding);
                    m_connectors.push_back(std::move(connector));
                    connectorNames += connectorNames.empty() ? "docker" : ",docker";
                }
            }

            m_queryService = std::make_unique<QueryService>(
                m_store, std::move(refreshers), m_resolver, RetryPolicy {}, connectorNames, m_logger);
            m_ipcServer = std::make_unique<IpcServer>(*m_queryService, config.ipcSocketPath, m_logger);

            if (m_ownershipPoller)
            {
                m_ownershipPoller->start(m_stop);
            }
            for (auto& connector : m_connectors)
            {
                m_connectorThreads.emplace_back([this, &connector] { connector->run(m_stop); });
            }

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
            for (auto& thread : m_connectorThreads)
            {
                if (thread.joinable())
                {
                    thread.join();
                }
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
        std::vector<std::unique_ptr<DockerApiClient>> m_dockerClients;
        std::vector<std::unique_ptr<IContainerConnector>> m_connectors;
        std::unique_ptr<QueryService> m_queryService;
        std::unique_ptr<IpcServer> m_ipcServer;
        std::vector<std::thread> m_connectorThreads;
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
