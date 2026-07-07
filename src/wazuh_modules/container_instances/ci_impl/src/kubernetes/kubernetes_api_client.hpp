#pragma once

#include "../core/logger.hpp"
#include "../transport/i_http_transport.hpp"
#include "i_kubeconfig_loader.hpp"
#include "i_kubernetes_api_client.hpp"
#include "ifile_io_utils.hpp"

#include <string>

namespace wazuh::container_instances
{

    struct KubernetesClientConfig
    {
        std::string kubeconfigPath;
        std::string nodeName;
        bool insecureSkipTlsVerify {false}; ///< ossec.conf override; OR-ed with the kubeconfig flag.
    };

    /// apiserver client. Credentials are re-resolved from the kubeconfig at the
    /// top of every call (token files re-read included), so external rotation
    /// works without restart or refresh threads.
    class KubernetesApiClient final : public IKubernetesApiClient
    {
    public:
        KubernetesApiClient(IHttpTransport& transport,
                            const IKubeconfigLoader& kubeconfigLoader,
                            const IFileIOUtils& fileIO,
                            KubernetesClientConfig config,
                            Logger logger);

        [[nodiscard]] PodList listPods() override;
        [[nodiscard]] WatchOutcome
        watchPods(const std::string& resourceVersion, const PodEventSink& sink, const StopController& stop) override;
        [[nodiscard]] WorkloadIndex listWorkloads() override;

    private:
        [[nodiscard]] HttpRequestSpec specFor(const std::string& resource) const;
        [[nodiscard]] HttpResponse get(const std::string& resource) const;
        [[nodiscard]] std::string podsResource() const;

        IHttpTransport& m_transport;
        const IKubeconfigLoader& m_kubeconfigLoader;
        const IFileIOUtils& m_fileIO;
        KubernetesClientConfig m_config;
        Logger m_logger;
        mutable bool m_skipVerifyWarned {false};
    };

} // namespace wazuh::container_instances
