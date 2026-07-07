#include "kubernetes_api_client.hpp"

#include "../transport/ndjson_framer.hpp"
#include "k8s_object_parser.hpp"

#include "json.hpp"

#include <array>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        constexpr long HTTP_GONE = 410;

        std::string trim(const std::string& text)
        {
            const auto begin = text.find_first_not_of(" \t\r\n");
            if (begin == std::string::npos)
            {
                return "";
            }
            const auto end = text.find_last_not_of(" \t\r\n");
            return text.substr(begin, end - begin + 1);
        }

        struct TokenResolver
        {
            const IFileIOUtils& fileIO;

            std::string operator()(const std::monostate&) const
            {
                return "";
            }

            std::string operator()(const StaticToken& token) const
            {
                return token.token;
            }

            std::string operator()(const TokenFile& tokenFile) const
            {
                // Re-read on every call: rotation-safe by construction.
                return trim(fileIO.getFileContent(tokenFile.path));
            }
        };

    } // namespace

    KubernetesApiClient::KubernetesApiClient(IHttpTransport& transport,
                                             const IKubeconfigLoader& kubeconfigLoader,
                                             const IFileIOUtils& fileIO,
                                             KubernetesClientConfig config,
                                             Logger logger)
        : m_transport(transport)
        , m_kubeconfigLoader(kubeconfigLoader)
        , m_fileIO(fileIO)
        , m_config(std::move(config))
        , m_logger(std::move(logger))
    {
    }

    HttpRequestSpec KubernetesApiClient::specFor(const std::string& resource) const
    {
        const auto credentials = m_kubeconfigLoader.load(m_config.kubeconfigPath);

        HttpRequestSpec spec;
        spec.url = credentials.serverUrl + resource;
        spec.tls.caBlob = credentials.caBlob;
        if (credentials.clientCert)
        {
            spec.tls.clientCertBlob = credentials.clientCert->certBlob;
            spec.tls.clientKeyBlob = credentials.clientCert->keyBlob;
        }
        spec.tls.skipVerify = credentials.skipVerify || m_config.insecureSkipTlsVerify;
        if (spec.tls.skipVerify && !m_skipVerifyWarned)
        {
            m_logger(LogLevel::warn,
                     "TLS verification of the Kubernetes apiserver is DISABLED "
                     "(insecure-skip-tls-verify) — use for development only");
            m_skipVerifyWarned = true;
        }

        spec.headers = {"Accept: application/json"};
        const auto token = std::visit(TokenResolver {m_fileIO}, credentials.token);
        if (!token.empty())
        {
            spec.headers.push_back("Authorization: Bearer " + token);
        }

        return spec;
    }

    HttpResponse KubernetesApiClient::get(const std::string& resource) const
    {
        try
        {
            return m_transport.request(specFor(resource));
        }
        catch (const HttpTransportError& error)
        {
            throw KubernetesApiError(0, std::string {"apiserver unreachable: "} + error.what());
        }
        catch (const KubeconfigError& error)
        {
            throw KubernetesApiError(0, error.what());
        }
    }

    std::string KubernetesApiClient::podsResource() const
    {
        return "/api/v1/pods?fieldSelector=spec.nodeName%3D" + m_config.nodeName;
    }

    PodList KubernetesApiClient::listPods()
    {
        const auto response = get(podsResource());
        if (response.status != 200)
        {
            throw KubernetesApiError(response.status, "pod list returned HTTP " + std::to_string(response.status));
        }

        const auto body = nlohmann::json::parse(response.body, nullptr, false);
        if (body.is_discarded() || !body.is_object())
        {
            throw KubernetesApiError(0, "pod list returned malformed JSON");
        }
        return k8s::parsePodList(body);
    }

    WatchOutcome KubernetesApiClient::watchPods(const std::string& resourceVersion,
                                                const PodEventSink& sink,
                                                const StopController& stop)
    {
        HttpRequestSpec spec;
        try
        {
            spec = specFor(podsResource() + "&watch=true&allowWatchBookmarks=true&resourceVersion=" + resourceVersion);
        }
        catch (const KubeconfigError& error)
        {
            WatchOutcome outcome;
            outcome.kind = WatchOutcome::Kind::disconnected;
            outcome.message = error.what();
            return outcome;
        }
        spec.totalTimeout = std::chrono::milliseconds {0}; // Intentionally unterminated.

        NdjsonFramer framer;
        bool sawGone = false;

        const auto result = m_transport.stream(
            spec,
            [&framer, &sink, &sawGone, this](std::string_view chunk)
            {
                for (const auto& line : framer.push(chunk))
                {
                    const auto event = k8s::parseWatchLine(line);
                    if (!event)
                    {
                        m_logger(LogLevel::warn, "Skipped unparseable watch line: " + line.substr(0, 128));
                        continue;
                    }
                    if (event->type == PodEventType::error && event->errorCode == HTTP_GONE)
                    {
                        sawGone = true; // apiserver signals expiry in-stream too.
                        return false;
                    }
                    sink(*event);
                }
                return true;
            },
            stop);

        WatchOutcome outcome;
        if (result.kind == StreamResult::Kind::cancelled)
        {
            outcome.kind = WatchOutcome::Kind::cancelled;
        }
        else if (sawGone || result.httpStatus == HTTP_GONE)
        {
            outcome.kind = WatchOutcome::Kind::gone;
            outcome.message = "watch resourceVersion expired (410)";
        }
        else
        {
            outcome.kind = WatchOutcome::Kind::disconnected;
            outcome.message = result.message;
        }
        return outcome;
    }

    WorkloadIndex KubernetesApiClient::listWorkloads()
    {
        static constexpr std::array<const char*, 6> RESOURCES {"/apis/apps/v1/replicasets",
                                                               "/apis/apps/v1/deployments",
                                                               "/apis/apps/v1/statefulsets",
                                                               "/apis/apps/v1/daemonsets",
                                                               "/apis/batch/v1/jobs",
                                                               "/apis/batch/v1/cronjobs"};

        WorkloadIndex index;
        for (const auto* resource : RESOURCES)
        {
            const auto response = get(resource);
            if (response.status != 200)
            {
                throw KubernetesApiError(response.status,
                                         std::string {resource} + " returned HTTP " + std::to_string(response.status));
            }
            const auto body = nlohmann::json::parse(response.body, nullptr, false);
            if (body.is_discarded() || !body.is_object())
            {
                throw KubernetesApiError(0, std::string {resource} + " returned malformed JSON");
            }
            k8s::mergeWorkloadList(body, index);
        }
        return index;
    }

} // namespace wazuh::container_instances
