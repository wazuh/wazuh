#include "docker_api_client.hpp"

#include "../transport/ndjson_framer.hpp"
#include "docker_object_parser.hpp"

#include "json.hpp"

#include <mutex>
#include <utility>

namespace wazuh::container_instances
{

    namespace
    {

        /// Oldest Engine API this module speaks (Docker 19.03). Everything used here
        /// (list, inspect, events since=) is stable well before it.
        constexpr const char* MINIMUM_API_VERSION = "1.40";

        /// "1.41" -> {1, 41}. Returns {0, 0} on garbage (treated as too old).
        std::pair<int, int> parseApiVersion(const std::string& version)
        {
            const auto dot = version.find('.');
            if (dot == std::string::npos)
            {
                return {0, 0};
            }
            try
            {
                return {std::stoi(version.substr(0, dot)), std::stoi(version.substr(dot + 1))};
            }
            catch (const std::exception&)
            {
                return {0, 0};
            }
        }

        bool versionAtLeast(const std::string& version, const std::string& minimum)
        {
            return parseApiVersion(version) >= parseApiVersion(minimum);
        }

    } // namespace

    DockerApiClient::DockerApiClient(IHttpTransport& transport, std::string socketPath, Logger logger)
        : m_transport(transport)
        , m_socketPath(std::move(socketPath))
        , m_logger(std::move(logger))
        , m_apiVersion(MINIMUM_API_VERSION)
    {
    }

    std::string DockerApiClient::apiVersion() const
    {
        std::lock_guard<std::mutex> lock(m_versionMutex);
        return m_apiVersion;
    }

    HttpRequestSpec DockerApiClient::specFor(const std::string& resource) const
    {
        HttpRequestSpec spec;
        spec.unixSocket = m_socketPath;
        spec.url = "http://localhost" + resource;
        spec.headers = {"Accept: application/json"};
        return spec;
    }

    HttpResponse DockerApiClient::get(const std::string& resource) const
    {
        try
        {
            return m_transport.request(specFor(resource));
        }
        catch (const HttpTransportError& error)
        {
            throw DockerApiError(0, std::string {"docker daemon unreachable: "} + error.what());
        }
    }

    std::string DockerApiClient::negotiateVersion()
    {
        const auto response = get("/version");
        if (response.status != 200)
        {
            throw DockerApiError(response.status, "GET /version returned HTTP " + std::to_string(response.status));
        }

        const auto body = nlohmann::json::parse(response.body, nullptr, false);
        if (body.is_discarded())
        {
            throw DockerApiError(0, "GET /version returned malformed JSON");
        }

        const auto daemonVersion = body.value("ApiVersion", "");
        if (!versionAtLeast(daemonVersion, MINIMUM_API_VERSION))
        {
            throw DockerVersionTooOld(daemonVersion, MINIMUM_API_VERSION);
        }

        // Negotiate down to the oldest version BOTH sides accept: modern
        // daemons also reject clients below their MinAPIVersion (e.g. Docker
        // 29 requires >= 1.44). The endpoints used here are stable across
        // versions, so requesting a newer version string is safe.
        const auto daemonMinimum = body.value("MinAPIVersion", MINIMUM_API_VERSION);
        const auto negotiated =
            versionAtLeast(MINIMUM_API_VERSION, daemonMinimum) ? std::string {MINIMUM_API_VERSION} : daemonMinimum;
        {
            std::lock_guard<std::mutex> lock(m_versionMutex);
            m_apiVersion = negotiated;
        }
        return negotiated;
    }

    std::vector<ContainerSummary> DockerApiClient::listContainers()
    {
        const auto response = get("/v" + apiVersion() + "/containers/json");
        if (response.status != 200)
        {
            throw DockerApiError(response.status, "container list returned HTTP " + std::to_string(response.status));
        }

        const auto body = nlohmann::json::parse(response.body, nullptr, false);
        if (body.is_discarded() || !body.is_array())
        {
            throw DockerApiError(0, "container list returned malformed JSON");
        }
        return docker::parseContainerList(body);
    }

    ContainerDetail DockerApiClient::inspect(const std::string& containerId)
    {
        const auto response = get("/v" + apiVersion() + "/containers/" + containerId + "/json");
        if (response.status != 200)
        {
            throw DockerApiError(response.status,
                                 "inspect of " + containerId + " returned HTTP " + std::to_string(response.status));
        }

        const auto body = nlohmann::json::parse(response.body, nullptr, false);
        if (body.is_discarded() || !body.is_object())
        {
            throw DockerApiError(0, "inspect of " + containerId + " returned malformed JSON");
        }
        return docker::parseInspect(body);
    }

    StreamOutcome
    DockerApiClient::streamEvents(std::int64_t sinceSeconds, const DockerEventSink& sink, const StopController& stop)
    {
        auto spec = specFor("/v" + apiVersion() + "/events?since=" + std::to_string(sinceSeconds));
        spec.totalTimeout = std::chrono::milliseconds {0}; // Intentionally unterminated.

        NdjsonFramer framer;
        const auto result = m_transport.stream(
            spec,
            [&framer, &sink, this](std::string_view chunk)
            {
                for (const auto& line : framer.push(chunk))
                {
                    if (const auto event = docker::parseEventLine(line))
                    {
                        sink(*event);
                    }
                    else
                    {
                        m_logger(LogLevel::debugVerbose, "Ignored /events line: " + line.substr(0, 128));
                    }
                }
                return true;
            },
            stop);

        StreamOutcome outcome;
        outcome.kind = (result.kind == StreamResult::Kind::cancelled) ? StreamOutcome::Kind::cancelled
                                                                      : StreamOutcome::Kind::disconnected;
        outcome.message = result.message;
        return outcome;
    }

} // namespace wazuh::container_instances
