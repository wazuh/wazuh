#include <conf/apiLoader.hpp>

#include <base/logging.hpp>

#include <UNIXSocketRequest.hpp>

namespace conf
{

constexpr auto URL_CONFIG {"http://localhost/api/v1/config?sections=indexer,engine"}; ///< Endpoint to get the config
constexpr auto SOCKET_CONFIG {"/run/wazuh-server/config-server.sock"};                ///< Unix socket to get the config

json::Json ApiLoader::load() const
{
    // Allow starting the engine without the API
    if (const auto env = std::getenv("WAZUH_CONFIG_SKIP_API"); env != nullptr && std::string(env) == "true")
    {
        LOG_INFO("Skipping configuration from API.");
        return json::Json(R"({})");
    }

    // Send the request to the API
    std::string json_response {};
    struct RequestParameters requestParam
    {
        .url = HttpUnixSocketURL(SOCKET_CONFIG, URL_CONFIG)
    };

    struct PostRequestParameters postRequestParameters
    {
        .onSuccess = [&json_response](const std::string& msg) mutable -> void { json_response = msg; },
        .onError = [](const std::string& msg, const long responseCode) mutable -> void
        {
            throw std::runtime_error(
                fmt::format("Error while loading configuration from API: '{}' - '{}'", msg, responseCode));
        }
    };

    UNIXSocketRequest::instance().get(requestParam, postRequestParameters, {});

    // Parse the response
    json::Json config {};
    try
    {
        config = json::Json(json_response.c_str());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Error while parsing configuration from API: '{}'", e.what()));
    }

    if (!config.isObject())
    {
        throw std::runtime_error("Invalid configuration from API: not an object");
    }

    return config;
}

} // namespace conf
