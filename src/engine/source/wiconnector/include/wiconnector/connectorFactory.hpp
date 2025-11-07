#ifndef _CONNECTOR_FACTORY_HPP
#define _CONNECTOR_FACTORY_HPP

#include <memory>
#include <string>
#include <string_view>
#include <stdexcept>

#include <json.hpp>
#include <wiconnector/iwindexerconnector.hpp>
#include <wiconnector/windexerconnector.hpp>
#include <wiconnector/wquickwitconnector.hpp>

namespace wiconnector
{

/**
 * @brief Factory class for creating indexer connectors.
 *
 * This factory creates the appropriate connector (OpenSearch or Quickwit)
 * based on the configuration provided.
 */
class ConnectorFactory
{
public:
    /**
     * @brief Connector types supported by the factory.
     */
    enum class ConnectorType
    {
        OPENSEARCH,
        QUICKWIT
    };

    /**
     * @brief Creates an indexer connector based on the JSON configuration.
     *
     * The configuration should contain a "type" field that specifies the backend:
     * - "opensearch" or "elasticsearch" for OpenSearch/Elasticsearch
     * - "quickwit" for Quickwit
     * If no type is specified, OpenSearch is used by default for backward compatibility.
     *
     * @param jsonConfig JSON configuration string containing connector settings
     * @return std::unique_ptr<IWIndexerConnector> Pointer to the created connector
     * @throws std::runtime_error If configuration is invalid or connector creation fails
     */
    static std::unique_ptr<IWIndexerConnector> createConnector(std::string_view jsonConfig)
    {
        if (jsonConfig.empty())
        {
            throw std::runtime_error("Empty JSON configuration for connector");
        }

        const auto jsonParsed = nlohmann::json::parse(jsonConfig, nullptr, false);
        if (jsonParsed.is_discarded())
        {
            throw std::runtime_error("Invalid JSON configuration for connector");
        }

        return createConnector(jsonParsed);
    }

    /**
     * @brief Creates an indexer connector based on the JSON configuration object.
     *
     * @param config JSON configuration object
     * @return std::unique_ptr<IWIndexerConnector> Pointer to the created connector
     * @throws std::runtime_error If configuration is invalid or connector creation fails
     */
    static std::unique_ptr<IWIndexerConnector> createConnector(const nlohmann::json& config)
    {
        ConnectorType type = determineConnectorType(config);

        switch (type)
        {
            case ConnectorType::QUICKWIT:
                return std::make_unique<WQuickwitConnector>(config.dump());

            case ConnectorType::OPENSEARCH:
            default:
                return std::make_unique<WIndexerConnector>(config.dump());
        }
    }

    /**
     * @brief Creates an indexer connector with explicit type specification.
     *
     * @param type The connector type to create
     * @param jsonConfig JSON configuration string
     * @return std::unique_ptr<IWIndexerConnector> Pointer to the created connector
     * @throws std::runtime_error If configuration is invalid or connector creation fails
     */
    static std::unique_ptr<IWIndexerConnector> createConnector(ConnectorType type, std::string_view jsonConfig)
    {
        switch (type)
        {
            case ConnectorType::QUICKWIT:
                return std::make_unique<WQuickwitConnector>(jsonConfig);

            case ConnectorType::OPENSEARCH:
            default:
                return std::make_unique<WIndexerConnector>(jsonConfig);
        }
    }

private:
    /**
     * @brief Determines the connector type from the configuration.
     *
     * Looks for a "type" field in the configuration. Supported values:
     * - "quickwit" -> ConnectorType::QUICKWIT
     * - "opensearch", "elasticsearch", or not specified -> ConnectorType::OPENSEARCH (default)
     *
     * @param config JSON configuration object
     * @return ConnectorType The determined connector type
     */
    static ConnectorType determineConnectorType(const nlohmann::json& config)
    {
        if (config.contains("type"))
        {
            std::string typeStr = config.at("type").get<std::string>();

            // Convert to lowercase for case-insensitive comparison
            std::transform(typeStr.begin(), typeStr.end(), typeStr.begin(),
                         [](unsigned char c) { return std::tolower(c); });

            if (typeStr == "quickwit")
            {
                return ConnectorType::QUICKWIT;
            }
            else if (typeStr == "opensearch" || typeStr == "elasticsearch")
            {
                return ConnectorType::OPENSEARCH;
            }
            else
            {
                throw std::runtime_error("Unknown connector type: " + typeStr);
            }
        }

        // Default to OpenSearch for backward compatibility
        return ConnectorType::OPENSEARCH;
    }
};

} // namespace wiconnector

#endif // _CONNECTOR_FACTORY_HPP
