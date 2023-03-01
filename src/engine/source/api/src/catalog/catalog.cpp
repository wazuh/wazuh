#include "api/catalog/catalog.hpp"

#include <fmt/format.h>
#include <logging/logging.hpp>

#include "yml2Json.hpp"

namespace api::catalog
{

void Config::validate() const
{
    if (!store)
    {
        throw std::runtime_error("Store is not set");
    }
    if (!validator)
    {
        throw std::runtime_error("Assets, environments and schemas Validator is not set");
    }
    if (assetSchema.empty())
    {
        throw std::runtime_error("Assets Schema is not set");
    }
    if (environmentSchema.empty())
    {
        throw std::runtime_error("Environments Schema is not set");
    }
}

Catalog::Catalog(const Config& config)
{
    config.validate();
    m_store = config.store;
    m_validator = config.validator;

    WAZUH_LOG_DEBUG("Engine catalog: \"{}\" method: Asset schema name: \"{}\". "
                    "Environment schema name: \"{}\".",
                    __func__,
                    config.assetSchema,
                    config.environmentSchema);

    // Json handling
    m_outFormat[Resource::Format::JSON] = [](const json::Json& json)
    {
        return json.str();
    };

    // TODO: what is str?
    m_inFormat[Resource::Format::JSON] = [](const std::string& str)
    {
        std::variant<json::Json, base::Error> result;
        try
        {
            result = json::Json {str.c_str()};
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_DEBUG(
                "Engine catalog: 'Catalog(const Config& config)' method: Config: '{}'.", str);
            result = base::Error {e.what()};
        }

        return result;
    };

    // Yaml handling
    m_outFormat[Resource::Format::YAML] = [](const json::Json& json)
    {
        std::variant<std::string, base::Error> result;
        try
        {
            // TODO: Expose internals on json::Json ??
            rapidjson::Document doc;
            doc.Parse(json.str().c_str());
            auto yaml = yml2json::internal::json2yaml(doc);
            YAML::Emitter out;
            out << yaml;
            result = out.c_str();
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_DEBUG("Engine catalog: Config: \"{}\".", json.str());
            result = base::Error {e.what()};
        }

        return result;
    };

    m_inFormat[Resource::Format::YAML] = [](const std::string& content)
    {
        std::variant<json::Json, base::Error> result;
        try
        {
            result = json::Json {yml2json::loadYMLfromString(content)};
        }
        catch (const std::exception& e)
        {
            WAZUH_LOG_DEBUG("Engine catalog: Config: \"{}\".", content);
            result = base::Error {e.what()};
        }

        return result;
    };

    // Get schemas
    base::Name assetSchemaName;
    base::Name environmentSchemaName;

    try
    {
        assetSchemaName = base::Name {config.assetSchema};
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Error while parsing the asset schema: {}", e.what()));
    }
    try
    {
        environmentSchemaName = base::Name {config.environmentSchema};
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(
            fmt::format("Error while parsing the environment schema name: {}", e.what()));
    }
    auto assetSchemaJson = m_store->get(assetSchemaName);
    if (std::holds_alternative<base::Error>(assetSchemaJson))
    {
        throw std::runtime_error(
            fmt::format("Error while getting the asset schema: {}",
                        std::get<base::Error>(assetSchemaJson).message));
    }

    m_schemas[Resource::Type::DECODER] = std::get<json::Json>(assetSchemaJson);
    m_schemas[Resource::Type::RULE] = std::get<json::Json>(assetSchemaJson);
    m_schemas[Resource::Type::OUTPUT] = std::get<json::Json>(assetSchemaJson);
    m_schemas[Resource::Type::FILTER] = std::get<json::Json>(assetSchemaJson);

    const auto environmentSchemaJson = m_store->get(environmentSchemaName);
    if (std::holds_alternative<base::Error>(environmentSchemaJson))
    {
        throw std::runtime_error(
            fmt::format("Error while getting the environment schema: {}",
                        std::get<base::Error>(environmentSchemaJson).message));
    }
    m_schemas[Resource::Type::ENVIRONMENT] = std::get<json::Json>(environmentSchemaJson);
}

std::optional<base::Error> Catalog::postResource(const Resource& collection,
                                                 const std::string& content)
{
    WAZUH_LOG_DEBUG("Engine catalog: '{}' method: Collection name: '{}'. Content: '{}'.",
                    __func__,
                    collection.m_name.fullName(),
                    content);

    // Specified resource must be a collection
    if (Resource::Type::COLLECTION != collection.m_type)
    {
        return base::Error {
            fmt::format(R"(Expected resource type is "{}", but got "{}")",
                        Resource::typeToStr(collection.m_type),
                        Resource::typeToStr(Resource::Type::COLLECTION))};
    }

    // content must be a valid resource for the specified collection
    // Build the resource Json, input content format must be the expected by the
    // collection and the name type of the content must be the same as the
    // collection
    const auto formatResult = m_inFormat[collection.m_format](content);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {
            fmt::format("JSON object could not be created from \"{} {}\": {}",
                        Resource::formatToStr(collection.m_format),
                        collection.m_name.fullName(),
                        std::get<base::Error>(formatResult).message)};
    }

    const auto contentJson = std::get<json::Json>(formatResult);
    const auto contentNameStr = contentJson.getString("/name");
    if (!contentNameStr)
    {
        return base::Error {fmt::format("Field \"name\" is missing in content")};
    }
    else if (contentNameStr.value().empty())
    {
        return base::Error {fmt::format("Field \"name\" cannot be empty")};
    }

    // Build the resource type of the content from the name
    base::Name contentName;
    Resource contentResource;
    try
    {
        contentName = base::Name(contentNameStr.value());
        contentResource = Resource(contentName, Resource::Format::JSON);
    }
    // Invalid content name
    catch (const std::exception& e)
    {
        return base::Error {fmt::format(
            "Invalid content name \"{}\": {}", contentNameStr.value(), e.what())};
    }

    // Assert content type is not a collection
    if (Resource::Type::COLLECTION == contentResource.m_type)
    {
        return base::Error {
            fmt::format("The asset \"{}\" cannot be added to the store: The name format "
                        "is not valid as it is identified as a \"collection\"",
                        contentNameStr.value())};
    }

    // Assert content type is the same as the collection
    for (auto i = 0; i < collection.m_name.parts().size(); ++i)
    {
        if (collection.m_name.parts()[i] != contentName.parts()[i])
        {
            return base::Error {
                fmt::format(R"(Invalid content name "{}" for collection "{}")",
                            contentName.fullName(),
                            collection.m_name.fullName())};
        }
    }

    // Validate the content if needed
    if (contentResource.m_validation)
    {
        const auto validationError = validate(contentResource, contentJson);

        if (validationError)
        {
            return base::Error {
                fmt::format("An error occurred while trying to validate \"{}\": {}",
                            contentNameStr.value(),
                            validationError.value().message)};
        }
    }

    // All pre-conditions are met, post the content in the store
    const auto storeError = m_store->add(contentResource.m_name, contentJson);
    if (storeError)
    {
        return base::Error {fmt::format("Content \"{}\" could not be added to store: {}",
                                        contentNameStr.value(),
                                        storeError.value().message)};
    }

    return std::nullopt;
}

std::optional<base::Error> Catalog::putResource(const Resource& item,
                                                const std::string& content)
{
    WAZUH_LOG_DEBUG("Engine catalog: \"{}\" method: Item name: \"{}\".",
                    __func__,
                    item.m_name.fullName());

    // Specified resource must be a Environment, Schema or Asset
    if (Resource::Type::ENVIRONMENT != item.m_type
        && Resource::Type::SCHEMA != item.m_type && Resource::Type::DECODER != item.m_type
        && Resource::Type::RULE != item.m_type && Resource::Type::FILTER != item.m_type
        && Resource::Type::OUTPUT != item.m_type)
    {
        return base::Error {fmt::format("Invalid resource type \"{}\" for PUT operation",
                                        Resource::typeToStr(item.m_type))};
    }

    // content must correspond to the specified resource
    // Build the resource Json, input content format must be the expected by the
    // resource
    const auto formatResult = m_inFormat[item.m_format](content);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {
            fmt::format("JSON object could not be created from \"{} {}\": {}",
                        Resource::formatToStr(item.m_format),
                        item.m_name.fullName(),
                        std::get<base::Error>(formatResult).message)};
    }

    const auto contentJson = std::get<json::Json>(formatResult);
    const auto contentNameStr = contentJson.getString("/name");
    if (!contentNameStr)
    {
        return base::Error {"Field \"name\" is missing in content"};
    }

    base::Name contentName;
    try
    {
        contentName = base::Name(contentNameStr.value());
    }
    // Invalid content name
    catch (const std::exception& e)
    {
        return base::Error {fmt::format(
            "Invalid content name \"{}\": {}", contentNameStr.value(), e.what())};
    }

    // Assert content name is the same as the resource name
    if (contentName != item.m_name)
    {
        return base::Error {
            fmt::format(R"(Invalid content name "{}" of "{}" for type "{}")",
                        contentNameStr.value(),
                        item.m_name.fullName(),
                        Resource::typeToStr(item.m_type))};
    }

    // Validate the content if needed
    if (item.m_validation)
    {
        const auto validationError = validate(item, contentJson);

        if (validationError)
        {
            return base::Error {
                fmt::format("An error occurred while trying to validate \"{}\": {}",
                            contentNameStr.value(),
                            validationError.value().message)};
        }
    }

    // All pre-conditions are met, update the content in the store
    const auto storeError = m_store->update(item.m_name, contentJson);
    if (storeError)
    {
        return base::Error {
            fmt::format("Content \"{}\" could not be updated in store: {}",
                        contentNameStr.value(),
                        storeError.value().message)};
    }

    return std::nullopt;
}

std::variant<std::string, base::Error>
Catalog::getResource(const Resource& resource) const
{
    // Get the content from the store
    const auto storeResult = m_store->get(resource.m_name);
    if (std::holds_alternative<base::Error>(storeResult))
    {
        return base::Error {
            fmt::format("Content \"{}\" could not be obtained from store: {}",
                        resource.m_name.fullName(),
                        std::get<base::Error>(storeResult).message)};
    }

    const auto contentJson = std::get<json::Json>(storeResult);
    // Format the content to the expected output format
    const auto formatterIt = m_outFormat.find(resource.m_format);
    if (formatterIt == m_outFormat.end())
    {
        return base::Error {fmt::format("Formatter was not found for format \"{}\"",
                                        Resource::formatToStr(resource.m_format))};
    }
    const auto formatResult = formatterIt->second(contentJson);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {
            fmt::format("JSON object could not be created from \"{} {}\": {}",
                        Resource::formatToStr(resource.m_format),
                        resource.m_name.fullName(),
                        std::get<base::Error>(formatResult).message)};
    }

    return std::get<std::string>(formatResult);
}

std::optional<base::Error> Catalog::deleteResource(const Resource& resource)
{
    const auto storeError = m_store->del(resource.m_name);
    if (storeError)
    {
        return base::Error {
            fmt::format("Content \"{}\" could not be deleted from store: {}",
                        resource.m_name.fullName(),
                        storeError.value().message)};
    }

    return std::nullopt;
}

std::optional<base::Error> Catalog::validate(const Resource& item,
                                             const json::Json& content) const
{
    // Assert resource type is Asset or Environment
    if (Resource::Type::DECODER != item.m_type && Resource::Type::RULE != item.m_type
        && Resource::Type::FILTER != item.m_type && Resource::Type::OUTPUT != item.m_type
        && Resource::Type::ENVIRONMENT != item.m_type)
    {
        return base::Error {fmt::format("Invalid resource type \"{}\"", Resource::typeToStr(item.m_type))};
    }

    // Validate against the schema first
    // TODO: Implement when we support a v7+ validator
    // auto schemaIt = m_schemas.find(item.m_type);

    // if (schemaIt == m_schemas.end())
    // {
    //     return base::Error {
    //         fmt::format("[Catalog] Schema validator not found for type [{}]",
    //                     Resource::typeToStr(item.m_type))};
    // }

    // auto validationError = content.validate(schemaIt->second);
    // if (validationError)
    // {
    //     return base::Error {fmt::format("[Catalog] Schema validation failed for [{}],
    //     {}",
    //                                     item.m_name.fullName(),
    //                                     validationError.value().message)};
    // }

    // Builder validator
    std::optional<base::Error> validationError;
    if (item.m_type == Resource::Type::DECODER || item.m_type == Resource::Type::RULE
        || item.m_type == Resource::Type::FILTER || item.m_type == Resource::Type::OUTPUT)
    {
        validationError = m_validator->validateAsset(content);
    }
    else if (item.m_type == Resource::Type::ENVIRONMENT)
    {
        validationError = m_validator->validateEnvironment(content);
    }
    else
    {
        return base::Error {fmt::format("Validator not found for type \"{}\"",
                                        Resource::typeToStr(item.m_type))};
    }

    if (validationError)
    {
        return base::Error {validationError.value().message};
    }

    return std::nullopt;
}

std::optional<base::Error> Catalog::validateResource(const Resource& item,
                                                     const std::string& content) const
{
    // Assert resource is asset or environment
    if (Resource::Type::DECODER != item.m_type && Resource::Type::RULE != item.m_type
        && Resource::Type::FILTER != item.m_type && Resource::Type::OUTPUT != item.m_type
        && Resource::Type::ENVIRONMENT != item.m_type)
    {
        return base::Error {
            fmt::format("Invalid resource type \"{}\" for VALIDATE operation",
                        Resource::typeToStr(item.m_type))};
    }

    // Build the content json
    const auto formatterIt = m_inFormat.find(item.m_format);
    if (formatterIt == m_inFormat.end())
    {
        return base::Error {fmt::format("Formatter was not found for format \"{}\"",
                                        Resource::formatToStr(item.m_format))};
    }

    const auto contentJson = formatterIt->second(content);
    if (std::holds_alternative<base::Error>(contentJson))
    {
        return base::Error {fmt::format("Content could not be parsed to json: {}",
                                        std::get<base::Error>(contentJson).message)};
    }

    // Validate the content
    const auto validationError = validate(item, std::get<json::Json>(contentJson));

    if (validationError)
    {
        return base::Error {validationError.value().message};
    }

    return std::nullopt;
}
} // namespace api::catalog
