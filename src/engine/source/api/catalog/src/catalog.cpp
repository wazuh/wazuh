#include <api/catalog/catalog.hpp>

#include <base/logging.hpp>
#include <fmt/format.h>

#include <store/utils.hpp>
#include <yml/yml.hpp>

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
}

Catalog::Catalog(const Config& config)
{
    config.validate();
    m_store = config.store;
    m_validator = config.validator;

    LOG_DEBUG("Engine catalog: constructor: Asset schema name: '{}'.", config.assetSchema);

    // Json handling
    m_outFormat[Resource::Format::json] = [](const json::Json& json)
    {
        return json.str();
    };

    m_inFormat[Resource::Format::json] = [](const std::string& str)
    {
        base::RespOrError<json::Json> result;
        try
        {
            result = json::Json {str.c_str()};
            if (std::holds_alternative<json::Json>(result))
            {
                auto error = std::get<json::Json>(result).checkDuplicateKeys();
                if (base::isError(error))
                {
                    result = base::getError(error);
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG("Engine catalog: Config: '{}'.", str);
            result = base::Error {e.what()};
        }

        return result;
    };

    // Yaml handling
    m_outFormat[Resource::Format::yaml] = [](const json::Json& json)
    {
        base::RespOrError<std::string> result;
        try
        {
            rapidjson::Document doc;
            doc.Parse(json.str().c_str());
            auto yaml = yml::Converter::jsonToYaml(doc);
            YAML::Emitter out;
            out << yaml;
            result = out.c_str();
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG("Engine catalog: Config: '{}'.", json.str());
            result = base::Error {e.what()};
        }

        return result;
    };

    m_inFormat[Resource::Format::yaml] = [](const std::string& content)
    {
        base::RespOrError<json::Json> result;
        try
        {
            result = json::Json {yml::Converter::loadYMLfromString(content)};
            if (std::holds_alternative<json::Json>(result))
            {
                auto error = std::get<json::Json>(result).checkDuplicateKeys();
                if (base::isError(error))
                {
                    result = base::getError(error);
                }
            }
        }
        catch (const std::exception& e)
        {
            LOG_DEBUG("Engine catalog: Config: '{}'.", content);
            result = base::Error {e.what()};
        }

        return result;
    };
}

base::OptError
Catalog::postResource(const Resource& collection, const std::string& namespaceStr, const std::string& content)
{
    LOG_DEBUG("Engine catalog: '{}' method: Collection name: '{}'. Content: '{}'.",
              __func__,
              collection.m_name.fullName(),
              content);

    // Specified resource must be a collection
    if (Resource::Type::collection != collection.m_type)
    {
        return base::Error {fmt::format("Expected resource type is '{}', but got '{}'",
                                        Resource::typeToStr(collection.m_type),
                                        Resource::typeToStr(Resource::Type::collection))};
    }

    // Verify namespace
    base::OptError namespaceError;
    store::NamespaceId namespaceId = [&namespaceError, &namespaceStr]()
    {
        try
        {
            return store::NamespaceId {namespaceStr};
        }
        catch (const std::exception& e)
        {
            namespaceError = base::Error {fmt::format("Invalid namespace '{}': {}", namespaceStr, e.what())};
            return store::NamespaceId {};
        }
    }();

    if (namespaceError)
    {
        return namespaceError;
    }

    // content must be a valid resource for the specified collection
    // Build the resource Json, input content format must be the expected by the
    // collection and the name type of the content must be the same as the
    // collection
    const auto formatResult = m_inFormat[collection.m_format](content);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {fmt::format("JSON object could not be created from '{} {}': {}",
                                        Resource::formatToStr(collection.m_format),
                                        collection.m_name.fullName(),
                                        std::get<base::Error>(formatResult).message)};
    }

    const auto& contentJson = std::get<json::Json>(formatResult);
    const auto contentNameStr = contentJson.getString("/name");
    if (!contentNameStr)
    {
        return base::Error {fmt::format("Field 'name' is missing in content")};
    }
    else if (contentNameStr.value().empty())
    {
        return base::Error {fmt::format("Field 'name' cannot be empty")};
    }

    // Build the resource type of the content from the name
    base::Name contentName;
    Resource contentResource;
    try
    {
        contentName = base::Name(contentNameStr.value());
        contentResource = Resource(contentName, Resource::Format::json);
    }
    // Invalid content name
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Invalid content name '{}': {}", contentNameStr.value(), e.what())};
    }

    // Assert content type is not a collection
    if (Resource::Type::collection == contentResource.m_type)
    {
        return base::Error {fmt::format("The asset '{}' cannot be added to the store: The name format is not valid as "
                                        "it is identified as a 'collection'",
                                        contentNameStr.value())};
    }

    // Assert content type is the same as the collection
    for (auto i = 0; i < collection.m_name.parts().size(); ++i)
    {
        if (collection.m_name.parts()[i] != contentName.parts()[i])
        {
            return base::Error {fmt::format(
                "Invalid content name '{}' for collection '{}'", contentName.fullName(), collection.m_name.fullName())};
        }
    }

    // Validate the content if needed
    if (contentResource.m_validation)
    {
        const auto validationError = validate(contentResource, namespaceStr, contentJson);

        if (validationError)
        {
            return base::Error {fmt::format("An error occurred while trying to validate '{}': {}",
                                            contentNameStr.value(),
                                            validationError.value().message)};
        }
    }

    // All pre-conditions are met, post the content in the store
    const auto storeError = store::utils::add(
        m_store, contentResource.m_name, namespaceId, Resource::formatToStr(collection.m_format), contentJson, content);
    if (storeError)
    {
        return base::Error {fmt::format(
            "Content '{}' could not be added to store: {}", contentNameStr.value(), storeError.value().message)};
    }

    return base::noError();
    ;
}

base::OptError Catalog::checkResourceInNamespace(const api::catalog::Resource& item,
                                                 const std::string& namespaceId,
                                                 const std::string& operation) const
{
    // Assert namespaceIds is not empty
    if (namespaceId.empty())
    {
        return base::Error {"Namespace id cannot be empty"};
    }

    // Get namespace associated with the resource
    auto getNamespace = [store = m_store](const api::catalog::Resource& item) -> base::RespOrError<store::NamespaceId>
    {
        auto ns = store->getNamespace(item.m_name);
        if (!ns)
        {
            return base::Error {fmt::format("Resource '{}' does not have an associated namespace", item.m_name)};
        }
        return ns.value();
    };

    // Check if the resource exist in the namespace
    auto ns = getNamespace(item);
    if (base::isError(ns))
    {
        return base::Error {fmt::format(
            "Could not {} resource '{}': {}", operation, item.m_name.fullName(), base::getError(ns).message)};
    }

    if (namespaceId != base::getResponse(ns).str())
    {
        return base::Error {fmt::format("Could not {} resource '{}': Does not exist in the '{}' namespace",
                                        operation,
                                        item.m_name.fullName(),
                                        namespaceId)};
    }

    return base::noError();
}

base::OptError Catalog::putResource(const Resource& item, const std::string& content, const std::string& namespaceId)
{
    LOG_DEBUG("Engine catalog: '{}' method: Item name: '{}'.", __func__, item.m_name.fullName());

    // Specified resource must be an Asset
    if (Resource::Type::decoder != item.m_type && Resource::Type::rule != item.m_type
        && Resource::Type::filter != item.m_type && Resource::Type::output != item.m_type
        && Resource::Type::integration != item.m_type)
    {
        return base::Error {
            fmt::format("Invalid resource type '{}' for PUT operation", Resource::typeToStr(item.m_type))};
    }

    // Check if resource exist in the namespace requested
    auto error = checkResourceInNamespace(item, namespaceId, "update");
    if (base::isError(error))
    {
        return base::getError(error);
    }

    // content must correspond to the specified resource
    // Build the resource Json, input content format must be the expected by the
    // resource
    const auto formatResult = m_inFormat[item.m_format](content);
    if (std::holds_alternative<base::Error>(formatResult))
    {
        return base::Error {fmt::format("JSON object could not be created from '{} {}': {}",
                                        Resource::formatToStr(item.m_format),
                                        item.m_name.fullName(),
                                        std::get<base::Error>(formatResult).message)};
    }

    const auto& contentJson = std::get<json::Json>(formatResult);
    const auto contentNameStr = contentJson.getString("/name");
    if (!contentNameStr)
    {
        return base::Error {"Field 'name' is missing in content"};
    }

    base::Name contentName;
    try
    {
        contentName = base::Name(contentNameStr.value());
    }
    // Invalid content name
    catch (const std::exception& e)
    {
        return base::Error {fmt::format("Invalid content name '{}': {}", contentNameStr.value(), e.what())};
    }

    // Assert content name is the same as the resource name
    if (contentName != item.m_name)
    {
        return base::Error {fmt::format("Invalid content name '{}' of '{}' for type '{}'",
                                        contentNameStr.value(),
                                        item.m_name.fullName(),
                                        Resource::typeToStr(item.m_type))};
    }

    // Validate the content if needed
    if (item.m_validation)
    {
        const auto validationError = validate(item, namespaceId, contentJson);

        if (validationError)
        {
            return base::Error {fmt::format("An error occurred while trying to validate '{}': {}",
                                            contentNameStr.value(),
                                            validationError.value().message)};
        }
    }

    // All pre-conditions are met, update the content in the store
    const auto storeError =
        store::utils::update(m_store, item.m_name, Resource::formatToStr(item.m_format), contentJson, content);
    if (storeError)
    {
        return base::Error {fmt::format(
            "Content '{}' could not be updated in store: {}", contentNameStr.value(), storeError.value().message)};
    }

    return base::noError();
    ;
}

base::RespOrError<store::Doc> Catalog::getDoc(const Resource& resource) const
{
    const auto storeResult = store::utils::get(m_store, resource.m_name, true);
    if (std::holds_alternative<base::Error>(storeResult))
    {
        return base::Error {std::get<base::Error>(storeResult).message};
    }

    const auto& content = std::get<json::Json>(storeResult);

    return content;
}

base::RespOrError<store::Col> Catalog::getCol(const Resource& resource, const std::string& namespaceId) const
{
    auto result = m_store->readCol(resource.m_name, store::NamespaceId {namespaceId});
    if (base::isError(result))
    {
        return base::getError(result);
    }

    auto col = base::getResponse<store::Col>(result);
    return col;
}

base::RespOrError<std::string> Catalog::getResource(const Resource& resource, const std::string& namespaceId) const
{
    using Type = ::com::wazuh::api::engine::catalog::ResourceType;
    using Format = ::com::wazuh::api::engine::catalog::ResourceFormat;

    const auto formatContent = [outFormat = m_outFormat, format = resource.m_format, name = resource.m_name](
                                   const json::Json& content) -> base::RespOrError<std::string>
    {
        const auto formatterIt = outFormat.find(format);
        if (formatterIt == outFormat.end())
        {
            return base::Error {fmt::format("Formatter was not found for format '{}'", Resource::formatToStr(format))};
        }

        const auto formatResult = formatterIt->second(content);
        if (std::holds_alternative<base::Error>(formatResult))
        {
            return base::Error {fmt::format("JSON object could not be created from '{} {}': {}",
                                            Resource::formatToStr(format),
                                            name.fullName(),
                                            std::get<base::Error>(formatResult).message)};
        }

        return std::get<std::string>(formatResult);
    };

    // Call appropriate method depending on the resource type
    // Collection
    if (Resource::Type::collection == resource.m_type)
    {
        // Concatenate all the collections
        store::Col mergedCol;
        auto colResult = getCol(resource, namespaceId);
        if (base::isError(colResult))
        {
            return base::getError(colResult);
        }
        auto col = base::getResponse<store::Col>(std::move(colResult));
        mergedCol.insert(mergedCol.end(), std::make_move_iterator(col.begin()), std::make_move_iterator(col.end()));

        json::Json content;
        content.setArray();
        for (const auto& item : mergedCol)
        {
            content.appendString(item.fullName());
        }

        return formatContent(content);
    }

    // Check if resource exist in the namespace requested
    auto error = checkResourceInNamespace(resource, namespaceId, "get");
    if (base::isError(error))
    {
        return base::getError(error);
    }

    // Get document
    auto docResult = getDoc(resource);
    if (base::isError(docResult))
    {
        return base::getError(docResult);
    }

    auto doc = base::getResponse<store::Doc>(docResult);
    if (doc.exists("/original"))
    {
        auto original = doc.getJson("/json");
        if (original)
        {
            return formatContent(std::move(original.value()));
        }

        return base::Error {"Could not get the original content from the store"};
    }

    // TODO: this is a workaround so tests pass. Update tests!!!
    return formatContent(std::move(doc));
}

base::OptError Catalog::delDoc(const Resource& resource)
{
    return m_store->deleteDoc(resource.m_name);
}

base::OptError Catalog::delCol(const Resource& resource, const std::string& namespaceId)
{
    return m_store->deleteCol(resource.m_name, store::NamespaceId {namespaceId});
}

base::OptError Catalog::deleteResource(const Resource& resource, const std::string& namespaceId)
{
    // Agregate all errors
    if (Resource::Type::collection == resource.m_type)
    {
        base::Error error;
        const auto delColError = delCol(resource, namespaceId);
        if (delColError)
        {
            error.message += fmt::format(
                "Could not delete collection '{}': {}\n", resource.m_name.fullName(), delColError.value().message);
        }

        if (!error.message.empty())
        {
            return error;
        }
        return base::noError();
    }

    // Check if resource exist in the namespace requested
    auto error = checkResourceInNamespace(resource, namespaceId, "delete");
    if (base::isError(error))
    {
        return base::getError(error);
    }

    // Delete document
    return delDoc(resource);
}

base::OptError Catalog::validate(const Resource& item, const std::string& namespaceId, const json::Json& content) const
{
    // Assert resource type is Asset, Policy or Integration
    if (Resource::Type::decoder != item.m_type && Resource::Type::rule != item.m_type
        && Resource::Type::filter != item.m_type && Resource::Type::output != item.m_type
        && Resource::Type::integration != item.m_type)
    {
        return base::Error {fmt::format("Invalid resource type '{}'", Resource::typeToStr(item.m_type))};
    }

    // Builder validator
    base::OptError validationError;
    if (item.m_type == Resource::Type::decoder || item.m_type == Resource::Type::rule
        || item.m_type == Resource::Type::filter || item.m_type == Resource::Type::output)
    {
        validationError = m_validator->validateAsset(content);
    }
    else if (item.m_type == Resource::Type::integration)
    {
        if (namespaceId.empty())
        {
            return base::Error {
                fmt::format("Missing /namespaceid parameter for type '{}'", Resource::typeToStr(item.m_type))};
        }
        validationError = m_validator->validateIntegration(content, namespaceId);
    }
    else
    {
        return base::Error {fmt::format("Validator not found for type '{}'", Resource::typeToStr(item.m_type))};
    }

    if (validationError)
    {
        return base::Error {validationError.value().message};
    }

    return base::noError();
    ;
}

base::OptError
Catalog::validateResource(const Resource& item, const std::string& namespaceId, const std::string& content) const
{
    // Assert resource is asset, policy or integration
    if (Resource::Type::decoder != item.m_type && Resource::Type::rule != item.m_type
        && Resource::Type::filter != item.m_type && Resource::Type::output != item.m_type
        && Resource::Type::integration != item.m_type)
    {
        return base::Error {
            fmt::format("Invalid resource type '{}' for VALIDATE operation", Resource::typeToStr(item.m_type))};
    }

    // Build the content json
    const auto formatterIt = m_inFormat.find(item.m_format);
    if (formatterIt == m_inFormat.end())
    {
        return base::Error {
            fmt::format("Formatter was not found for format '{}'", Resource::formatToStr(item.m_format))};
    }

    const auto contentJson = formatterIt->second(content);
    if (std::holds_alternative<base::Error>(contentJson))
    {
        return base::Error {
            fmt::format("Content could not be parsed to json: {}", std::get<base::Error>(contentJson).message)};
    }

    // Validate the content
    const auto validationError = validate(item, namespaceId, std::get<json::Json>(contentJson));

    if (validationError)
    {
        return base::Error {validationError.value().message};
    }

    return base::noError();
    ;
}

} // namespace api::catalog
