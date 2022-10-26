#include "api/catalog/commands.hpp"

#include <json/json.hpp>

namespace api::catalog::cmds
{

api::CommandFn postResourceCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
        {
            // Check json params
            auto formatOpt = params.getString("/format");
            if (!formatOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [format] string parameter"};
            }
            auto format = catalog::Resource::strToFormat(formatOpt.value().c_str());
            if (format == catalog::Resource::Format::ERROR_FORMAT)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Format not supported"};
            }

            auto contentOpt = params.getString("/content");
            if (!contentOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [content] string parameter"};
            }

            auto nameOpt = params.getString("/name");
            if (!nameOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [name] string parameter"};
            }
            base::Name name;
            try
            {
                name = base::Name {nameOpt.value()};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("Invalid [name] parameter, {}", e.what())};
            }

            // Build target resource
            catalog::Resource targetResource;
            try
            {
                targetResource = catalog::Resource {name, format};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, e.what()};
            }

            auto error = catalog->postResource(targetResource, contentOpt.value());
            if (error)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
            }

            return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
        };
}

api::CommandFn getResourceCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
        {
            // Check json params
            auto nameOpt = params.getString("/name");
            if (!nameOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [name] string parameter"};
            }
            base::Name name;
            try
            {
                name = base::Name {nameOpt.value()};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("Invalid [name] parameter, {}", e.what())};
            }

            auto formatOpt = params.getString("/format");
            if (!formatOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [format] string parameter"};
            }
            auto format = catalog::Resource::strToFormat(formatOpt.value().c_str());
            if (format == catalog::Resource::Format::ERROR_FORMAT)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Format not supported"};
            }

            // Build target resource
            catalog::Resource targetResource;
            try
            {
                targetResource = catalog::Resource {name, format};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, e.what()};
            }

            auto result = catalog->getResource(targetResource);
            if (std::holds_alternative<base::Error>(result))
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, std::get<base::Error>(result).message};
            }

            json::Json data;
            data.setObject();
            data.setString(std::get<std::string>(result), "/content");

            return api::WazuhResponse {std::move(data), 200, "OK"};
        };
}

api::CommandFn putResourceCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
        {
            // Check json params
            auto nameOpt = params.getString("/name");
            if (!nameOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [name] string parameter"};
            }
            base::Name name;
            try
            {
                name = base::Name {nameOpt.value()};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("Invalid [name] parameter, {}", e.what())};
            }

            auto formatOpt = params.getString("/format");
            if (!formatOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [format] string parameter"};
            }
            auto format = catalog::Resource::strToFormat(formatOpt.value().c_str());
            if (format == catalog::Resource::Format::ERROR_FORMAT)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Format not supported"};
            }

            auto contentOpt = params.getString("/content");
            if (!contentOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [content] string parameter"};
            }

            // Build target resource
            catalog::Resource targetResource;
            try
            {
                targetResource = catalog::Resource {name, format};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, e.what()};
            }

            auto error = catalog->putResource(targetResource, contentOpt.value());
            if (error)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
            }

            return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
        };
}

api::CommandFn deleteResourceCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
        {
            // Check json params
            auto nameOpt = params.getString("/name");
            if (!nameOpt)
            {
                return api::WazuhResponse {
                    json::Json {"{}"}, 400, "Missing [name] string parameter"};
            }
            base::Name name;
            try
            {
                name = base::Name {nameOpt.value()};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {
                    json::Json {"{}"},
                    400,
                    fmt::format("Invalid [name] parameter, {}", e.what())};
            }

            // Build target resource
            catalog::Resource targetResource;
            try
            {
                // TODO: format is not used in deleteResource
                targetResource =
                    catalog::Resource {name, catalog::Resource::Format::JSON};
            }
            catch (const std::exception& e)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, e.what()};
            }

            auto error = catalog->deleteResource(targetResource);
            if (error)
            {
                return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
            }

            return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
        };
}

api::CommandFn validateResourceCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse {
        // Check json params
        auto nameOpt = params.getString("/name");
        if (!nameOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] string parameter"};
        }
        base::Name name;
        try
        {
            name = base::Name {nameOpt.value()};
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {
                json::Json {"{}"},
                400,
                fmt::format("Invalid [name] parameter, {}", e.what())};
        }

        auto formatOpt = params.getString("/format");
        if (!formatOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [format] string parameter"};
        }
        auto format = catalog::Resource::strToFormat(formatOpt.value().c_str());
        if (format == catalog::Resource::Format::ERROR_FORMAT)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, "Format not supported"};
        }

        auto contentOpt = params.getString("/content");
        if (!contentOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [content] string parameter"};
        }

        // Build target resource
        catalog::Resource targetResource;
        try
        {
            targetResource = catalog::Resource {name, format};
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, e.what()};
        }

        auto error = catalog->validateResource(targetResource, contentOpt.value());
        if (error)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

void registerAllCmds(std::shared_ptr<Catalog> catalog,
                     std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("post_catalog", postResourceCmd(catalog));
        registry->registerCommand("get_catalog", getResourceCmd(catalog));
        registry->registerCommand("put_catalog", putResourceCmd(catalog));
        registry->registerCommand("delete_catalog", deleteResourceCmd(catalog));
        registry->registerCommand("validate_catalog", validateResourceCmd(catalog));
    }
    catch (const std::exception& e)
    {
        std::throw_with_nested(std::runtime_error(fmt::format(
            "Engine API commands: An error while registering the commands: {}",
            e.what())));
    }
}
} // namespace api::catalog::cmds
