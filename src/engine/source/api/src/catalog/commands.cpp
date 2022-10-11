#include "api/catalog/commands.hpp"

#include <json/json.hpp>

namespace api::catalog::cmds
{
api::CommandFn getAssetCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
    {
        // Check json params
        if (!params.exists("/name"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] parameter"};
        }
        auto nameOpt = params.getString("/name");
        if (!nameOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [name] parameter, expected string"};
        }
        CatalogName name;
        try
        {
            name = CatalogName {nameOpt.value()};
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {json::Json {"{}"},
                                       400,
                                       "Invalid [name] parameter, expected string in "
                                       "format <type>.<name>.<version>"};
        }
        if (!params.exists("/format"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [format] parameter"};
        }
        auto formatOpt = params.getString("/format");
        if (!formatOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [format] parameter, expected string"};
        }

        // Get asset
        auto assetOpt = catalog->getAsset(name, stringToFormat(formatOpt.value()));
        if (std::holds_alternative<base::Error>(assetOpt))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, std::get<base::Error>(assetOpt).message};
        }
        auto data = json::Json {
            fmt::format("{{\"data\": {}}}", std::get<std::string>(assetOpt)).c_str()};
        return api::WazuhResponse {std::move(data), 200, "OK"};
    };
}

api::CommandFn postAssetCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
    {
        // Check json params
        if (!params.exists("/name"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] parameter"};
        }
        auto nameOpt = params.getString("/name");
        if (!nameOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [name] parameter, expected string"};
        }
        CatalogName name;
        try
        {
            name = CatalogName {nameOpt.value()};
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {json::Json {"{}"},
                                       400,
                                       "Invalid [name] parameter, expected string in "
                                       "format <type>.<name>.<version>"};
        }
        if (!params.exists("/format"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [format] parameter"};
        }
        auto formatOpt = params.getString("/format");
        if (!formatOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [format] parameter, expected string"};
        }
        if (!params.exists("/content"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [content] parameter"};
        }
        auto contentOpt = params.getString("/content");
        if (!contentOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [content] parameter, expected string"};
        }

        // Post asset
        auto error = catalog->addAsset(
            name, contentOpt.value(), stringToFormat(formatOpt.value()));
        if (error)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn deleteAssetCmd(std::shared_ptr<Catalog> catalog)
{
    return [catalog](const json::Json& params) -> api::WazuhResponse
    {
        // Check json params
        if (!params.exists("/name"))
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Missing [name] parameter"};
        }
        auto nameOpt = params.getString("/name");
        if (!nameOpt)
        {
            return api::WazuhResponse {
                json::Json {"{}"}, 400, "Invalid [name] parameter, expected string"};
        }
        CatalogName name;
        try
        {
            name = CatalogName {nameOpt.value()};
        }
        catch (const std::exception& e)
        {
            return api::WazuhResponse {json::Json {"{}"},
                                       400,
                                       "Invalid [name] parameter, expected string in "
                                       "format <type>.<name>.<version>"};
        }

        // Delete asset
        auto error = catalog->delAsset(name);
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
        registry->registerCommand("get_decoders", getAssetCmd(catalog));
        registry->registerCommand("post_decoders", postAssetCmd(catalog));
        registry->registerCommand("delete_decoders", deleteAssetCmd(catalog));
    }
    catch (...)
    {
        std::throw_with_nested(
            std::runtime_error("[cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace api::catalog::cmds
