#include "catalog/commands.hpp"

#include <json/json.hpp>

namespace catalog::cmds
{
api::CommandFn getAssetCmd(std::shared_ptr<catalog::Catalog> catalog)
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
        base::Name name;
        try
        {
            name = base::Name {nameOpt.value()};
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
        auto assetOpt =
            catalog->getAsset(name, catalog::stringToFormat(formatOpt.value()));
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

api::CommandFn postAssetCmd(std::shared_ptr<catalog::Catalog> catalog)
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
        base::Name name;
        try
        {
            name = base::Name {nameOpt.value()};
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
            name, contentOpt.value(), catalog::stringToFormat(formatOpt.value()));
        if (error)
        {
            return api::WazuhResponse {json::Json {"{}"}, 400, error.value().message};
        }

        return api::WazuhResponse {json::Json {"{}"}, 200, "OK"};
    };
}

api::CommandFn deleteAssetCmd(std::shared_ptr<catalog::Catalog> catalog)
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
        base::Name name;
        try
        {
            name = base::Name {nameOpt.value()};
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

void registerAllCmds(std::shared_ptr<catalog::Catalog> catalog,
                     std::shared_ptr<api::Registry> registry)
{
    try
    {
        registry->registerCommand("get_asset", getAssetCmd(catalog));
        registry->registerCommand("post_asset", postAssetCmd(catalog));
        registry->registerCommand("delete_asset", deleteAssetCmd(catalog));
    }
    catch (...)
    {
        std::throw_with_nested(std::runtime_error(
            "[catalog::cmds::registerAllCmds] Failed to register commands"));
    }
}
} // namespace catalog::cmds
