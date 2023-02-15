#ifndef _API_CONFIG_CMDS_HPP
#define _API_CONFIG_CMDS_HPP

#include <memory>

#include <api/registry.hpp>
#include <conf/iconf.hpp>
#include <json/json.hpp>

namespace api::config::cmds
{
template<typename ConfDriver>
using ConfHandler = std::shared_ptr<conf::IConf<ConfDriver>>;

template<typename ConfDriver>
api::CommandFn configGetCmd(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        try
        {
            auto name = params.getString("/name");
            if (!name)
            {
                auto confStr = confHandler->getConfiguration();
                json::Json jValue;
                jValue.setString(confStr, "/content");
                return api::wpResponse(jValue, 0, "");
            }

            auto value = confHandler->template get<std::string>(name.value());
            json::Json jValue;
            jValue.setString(value, "/content");
            return api::wpResponse(jValue, 0, "");
        }
        catch (const std::exception& e)
        {
            return api::wpResponse(e.what());
        }
    };
}

template<typename ConfDriver>
api::CommandFn configSaveCmd(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        try
        {
            auto path = params.getString("/path");
            if (path)
            {
                confHandler->saveConfiguration(path.value());
            }
            else
            {
                confHandler->saveConfiguration();
            }
        }
        catch (const std::exception& e)
        {
            return api::wpResponse(e.what());
        }

        return api::wpResponse("OK");
    };
}

template<typename ConfDriver>
api::CommandFn configPutCmd(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest request) -> api::wpResponse
    {
        const auto params = request.getParameters().value(); // The request is validated by the server

        try
        {
            auto name = params.getString("/name");
            auto value = params.getString("/value");
            if (!name || !value)
            {
                return api::wpResponse("Missing parameters");
            }

            confHandler->put(name.value(), value.value());
            return api::wpResponse("OK");
        }
        catch (const std::exception& e)
        {
            return api::wpResponse(e.what());
        }
    };
}

template<typename ConfDriver>
bool registerCommands(std::shared_ptr<api::Registry> registry, ConfHandler<ConfDriver> confHandler)
{
    return registry->registerCommand("config_get", configGetCmd(confHandler))
           && registry->registerCommand("config_save", configSaveCmd(confHandler))
           && registry->registerCommand("config_put", configPutCmd(confHandler));
}
} // namespace api::config::cmds

#endif // _API_CONFIG_CMDS_HPP
