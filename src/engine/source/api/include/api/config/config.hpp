#ifndef _API_CONFIG_CMDS_HPP
#define _API_CONFIG_CMDS_HPP

#include <memory>
#include <optional>

#include <api/registry.hpp>
#include <conf/iconf.hpp>
#include <json/json.hpp>

#include <api/adapter.hpp>
#include <eMessages/config.pb.h>

namespace api::config::cmds
{
template<typename ConfDriver>
using ConfHandler = std::shared_ptr<conf::IConf<ConfDriver>>;

namespace eConfig = ::com::wazuh::api::engine::config;
namespace eEngine = ::com::wazuh::api::engine;

/* Runtime endpoint */
template<typename ConfDriver>
api::Handler runtimeGet(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eConfig::RuntimeGet_Request;
        using ResponseType = eConfig::RuntimeGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& request = std::get<RequestType>(res);
        ResponseType response;
        // Execute the command
        try
        {
            auto content = request.has_name() ? confHandler->template get<std::string>(request.name())
                                              : confHandler->getConfiguration();
            response.set_content(std::move(content));
            response.set_status(eEngine::ReturnStatus::OK);
        }
        catch (const std::exception& e)
        {
            response.set_error(e.what());
            response.set_status(eEngine::ReturnStatus::ERROR);
        }

        return ::api::adapter::toWazuhResponse<ResponseType>(response);
    };
}

template<typename ConfDriver>
api::Handler runtimePut(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eConfig::RuntimePut_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& request = std::get<RequestType>(res);
        // Validate the engine request
        std::optional<std::string> error = !request.has_name()    ? std::make_optional("Missing /name")
                                           : !request.has_content() ? std::make_optional("Missing /value")
                                                                  : std::nullopt;
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(error.value());
        }

        ResponseType response;
        try
        {
            confHandler->put(request.name(), request.content());
            response.set_status(eEngine::ReturnStatus::OK);
        }
        catch (const std::exception& e)
        {
            response.set_error(e.what());
            response.set_status(eEngine::ReturnStatus::ERROR);
        }

        return ::api::adapter::toWazuhResponse<ResponseType>(response);
    };
}

template<typename ConfDriver>
api::Handler runtimeSave(ConfHandler<ConfDriver> confHandler)
{
    return [confHandler](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eConfig::RuntimeSave_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& request = std::get<RequestType>(res);
        ResponseType response;

        try
        {
            if (request.has_path())
            {
                confHandler->saveConfiguration(request.path());
            }
            else
            {
                confHandler->saveConfiguration();
            }
            response.set_status(eEngine::ReturnStatus::OK);
        }
        catch (const std::exception& e)
        {
            response.set_error(e.what());
            response.set_status(eEngine::ReturnStatus::ERROR);
        }

        return ::api::adapter::toWazuhResponse<ResponseType>(response);
    };
}

template<typename ConfDriver>
bool registerCommands(std::shared_ptr<api::Registry> registry, ConfHandler<ConfDriver> confHandler)
{
    return registry->registerCommand("config.runtime/get", runtimeGet(confHandler))
           && registry->registerCommand("config.runtime/put", runtimePut(confHandler))
           && registry->registerCommand("config.runtime/save", runtimeSave(confHandler));
}
} // namespace api::config::cmds

#endif // _API_CONFIG_CMDS_HPP
