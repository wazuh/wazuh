#include <api/router/commands.hpp>

#include <eMessages/eMessage.h>
#include <eMessages/router.pb.h>

namespace
{

}
namespace api::router::cmds
{
// Using the engine protobuffer namespace
namespace eRouter = ::com::wazuh::api::engine::router;

void registerCommands(std::shared_ptr<::router::Router> router, std::shared_ptr<api::Registry> registry)
{
    // Command to manage a route
    registry->registerCommand("router.route/get", routeGet(router));
    registry->registerCommand("router.route/set", routeSet(router));
}

api::CommandFn routeGet(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eRouter::RouteGet_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::RouteGet_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;
        std::optional<::router::Router::Entry> entry = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            errorMsg = std::get<base::Error>(result).message;
        }
        else
        {
            const auto& eRequest = std::get<eRouter::RouteGet_Request>(result);
            if (eRequest.has_name())
            {
                entry = router->getEntry(eRequest.name());
            }
            else
            {
                errorMsg = "Missing name";
            }
        }

        if (errorMsg.has_value() || !entry.has_value())
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(errorMsg.value_or("Route not found"));
        }
        else
        {
            const auto& [name, priority, filterName, envName] = entry.value();
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
            eResponse.mutable_rute()->set_name(name);
            eResponse.mutable_rute()->set_filter(filterName);
            eResponse.mutable_rute()->set_policy(envName);
            eResponse.mutable_rute()->set_priority(priority);
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eRouter::RouteGet_Response>(eResponse, true);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}


api::CommandFn routeSet(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eRouter::RouteSet_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::RouteSet_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eRouter::RouteSet_Request>(result);
            // Valida the request
            errorMsg = !eRequest.has_route()              ? std::make_optional("Missing route")
                       : !eRequest.route().has_name()     ? std::make_optional("Missing route/name")
                       : !eRequest.route().has_filter()   ? std::make_optional("Missing route/filter")
                       : !eRequest.route().has_policy()   ? std::make_optional("Missing route/policy")
                       : !eRequest.route().has_priority() ? std::make_optional("Missing route/priority")
                                                          : std::nullopt;

            auto eEntry = eRequest.route();
            auto error = router->addRoute(eEntry.name(), eEntry.priority(), eEntry.filter(), eEntry.policy());
            if (error.has_value())
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                eResponse.set_error(error.value().message);
            }

        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eRouter::RouteSet_Response>(eResponse, true);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}
} // namespace api::router::cmds
