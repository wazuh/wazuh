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
namespace eEngine = ::com::wazuh::api::engine;

void registerCommands(std::shared_ptr<::router::Router> router, std::shared_ptr<api::Registry> registry)
{
    // Commands to manage routes
    registry->registerCommand("router.route/get", routeGet(router));
    registry->registerCommand("router.route/post", routePost(router));
    registry->registerCommand("router.route/patch", routePatch(router));
    registry->registerCommand("router.route/delete", routeDelete(router));

    // Commands to manage the routes table
    registry->registerCommand("router.table/get", tableGet(router));

    // Commands to manage the queue of events
    registry->registerCommand("router.queue/post", queuePost(router));
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
        const auto resJson = eMessage::eMessageToJson<eRouter::RouteGet_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn routePost(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::RoutePost_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eRouter::RoutePost_Request>(result);
            // Valida the request
            errorMsg = !eRequest.has_route()              ? std::make_optional("Missing /route")
                       : !eRequest.route().has_name()     ? std::make_optional("Missing /route/name")
                       : !eRequest.route().has_filter()   ? std::make_optional("Missing /route/filter")
                       : !eRequest.route().has_policy()   ? std::make_optional("Missing /route/policy")
                       : !eRequest.route().has_priority() ? std::make_optional("Missing /route/priority")
                                                          : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto eEntry = eRequest.route();
                auto error = router->addRoute(eEntry.name(), eEntry.priority(), eEntry.filter(), eEntry.policy());
                errorMsg = error.has_value() ? std::make_optional(error.value().message) : std::nullopt;
            }

            if (errorMsg.has_value())
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                eResponse.set_error(errorMsg.value());
            }
            else
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
            }
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn routePatch(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::RoutePatch_Request>(params);

        std::optional<std::string> errorMsg = std::nullopt;

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eRouter::RoutePatch_Request>(result);
            // Valida the request
            errorMsg = !eRequest.has_route()              ? std::make_optional("Missing /route")
                       : !eRequest.route().has_name()     ? std::make_optional("Missing /route/name")
                       : !eRequest.route().has_priority() ? std::make_optional("Missing /route/priority")
                                                          : std::nullopt;

            if (!errorMsg.has_value())
            {
                auto eEntry = eRequest.route();
                auto error = router->changeRoutePriority(eEntry.name(), eEntry.priority());
                errorMsg = error.has_value() ? std::make_optional(error.value().message) : std::nullopt;
            }

            if (errorMsg.has_value())
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                eResponse.set_error(errorMsg.value());
            }
            else
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
            }
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn routeDelete(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::RouteDelete_Request>(params);

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eRouter::RouteDelete_Request>(result);
            // Valida the request
            if (eRequest.has_name())
            {
                router->removeRoute(eRequest.name());
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
            }
            else
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                eResponse.set_error("Missing /name");
            }
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn tableGet(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eRouter::TableGet_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::TableGet_Request>(params);

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            auto eTable = eResponse.mutable_table(); // Create the empty table
            for (const auto& [name, priority, filter, policy] : router->getRouteTable())
            {
                auto eEntry = eRouter::Entry();
                eEntry.mutable_name()->assign(name);
                eEntry.mutable_filter()->assign(filter);
                eEntry.mutable_policy()->assign(policy);
                eEntry.set_priority(priority);
                eTable->Add(std::move(eEntry));
            }
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eRouter::TableGet_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

api::CommandFn queuePost(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        eEngine::GenericStatus_Response eResponse;

        // Adapt the request to the engine, the request is validated by the server
        const auto params = wRequest.getParameters().value().str();
        const auto result = eMessage::eMessageFromJson<eRouter::QueuePost_Request>(params);

        if (std::holds_alternative<base::Error>(result))
        {
            eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
            eResponse.set_error(std::get<base::Error>(result).message);
        }
        else
        {
            const auto& eRequest = std::get<eRouter::QueuePost_Request>(result);
            // Valida the request
            if (eRequest.has_ossec_event())
            {
                auto err = router->enqueueOssecEvent(eRequest.ossec_event());
                if (err)
                {
                    eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                    eResponse.set_error(err.value().message);
                }
                else
                {
                    eResponse.set_status(com::wazuh::api::engine::ReturnStatus::OK);
                }
            }
            else
            {
                eResponse.set_status(com::wazuh::api::engine::ReturnStatus::ERROR);
                eResponse.set_error("Missing /ossec_event");
            }
        }

        // Adapt the response to wazuh api
        const auto resJson = eMessage::eMessageToJson<eEngine::GenericStatus_Response>(eResponse);
        if (std::holds_alternative<base::Error>(resJson))
        {
            const auto& error = std::get<base::Error>(resJson);
            return api::wpResponse::internalError(error.message);
        }
        return api::wpResponse {json::Json {std::get<std::string>(resJson).c_str()}};
    };
}

} // namespace api::router::cmds
