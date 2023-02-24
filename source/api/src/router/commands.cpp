#include <api/adapter.hpp>
#include <api/router/commands.hpp>

#include <eMessages/router.pb.h>

namespace api::router::cmds
{
// Using the engine protobuffer namespace
namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;

api::Handler routeGet(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RouteGet_Request;
        using ResponseType = eRouter::RouteGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        // Execute the command
        const auto& entry = router->getEntry(eRequest.name());
        if (!entry.has_value())
        {
            return ::api::adapter::genericError<ResponseType>("Route not found");
        }

        // Build the response
        const auto& [name, priority, filterName, envName] = entry.value();
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.mutable_rute()->set_name(name);
        eResponse.mutable_rute()->set_filter(filterName);
        eResponse.mutable_rute()->set_policy(envName);
        eResponse.mutable_rute()->set_priority(priority);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routePost(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RoutePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg = !eRequest.has_route()              ? std::make_optional("Missing /route")
                              : !eRequest.route().has_name()     ? std::make_optional("Missing /route/name")
                              : !eRequest.route().has_filter()   ? std::make_optional("Missing /route/filter")
                              : !eRequest.route().has_policy()   ? std::make_optional("Missing /route/policy")
                              : !eRequest.route().has_priority() ? std::make_optional("Missing /route/priority")
                                                                 : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        const auto& eEntry = eRequest.route();
        auto error = router->addRoute(eEntry.name(), eEntry.priority(), eEntry.filter(), eEntry.policy());

        // Build the response
        ResponseType eResponse;
        eResponse.set_status(error.has_value() ? eEngine::ReturnStatus::ERROR : eEngine::ReturnStatus::OK);
        if (error.has_value())
        {
            eResponse.set_error(error.value().message);
        }

        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routePatch(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RoutePatch_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg = !eRequest.has_route()              ? std::make_optional("Missing /route")
                              : !eRequest.route().has_name()     ? std::make_optional("Missing /route/name")
                              : !eRequest.route().has_priority() ? std::make_optional("Missing /route/priority")
                                                                 : std::nullopt;
        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        auto eEntry = eRequest.route();
        auto error = router->changeRoutePriority(eEntry.name(), eEntry.priority());

        // Build the response
        ResponseType eResponse;
        eResponse.set_status(error.has_value() ? eEngine::ReturnStatus::ERROR : eEngine::ReturnStatus::OK);
        if (error.has_value())
        {
            eResponse.set_error(error.value().message);
        }

        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routeDelete(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RouteDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_name())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /name");
        }

        router->removeRoute(eRequest.name());
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler tableGet(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::TableGet_Request;
        using ResponseType = eRouter::TableGet_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Build the response
        ResponseType eResponse;
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
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler queuePost(std::shared_ptr<::router::Router> router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::QueuePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        if (!eRequest.has_ossec_event())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /event");
        }

        auto err = router->enqueueOssecEvent(eRequest.ossec_event());
        if (err.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

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

} // namespace api::router::cmds
