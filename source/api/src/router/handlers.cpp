#include <utility>

#include <api/adapter.hpp>
#include <eMessages/router.pb.h>

#include <api/router/handlers.hpp>
#include <router/iapi.hpp>

namespace api::router::handlers
{
// Using the engine protobuffer namespace
namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;

using api::adapter::genericError;
using api::adapter::genericSuccess;

template<typename RequestType>
using RouterAndRequest = std::pair<std::shared_ptr<::router::IRouterAPI>, RequestType>; ///< Router and request pair

namespace
{

/**
 * @brief Get the base::Name from a string or an error response if the name is invalid
 *
 * @tparam ResponseType
 * @param name to convert
 * @param field fild to get the error response
 * @return std::variant<api::wpResponse, base::Name>
 */
template<typename ResponseType>
std::variant<api::wpResponse, base::Name> getName(const std::string& name, const std::string& field)
{
    try
    {
        return base::Name(name);
    }
    catch (const std::exception& e)
    {
        return genericError<ResponseType>("Invalid " + field + " name: " + e.what());
    }
}

/**
 * @brief Get the request from the wazuh request and validate the router
 *
 * @tparam RequestType
 * @tparam ResponseType
 * @param wRequest The wazuh request to convert
 * @param wRouter weak pointer to the router to validate
 * @return std::variant<api::wpResponse, RouterAndRequest<RequestType>>
 */
template<typename RequestType, typename ResponseType>
std::variant<api::wpResponse, RouterAndRequest<RequestType>>
getRequest(const api::wpRequest& wRequest, const std::weak_ptr<::router::IRouterAPI>& wRouter)
{
    auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
    // validate the request
    if (std::holds_alternative<api::wpResponse>(res))
    {
        return std::move(std::get<api::wpResponse>(res));
    }

    // validate the router
    auto router = wRouter.lock();
    if (!router)
    {
        return genericError<ResponseType>("Router is not available");
    }

    return std::make_pair(router, std::get<RequestType>(res));
}
} // namespace

eRouter::Entry eRouteEntryFromEntry(const ::router::prod::Entry& entry)
{
    eRouter::Entry eEntry;
    eEntry.set_name(entry.name());
    eEntry.set_filter(entry.filter().fullName());
    eEntry.set_policy(entry.policy().fullName());
    eEntry.set_priority(static_cast<uint32_t>(entry.priority()));
    if (entry.description().has_value())
    {
        eEntry.mutable_description()->assign(entry.description().value());
    }
    // TODO: set the status and sync
    eEntry.set_policy_sync(eRouter::Sync::SYNC_UNKNOWN);
    eEntry.set_entry_status(eRouter::State::STATE_UNKNOWN);
    eEntry.set_last_update(entry.lastUpdate());
    return eEntry;
}

api::Handler routePost(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RoutePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate the request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);

        // Check the route name
        if (!eRequest.has_route())
        {
            return genericError<ResponseType>("Missing /route");
        }

        auto policyName = getName<ResponseType>(eRequest.route().policy(), "policy");
        auto filterName = getName<ResponseType>(eRequest.route().filter(), "filter");
        if (std::holds_alternative<api::wpResponse>(policyName))
        {
            return std::move(std::get<api::wpResponse>(policyName));
        }
        if (std::holds_alternative<api::wpResponse>(filterName))
        {
            return std::move(std::get<api::wpResponse>(filterName));
        }

        // Add the route
        ::router::prod::EntryPost entryPost(eRequest.route().name(),
                                            std::get<base::Name>(policyName),
                                            std::get<base::Name>(filterName),
                                            eRequest.route().priority());
        if (eRequest.route().has_description() && !eRequest.route().description().empty())
        {
            entryPost.description(eRequest.route().description());
        }
        auto error = router->postEntry(entryPost);

        // Build the response
        if (error.has_value())
        {
            genericError<ResponseType>(error.value().message);
        }

        return genericSuccess<ResponseType>();
    };
}

api::Handler routeDelete(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RouteDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // If the request is not valid, return the error
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        // Validate the params request
        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);

        auto error = router->deleteEntry(eRequest.name());
        if (error.has_value())
        {
            return genericError<ResponseType>(error.value().message);
        }

        return genericSuccess<ResponseType>();
    };
}

api::Handler routeGet(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RouteGet_Request;
        using ResponseType = eRouter::RouteGet_Response;
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);

        // Execute the command
        const auto& getResult = router->getEntry(eRequest.name());

        if (base::isError(getResult))
        {
            return genericError<ResponseType>(base::getError(getResult).message);
        }

        // Build the response
        ResponseType eResponse;
        const auto& entry = base::getResponse(getResult);
        eResponse.mutable_route()->CopyFrom(eRouteEntryFromEntry(entry));

        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routeReload(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RouteReload_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);

        // Execute the command
        const auto& getResult = router->reloadEntry(eRequest.name());

        if (base::isError(getResult))
        {
            return genericError<ResponseType>(base::getError(getResult).message);
        }

        // Build the response
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routePatchPriority(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::RoutePatchPriority_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);

        // Execute the command
        const auto& getResult = router->changeEntryPriority(eRequest.name(), eRequest.priority());

        if (base::isError(getResult))
        {
            return genericError<ResponseType>(base::getError(getResult).message);
        }

        // Build the response
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler tableGet(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::TableGet_Request;
        using ResponseType = eRouter::TableGet_Response;
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);
        const auto entries = router->getEntries();

        // Build the response
        ResponseType eResponse;
        auto eTable = eResponse.mutable_table(); // Create the empty table
        for (const auto& entry : entries)
        {
            eTable->Add(eRouteEntryFromEntry(entry));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler queuePost(const std::weak_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eRouter::QueuePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = getRequest<RequestType, ResponseType>(wRequest, wRouter);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        auto& [router, eRequest] = std::get<RouterAndRequest<RequestType>>(res);
        const auto postRes = router->postStrEvent(eRequest.wazuh_event());

        if (postRes.has_value())
        {
            return genericError<ResponseType>(postRes.value().message);
        }
        return genericSuccess<ResponseType>();
    };
}

void registerHandlers(const std::weak_ptr<::router::IRouterAPI>& router, std::shared_ptr<api::Api> api)
{
    // Commands to manage routes
    const bool ok = api->registerHandler("router.route/post", routePost(router))
                    && api->registerHandler("router.route/delete", routeDelete(router))
                    && api->registerHandler("router.route/get", routeGet(router))
                    && api->registerHandler("router.route/reload", routeReload(router))
                    && api->registerHandler("router.route/patchPriority", routePatchPriority(router))
                    // Commands to manage the routes table
                    && api->registerHandler("router.table/get", tableGet(router))
                    // Commands to manage the queue of events
                    && api->registerHandler("router.queue/post", queuePost(router));

    if (!ok)
    {
        throw std::runtime_error("Failed to register router handlers");
    }
}

} // namespace api::router::handlers
