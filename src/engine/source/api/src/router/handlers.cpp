#include <api/adapter.hpp>
#include <api/router/handlers.hpp>

#include <eMessages/router.pb.h>

namespace api::router::handlers
{
// Using the engine protobuffer namespace
namespace eRouter = ::com::wazuh::api::engine::router;
namespace eEngine = ::com::wazuh::api::engine;


namespace {

/**
 * @brief Compare the hash of the policy stored in the router with the hash of the policy stored in the store and
 * return the status of the comparison in human readable format:
 *
 * - OUTDATED: The policy stored in the router is outdated. The policy stored in the store differs from the policy
 * stored
 * - UPDATED: The policy stored in the router is updated. The policy stored in the store is the same as the policy
 * - ERROR: An error occurred while comparing the hashes, The policy stored in the store is inaccesible
 *
 * @tparam ResponseType
 * @param policyApi
 * @param policyName
 * @return std::string
 */
std::string getHashStatus(const std::weak_ptr<api::policy::IPolicy>& policyApi,
                                                   const std::string& policyName,
                                                   const std::string& hash)
{
    auto policyApiPtr = policyApi.lock();
    if (!policyApiPtr)
    {
        return "Error: Policy API is not available";
    }

    base::Name name;
    try {
        name = base::Name(policyName);
    } catch (const std::exception& e) {
        return "Error: Invalid policy name";
    }

    const auto policyHash = policyApiPtr->getHash(name);
    if (base::isError(policyHash))
    {
        return std::string("Error: ") + base::getError(policyHash).message;
    }

    const auto hashStored = base::getResponse<std::string>(policyHash);
    if (hashStored != hash)
    {
        return std::string("OUTDATED");
    }

    return std::string("UPDATED");
}
}

api::Handler routeGet(std::shared_ptr<::router::Router> router, std::weak_ptr<api::policy::IPolicy> policyApi)
{
    return [router, policyApi](const api::wpRequest& wRequest) -> api::wpResponse
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

        // Get policy hash from api policy
        if (!entry.has_value())
        {
            return ::api::adapter::genericError<ResponseType>("Route not found");
        }

        // Build the response
        const auto& [name, priority, filterName, envName, hash] = entry.value();
        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.mutable_route()->set_name(name);
        eResponse.mutable_route()->set_filter(filterName);
        eResponse.mutable_route()->set_policy(envName);
        eResponse.mutable_route()->set_priority(static_cast<int32_t>(priority));

        auto hashStatus = getHashStatus(policyApi, envName, hash); // Get policy hash from the store
        eResponse.mutable_route()->set_policy_sync(hashStatus);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler routePost(std::shared_ptr<::router::Router> router)
{
    return [router](const api::wpRequest& wRequest) -> api::wpResponse
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

        if (::router::USER_ROUTE_MAXIMUM_PRIORITY > eRequest.route().priority())
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Route priority ({}) must be greater than or equal to {}",
                            eRequest.route().priority(),
                            ::router::USER_ROUTE_MAXIMUM_PRIORITY));
        }

        const auto& eEntry = eRequest.route();
        auto error = router->addRoute(eEntry.name(), eEntry.priority(), std::make_pair(eEntry.filter(), std::nullopt), eEntry.policy());

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
    return [router](const api::wpRequest& wRequest) -> api::wpResponse
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

        if (::router::USER_ROUTE_MAXIMUM_PRIORITY > eRequest.route().priority())
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Route priority ({}) must be greater than or equal to {}",
                            eRequest.route().priority(),
                            ::router::USER_ROUTE_MAXIMUM_PRIORITY));
        }

        if (::router::USER_ROUTE_MINIMUM_PRIORITY < eRequest.route().priority())
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Route priority ({}) must be less than or equal to {}",
                            eRequest.route().priority(),
                            ::router::USER_ROUTE_MINIMUM_PRIORITY));
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
    return [router](const api::wpRequest& wRequest) -> api::wpResponse
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

api::Handler tableGet(std::shared_ptr<::router::Router> router, std::weak_ptr<api::policy::IPolicy> policyApi)
{
    return [router, policyApi](const api::wpRequest& wRequest) -> api::wpResponse
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
        for (const auto& [name, priority, filter, policy, hash] : router->getRouteTable())
        {
            auto eEntry = eRouter::Entry();
            eEntry.mutable_name()->assign(name);
            eEntry.mutable_filter()->assign(filter);
            eEntry.mutable_policy()->assign(policy);
            eEntry.set_priority(static_cast<int32_t>(priority));

            auto hashStatus = getHashStatus(policyApi, policy, hash); // Get policy hash from the store
            eEntry.set_policy_sync(hashStatus);

            eTable->Add(std::move(eEntry));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        // Adapt the response to wazuh api
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler queuePost(std::shared_ptr<::router::Router> router)
{
    return [router](const api::wpRequest& wRequest) -> api::wpResponse
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
        if (!eRequest.has_wazuh_event())
        {
            return ::api::adapter::genericError<ResponseType>("Missing /event");
        }

        auto err = router->enqueueWazuhEvent(eRequest.wazuh_event());
        if (err.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(err.value().message);
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

void registerHandlers(std::shared_ptr<::router::Router> router, std::shared_ptr<api::Api> api, std::weak_ptr<api::policy::IPolicy> policyApi)
{
    // Commands to manage routes
    const bool ok = api->registerHandler("router.route/get", routeGet(router, policyApi))
                    && api->registerHandler("router.route/post", routePost(router))
                    && api->registerHandler("router.route/patch", routePatch(router))
                    && api->registerHandler("router.route/delete", routeDelete(router)) &&
                    // Commands to manage the routes table
                    api->registerHandler("router.table/get", tableGet(router, policyApi)) &&
                    // Commands to manage the queue of events
                    api->registerHandler("router.queue/post", queuePost(router));

    if (!ok)
    {
        throw std::runtime_error("Failed to register router handlers");
    }
}

} // namespace api::router::handlers
