#include <utility>

#include <api/adapter/adapter.hpp>
#include <api/adapter/helpers.hpp>
#include <api/router/handlers.hpp>
#include <eMessages/router.pb.h>
#include <router/iapi.hpp>

namespace api::router::handlers
{
namespace eRouter = adapter::eEngine::router;
namespace eEngine = adapter::eEngine;
using namespace adapter::helpers;

namespace
{
/**
 * @brief   Return the current time in seconds since epoch
 * @return  Current time in seconds since epoch
 */
inline int64_t currentTime()
{
    auto startTime = std::chrono::system_clock::now();
    return std::chrono::duration_cast<std::chrono::seconds>(startTime.time_since_epoch()).count();
}

eRouter::Sync getHashSatus(const ::router::prod::Entry& entry,
                           const std::weak_ptr<api::policy::IPolicy>& wPolicyManager)
{
    auto policyManager = wPolicyManager.lock();
    if (!policyManager)
    {
        return eRouter::Sync::SYNC_UNKNOWN;
    }

    auto resPolicy = policyManager->getHash(entry.policy());
    if (base::isError(resPolicy))
    {
        return eRouter::Sync::ERROR;
    }

    return base::getResponse(resPolicy) == entry.hash() ? eRouter::Sync::UPDATED : eRouter::Sync::OUTDATED;
}

/**
 * @brief Convert a router entry to a api entry
 *
 * @param entry to convert
 * @param wPolicyManager for hash comparison
 * @return eRouter::Entry
 */
eRouter::Entry eRouteEntryFromEntry(const ::router::prod::Entry& entry,
                                    const std::weak_ptr<api::policy::IPolicy>& wPolicyManager)
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

    eRouter::State state = ::router::env::State::ENABLED == entry.status()    ? eRouter::State::ENABLED
                           : ::router::env::State::DISABLED == entry.status() ? eRouter::State::DISABLED
                                                                              : eRouter::State::STATE_UNKNOWN;

    eEntry.set_policy_sync(getHashSatus(entry, wPolicyManager));
    eEntry.set_entry_status(state);

    // Calculate the uptime
    if (state == eRouter::State::DISABLED)
    {
        eEntry.set_uptime(entry.lastUpdate());
    }
    else
    {
        eEntry.set_uptime(static_cast<uint32_t>(currentTime() - entry.lastUpdate()));
    }

    return eEntry;
}
} // namespace

adapter::RouteHandler routePost(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::RoutePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto protoRoute = tryGetProperty<ResponseType, eRouter::EntryPost>(
            protoReq.has_route(), [&protoReq]() { return protoReq.route(); }, "route", "route");
        if (adapter::isError(protoRoute))
        {
            res = adapter::getErrorResp(protoRoute);
            return;
        }

        auto policyName = tryGetProperty<ResponseType, base::Name>(
            true, [&protoRoute]() { return base::Name(adapter::getRes(protoRoute).policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        auto filterName = tryGetProperty<ResponseType, base::Name>(
            true, [&protoRoute]() { return base::Name(adapter::getRes(protoRoute).filter()); }, "filter", "name");
        if (adapter::isError(filterName))
        {
            res = adapter::getErrorResp(filterName);
            return;
        }

        // Add the route
        ::router::prod::EntryPost entryPost(protoReq.route().name(),
                                            adapter::getRes(policyName),
                                            adapter::getRes(filterName),
                                            protoReq.route().priority());

        if (protoReq.route().has_description() && !protoReq.route().description().empty())
        {
            entryPost.description(protoReq.route().description());
        }

        auto error = router->postEntry(entryPost);
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler routeDelete(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::RouteDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto name = tryGetProperty<ResponseType, base::Name>(
            true, [&protoReq]() { return base::Name(protoReq.name()); }, "name", "name");
        if (adapter::isError(name))
        {
            res = adapter::getErrorResp(name);
            return;
        }

        // Delete the route
        auto error = router->deleteEntry(adapter::getRes(name));
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(error.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler routeGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<api::policy::IPolicy>& policy)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router),
            wPolicyManager = std::weak_ptr<api::policy::IPolicy>(policy)](const auto& req, auto& res)
    {
        using RequestType = eRouter::RouteGet_Request;
        using ResponseType = eRouter::RouteGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        auto policy = wPolicyManager.lock();
        if (!policy)
        {
            res = adapter::internalErrorResponse<ResponseType>("Error: Policy Manager is not initialized");
            return;
        }

        // Execute the command
        const auto& error = router->getEntry(protoReq.name());
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.mutable_route()->CopyFrom(eRouteEntryFromEntry(base::getResponse(error), wPolicyManager));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler routeReload(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::RouteReload_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto name = tryGetProperty<ResponseType, base::Name>(
            true, [&protoReq]() { return base::Name(protoReq.name()); }, "name", "name");
        if (adapter::isError(name))
        {
            res = adapter::getErrorResp(name);
            return;
        }

        // Execute the command
        const auto& getResult = router->reloadEntry(adapter::getRes(name));
        if (base::isError(getResult))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(getResult).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler routePatchPriority(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::RoutePatchPriority_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto name = tryGetProperty<ResponseType, base::Name>(
            true, [&protoReq]() { return base::Name(protoReq.name()); }, "name", "name");
        if (adapter::isError(name))
        {
            res = adapter::getErrorResp(name);
            return;
        }

        // Execute the command
        const auto& error = router->changeEntryPriority(adapter::getRes(name), protoReq.priority());
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler tableGet(const std::shared_ptr<::router::IRouterAPI>& router,
                               const std::shared_ptr<api::policy::IPolicy>& policy)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router),
            wPolicyManager = std::weak_ptr<api::policy::IPolicy>(policy)](const auto& req, auto& res)
    {
        using RequestType = eRouter::TableGet_Request;
        using ResponseType = eRouter::TableGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        auto policy = wPolicyManager.lock();
        if (!policy)
        {
            res = adapter::internalErrorResponse<ResponseType>("Error: Policy Manager is not initialized");
            return;
        }

        // Execute the command
        const auto& entries = router->getEntries();
        ResponseType eResponse;
        auto eTable = eResponse.mutable_table(); // Create the empty table
        for (const auto& entry : entries)
        {
            eTable->Add(eRouteEntryFromEntry(entry, wPolicyManager));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler queuePost(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::QueuePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Execute the command
        const auto& error = router->postStrEvent(protoReq.wazuh_event());
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(error.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler changeEpsSettings(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::EpsUpdate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Execute the command
        const auto error = router->changeEpsSettings(protoReq.eps(), protoReq.refresh_interval());
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(error.value().message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getEpsSettings(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::EpsGet_Request;
        using ResponseType = eRouter::EpsGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Execute the command
        const auto error = router->getEpsSettings();
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        auto [eps, refreshInterval, active] = base::getResponse(error);
        eResponse.set_eps(eps);
        eResponse.set_refresh_interval(refreshInterval);
        eResponse.set_enabled(active);
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler activateEpsLimiter(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::EpsEnable_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Execute the command
        const auto error = router->activateEpsCounter(true);
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler deactivateEpsLimiter(const std::shared_ptr<::router::IRouterAPI>& router)
{
    return [wRouter = std::weak_ptr<::router::IRouterAPI>(router)](const auto& req, auto& res)
    {
        using RequestType = eRouter::EpsDisable_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::IRouterAPI>(req, wRouter);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [router, protoReq] = adapter::getRes(result);

        // Execute the command
        const auto error = router->activateEpsCounter(false);
        if (base::isError(error))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(error).message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::router::handlers
