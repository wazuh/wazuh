#include <api/contentsync/handlers.hpp>

#include <base/logging.hpp>
#include <eMessages/engine.pb.h>

namespace api::contentsync::handlers
{

namespace eEngine = ::com::wazuh::api::engine;

namespace
{

/// The shape both routes answer with. They carry no result of their own: the request is queued, and
/// what came of it is read from `GET /status`.
httplib::Response accepted()
{
    eEngine::GenericStatus_Response response;
    response.set_status(eEngine::ReturnStatus::OK);
    return adapter::userResponse(response);
}

} // namespace

adapter::RouteHandler updateRuleset(const std::shared_ptr<cm::sync::ICMSync>& cmSync)
{
    return [weakCmSync = std::weak_ptr(cmSync)](const httplib::Request&, httplib::Response& res)
    {
        auto cmSyncPtr = weakCmSync.lock();
        if (!cmSyncPtr)
        {
            res = adapter::internalErrorResponse<eEngine::GenericStatus_Response>(
                "Content Manager Sync service is not available");
            return;
        }

        try
        {
            // Empty: every tracked space. Which spaces those are is the sync service's own state,
            // and it can change at runtime, so the route does not hard-code a list.
            cmSyncPtr->requestOnDemandUpdate();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[API] Failed to queue a ruleset content update: {}", e.what());
            res = adapter::internalErrorResponse<eEngine::GenericStatus_Response>(e.what());
            return;
        }

        LOG_DEBUG("[API] Ruleset content update queued");
        res = accepted();
    };
}

adapter::RouteHandler syncIocFromIndexer(const std::shared_ptr<ioc::sync::IIocSync>& iocSync)
{
    return [weakIocSync = std::weak_ptr(iocSync)](const httplib::Request&, httplib::Response& res)
    {
        auto iocSyncPtr = weakIocSync.lock();
        if (!iocSyncPtr)
        {
            res = adapter::internalErrorResponse<eEngine::GenericStatus_Response>("IOC Sync service is not available");
            return;
        }

        try
        {
            iocSyncPtr->requestOnDemandUpdate();
        }
        catch (const std::exception& e)
        {
            LOG_WARNING("[API] Failed to queue an IOC content update: {}", e.what());
            res = adapter::internalErrorResponse<eEngine::GenericStatus_Response>(e.what());
            return;
        }

        LOG_DEBUG("[API] IOC content update queued");
        res = accepted();
    };
}

} // namespace api::contentsync::handlers
