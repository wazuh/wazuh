#include <api/rawevtindexer/handlers.hpp>

#include <base/logging.hpp>
#include <eMessages/rawevtindexer.pb.h>

namespace api::rawevtindexer::handlers
{

namespace eRawIndexer = adapter::eEngine::rawevtindexer;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler enableRawEventIndexer(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakRawIndexer = std::weak_ptr(rawIndexer)](const auto& req, auto& res)
    {
        using RequestType = eRawIndexer::RawEvtIndexerEnable_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::raweventindexer::IRawEventIndexer>(
            req, weakRawIndexer);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [rawIndexer, protoReq] = adapter::getRes(result);

        rawIndexer->enable();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler disableRawEventIndexer(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakRawIndexer = std::weak_ptr(rawIndexer)](const auto& req, auto& res)
    {
        using RequestType = eRawIndexer::RawEvtIndexerDisable_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::raweventindexer::IRawEventIndexer>(
            req, weakRawIndexer);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [rawIndexer, protoReq] = adapter::getRes(result);

        rawIndexer->disable();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getRawEventIndexerStatus(const std::shared_ptr<::raweventindexer::IRawEventIndexer>& rawIndexer)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakRawIndexer = std::weak_ptr(rawIndexer)](const auto& req, auto& res)
    {
        using RequestType = eRawIndexer::RawEvtIndexerStatus_Request;
        using ResponseType = eRawIndexer::RawEvtIndexerStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::raweventindexer::IRawEventIndexer>(
            req, weakRawIndexer);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [rawIndexer, protoReq] = adapter::getRes(result);

        // Get the status
        const auto isEnabled = rawIndexer->isEnabled();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_enabled(isEnabled);
        res = adapter::userResponse(eResponse);
    };
}
} // namespace api::rawevtindexer::handlers
