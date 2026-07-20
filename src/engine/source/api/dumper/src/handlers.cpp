#include <api/dumper/handlers.hpp>
#include <base/logging.hpp>
#include <eMessages/event_dumper.pb.h>

namespace api::dumper::handlers
{

namespace eEventDumper = adapter::eEngine::event_dumper;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler activateDumper(const std::shared_ptr<::dumper::IDumper>& dumper)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakDumper = std::weak_ptr(dumper)](const auto& req, auto& res)
    {
        using RequestType = eEventDumper::EventDumperActivate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::dumper::IDumper>(req, weakDumper);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [dumper, protoReq] = adapter::getRes(result);

        dumper->activate();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler deactivateDumper(const std::shared_ptr<::dumper::IDumper>& dumper)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakDumper = std::weak_ptr(dumper)](const auto& req, auto& res)
    {
        using RequestType = eEventDumper::EventDumperDeactivate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::dumper::IDumper>(req, weakDumper);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [dumper, protoReq] = adapter::getRes(result);

        dumper->deactivate();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getDumperStatus(const std::shared_ptr<::dumper::IDumper>& dumper)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakDumper = std::weak_ptr(dumper)](const auto& req, auto& res)
    {
        using RequestType = eEventDumper::EventDumperStatus_Request;
        using ResponseType = eEventDumper::EventDumperStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::dumper::IDumper>(req, weakDumper);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [dumper, protoReq] = adapter::getRes(result);

        // Get the status
        const auto isActive = dumper->isActive();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_active(isActive);
        res = adapter::userResponse(eResponse);
    };
}
} // namespace api::dumper::handlers
