#include <api/archiver/handlers.hpp>
#include <base/logging.hpp>
#include <eMessages/archiver.pb.h>

namespace api::archiver::handlers
{

namespace eArchiver = adapter::eEngine::archiver;
namespace eEngine = adapter::eEngine;

adapter::RouteHandler activateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakArchiver = std::weak_ptr(archiver)](const auto& req, auto& res)
    {
        using RequestType = eArchiver::ArchiverActivate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::archiver::IArchiver>(req, weakArchiver);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [archiver, protoReq] = adapter::getRes(result);

        archiver->activate();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler deactivateArchiver(const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakArchiver = std::weak_ptr(archiver)](const auto& req, auto& res)
    {
        using RequestType = eArchiver::ArchiverDeactivate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::archiver::IArchiver>(req, weakArchiver);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [archiver, protoReq] = adapter::getRes(result);

        archiver->deactivate();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler getArchiverStatus(const std::shared_ptr<::archiver::IArchiver>& archiver)
{
    return [lambdaName = logging::getLambdaName(__FUNCTION__, "apiHandler"),
            weakArchiver = std::weak_ptr(archiver)](const auto& req, auto& res)
    {
        using RequestType = eArchiver::ArchiverStatus_Request;
        using ResponseType = eArchiver::ArchiverStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::archiver::IArchiver>(req, weakArchiver);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [archiver, protoReq] = adapter::getRes(result);

        // Get the status
        const auto isActive = archiver->isActive();

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        eResponse.set_active(isActive);
        res = adapter::userResponse(eResponse);
    };
}
} // namespace api::archiver::handlers
