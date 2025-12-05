
#include <string>
#include <type_traits>
#include <utility>

#include <fmt/format.h>

#include <base/json.hpp>
#include <cmstore/types.hpp>
#include <eMessages/crud.pb.h>
#include <eMessages/eMessage.h>

#include <api/adapter/helpers.hpp>
#include <api/cmcrud/handlers.hpp>

namespace api::cmcrud::handlers
{

namespace eContent = ::com::wazuh::api::engine::content;
namespace eEngine = ::com::wazuh::api::engine;

// Error messages
constexpr auto MESSAGE_SPACE_REQUIRED = "Field /space cannot be empty";
constexpr auto MESSAGE_YML_REQUIRED = "Field /ymlContent cannot be empty";
constexpr auto MESSAGE_UUID_REQUIRED = "Field /uuid cannot be empty";
constexpr auto MESSAGE_TYPE_REQUIRED = "Field /type is required";
constexpr auto MESSAGE_TYPE_UNSUPPORTED = "Unsupported value for /type";

/*********************************************
 * Namespace handlers
 *********************************************/

adapter::RouteHandler namespaceList(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::namespaceGet_Request;
        using ResponseType = eContent::namespaceGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);
        (void)protoReq; // No fields in namespaceGet_Request

        ResponseType eResponse;

        try
        {
            const auto namespaces = service->listNamespaces();

            auto* spaces = eResponse.mutable_spaces();
            spaces->Clear();

            for (const auto& nsId : namespaces)
            {
                auto* s = spaces->Add();
                if constexpr (std::is_same_v<std::decay_t<decltype(nsId)>, cm::store::NamespaceId>)
                {
                    s->assign(nsId.toStr());
                }
                else
                {
                    s->assign(nsId);
                }
            }

            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        }
        catch (const std::exception& ex)
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(ex.what());
            res = adapter::userResponse(eResponse);
        }
    };
}

adapter::RouteHandler namespaceCreate(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::namespacePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        try
        {
            service->createNamespace(protoReq.space());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler namespaceDelete(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::namespaceDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        try
        {
            service->deleteNamespace(protoReq.space());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

/*********************************************
 * Policy handlers
 *********************************************/

adapter::RouteHandler policyUpsert(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::policyPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        if (protoReq.ymlcontent().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_YML_REQUIRED);
            return;
        }

        try
        {
            service->upsertPolicy(protoReq.space(), protoReq.ymlcontent());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler policyDelete(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::policyDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        try
        {
            service->deletePolicy(protoReq.space());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

/*********************************************
 * Resource handlers – list & get
 *********************************************/

adapter::RouteHandler resourceList(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::resourceList_Request;
        using ResponseType = eContent::resourceList_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        if (protoReq.type().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_REQUIRED);
            return;
        }

        const auto rType = cm::store::resourceTypeFromString(protoReq.type());
        if (rType == cm::store::ResourceType::UNDEFINED)
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_UNSUPPORTED);
            return;
        }

        ResponseType eResponse;

        try
        {
            const auto resources = service->listResources(protoReq.space(), rType);

            auto* out = eResponse.mutable_resources();
            out->Clear();

            for (const auto& r : resources)
            {
                auto* item = out->Add();
                item->set_uuid(r.uuid);
                item->set_name(r.name);
                item->set_hash(r.hash);
            }

            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        }
        catch (const std::exception& ex)
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(ex.what());
            res = adapter::userResponse(eResponse);
        }
    };
}

adapter::RouteHandler resourceGet(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::resourceGet_Request;
        using ResponseType = eContent::resourceGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        if (protoReq.uuid().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_UUID_REQUIRED);
            return;
        }

        ResponseType eResponse;

        try
        {
            const auto yml = service->getResourceByUUID(protoReq.space(), protoReq.uuid());
            eResponse.set_ymlcontent(yml);
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        }
        catch (const std::exception& ex)
        {
            eResponse.set_status(eEngine::ReturnStatus::ERROR);
            eResponse.set_error(ex.what());
            res = adapter::userResponse(eResponse);
        }
    };
}

/*********************************************
 * Resource handlers – upsert & delete
 *********************************************/

adapter::RouteHandler resourceUpsert(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::resourcePost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        if (protoReq.type().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_REQUIRED);
            return;
        }

        if (protoReq.ymlcontent().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_YML_REQUIRED);
            return;
        }

        const auto rType = cm::store::resourceTypeFromString(protoReq.type());
        if (rType == cm::store::ResourceType::UNDEFINED)
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_UNSUPPORTED);
            return;
        }

        try
        {
            service->upsertResource(protoReq.space(), rType, protoReq.ymlcontent());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler resourceDelete(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::resourceDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.space().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_SPACE_REQUIRED);
            return;
        }

        if (protoReq.uuid().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_UUID_REQUIRED);
            return;
        }

        try
        {
            service->deleteResourceByUUID(protoReq.space(), protoReq.uuid());
        }
        catch (const std::exception& ex)
        {
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::cmcrud::handlers
