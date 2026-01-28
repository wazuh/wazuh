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
#include <api/shared/constants.hpp>

namespace {
    constexpr std::string_view ORGIN_SPACE_TESTING = "testing";
}
namespace api::cmcrud::handlers
{

namespace eContent = ::com::wazuh::api::engine::content;
namespace eEngine = ::com::wazuh::api::engine;

// Error messages
constexpr auto MESSAGE_SPACE_REQUIRED = "Field /space cannot be empty";
constexpr auto MESSAGE_YML_REQUIRED = "Field /ymlContent cannot be empty";
constexpr auto MESSAGE_JSON_REQUIRED = "Field /jsonContent cannot be empty";
constexpr auto MESSAGE_UUID_REQUIRED = "Field /uuid cannot be empty";
constexpr auto MESSAGE_TYPE_REQUIRED = "Field /type is required";
constexpr auto MESSAGE_TYPE_UNSUPPORTED = "Unsupported value for /type";
constexpr auto MESSAGE_RESOURCE_REQUIRED = "Field /resource cannot be empty";

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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->createNamespace(nsId);
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->deleteNamespace(nsId);
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

adapter::RouteHandler namespaceImport(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::namespaceImport_Request;
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

        if (protoReq.jsoncontent().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_JSON_REQUIRED);
            return;
        }

        try
        {
            const cm::store::NamespaceId nsId {protoReq.space()};
            // Use empty origin, so if exists, the origin space is not set.
            service->importNamespace(nsId, protoReq.jsoncontent(), "", protoReq.force());
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->upsertPolicy(nsId, protoReq.ymlcontent());
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->deletePolicy(nsId);
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

adapter::RouteHandler policyValidate(std::shared_ptr<cm::crud::ICrudService> crud,
                                     const std::shared_ptr<::router::ITesterAPI>& tester)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud),
            wTester = std::weak_ptr<::router::ITesterAPI>(tester)](const auto& req, auto& res)
    {
        using RequestType = eContent::policyValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        auto testerLocked = wTester.lock();
        if (!testerLocked)
        {
            res = adapter::userErrorResponse<ResponseType>("Tester API is not available");
            return;
        }

        const bool loadInTester = protoReq.load_in_tester();

        auto jsonOrErr = eMessage::eMessageToJson(protoReq.full_policy(), /*printPrimitiveFields=*/true);
        if (std::holds_alternative<base::Error>(jsonOrErr))
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format(
                "Error converting full_policy to JSON object: {}", std::get<base::Error>(jsonOrErr).message));
            return;
        }

        const auto& fullPolicyStr = std::get<std::string>(jsonOrErr);
        json::Json fullPolicy;
        try
        {
            fullPolicy = json::Json(fullPolicyStr.c_str());
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Error parsing full policy JSON object: {}", e.what()));
            return;
        }

        if (fullPolicy.isEmpty())
        {
            res = adapter::userErrorResponse<ResponseType>("Missing full policy");
            return;
        }

        // Strongly unique nonce: time + thread id hash + monotonic counter.
        static std::atomic<uint64_t> seq {0};
        const auto t = std::chrono::steady_clock::now().time_since_epoch().count();
        const auto tid = std::hash<std::thread::id> {}(std::this_thread::get_id());
        const auto s = seq.fetch_add(1, std::memory_order_relaxed);
        const auto nonce = fmt::format("{}_{}_{}", t, tid, s);

        const std::string tmpNsName = fmt::format("policy_validate_{}", nonce);
        const cm::store::NamespaceId tmpNsId {tmpNsName};
        const std::string tmpSessionName = fmt::format("policy_validate_{}", nonce);
        const std::string finalSessionName = api::shared::constants::SESSION_NAME;

        bool tmpNamespaceCreated = false;
        bool tmpSessionCreated = false;

        auto cleanupSession = [&](const std::string& name, bool shouldRun) -> base::OptError
        {
            if (!shouldRun)
            {
                return std::nullopt;
            }

            auto err = testerLocked->deleteTestEntry(name);
            if (base::isError(err))
            {
                return base::Error {
                    fmt::format("Cleanup: failed deleting session '{}': {}", name, base::getError(err).message)};
            }
            return std::nullopt;
        };

        auto cleanupNamespace = [&](const std::string& name, bool shouldRun) -> base::OptError
        {
            if (!shouldRun)
            {
                return std::nullopt;
            }

            try
            {
                const cm::store::NamespaceId nsId {name};
                service->deleteNamespace(nsId);
                return std::nullopt;
            }
            catch (const std::exception& e)
            {
                return base::Error {fmt::format("Cleanup: failed deleting namespace '{}': {}", name, e.what())};
            }
        };

        // Best-effort cleanup: never writes to `res`.
        auto bestEffortCleanup = [&](bool cleanupTmpSession,
                                     bool cleanupTmpNamespace,
                                     const std::optional<std::string>& extraNamespaceToDelete = std::nullopt) noexcept
        {
            (void)cleanupSession(tmpSessionName, cleanupTmpSession);
            (void)cleanupNamespace(tmpNsName, cleanupTmpNamespace);

            if (extraNamespaceToDelete)
            {
                (void)cleanupNamespace(*extraNamespaceToDelete, /*shouldRun=*/true);
            }
        };

        try
        {
            // Import into temp namespace
            service->importNamespace(tmpNsId, fullPolicyStr, ORGIN_SPACE_TESTING,/*force=*/true);
            tmpNamespaceCreated = true;

            // Create a tester entry to validate tester-loading path.
            const int lifetime = 0;
            ::router::test::EntryPost entryPost(tmpSessionName, tmpNsId, lifetime);
            entryPost.description("wazuh-indexer auto created session");

            // Post temp entry
            {
                auto err = testerLocked->postTestEntry(entryPost);
                if (base::isError(err))
                {
                    bestEffortCleanup(/*cleanupTmpSession=*/tmpSessionCreated,
                                      /*cleanupTmpNamespace=*/true);
                    res = adapter::userErrorResponse<ResponseType>(base::getError(err).message);
                    return;
                }
                tmpSessionCreated = true;
            }

            if (loadInTester)
            {
                std::optional<std::string> oldNsToDelete;

                // If SESSION_NAME exists, delete it first (it references old namespace).
                auto entry = testerLocked->getTestEntry(finalSessionName);
                if (!base::isError(entry))
                {
                    oldNsToDelete = base::getResponse(entry).namespaceId().toStr();

                    // Strict: if we can't delete the old session, abort.
                    if (auto serr = cleanupSession(finalSessionName, /*shouldRun=*/true))
                    {
                        bestEffortCleanup(/*cleanupTmpSession=*/tmpSessionCreated,
                                          /*cleanupTmpNamespace=*/true);
                        res = adapter::userErrorResponse<ResponseType>(serr->message);
                        return;
                    }
                }

                // Promote temp session to SESSION_NAME (now points to tmpNsName).
                auto rerr = testerLocked->renameTestEntry(tmpSessionName, finalSessionName);
                if (base::isError(rerr))
                {
                    bestEffortCleanup(/*cleanupTmpSession=*/tmpSessionCreated,
                                      /*cleanupTmpNamespace=*/true);
                    res = adapter::userErrorResponse<ResponseType>(base::getError(rerr).message);
                    return;
                }

                // After rename, temp session no longer exists.
                tmpSessionCreated = false;

                // Now it's safe to delete the old namespace (if any).
                if (oldNsToDelete)
                {
                    // Strict: if we can't delete old namespace, abort.
                    if (auto nerr = cleanupNamespace(*oldNsToDelete, /*shouldRun=*/true))
                    {
                        res = adapter::userErrorResponse<ResponseType>(nerr->message);
                        return;
                    }
                }

                ResponseType eResponse;
                eResponse.set_status(eEngine::ReturnStatus::OK);
                res = adapter::userResponse(eResponse);
                return;
            }

            // Not testing: cleanup must succeed, otherwise do NOT return OK.
            if (auto serr = cleanupSession(tmpSessionName, /*shouldRun=*/tmpSessionCreated))
            {
                (void)cleanupNamespace(tmpNsName, /*shouldRun=*/true); // best-effort follow-up
                res = adapter::userErrorResponse<ResponseType>(serr->message);
                return;
            }

            if (auto nerr = cleanupNamespace(tmpNsName, /*shouldRun=*/true))
            {
                res = adapter::userErrorResponse<ResponseType>(nerr->message);
                return;
            }

            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
            return;
        }
        catch (const std::exception& ex)
        {
            // Best-effort cleanup; preserve the primary failure cause.
            bestEffortCleanup(/*cleanupTmpSession=*/tmpSessionCreated,
                              /*cleanupTmpNamespace=*/tmpNamespaceCreated);
            res = adapter::userErrorResponse<ResponseType>(ex.what());
            return;
        }
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            const auto resources = service->listResources(nsId, rType);

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
            const cm::store::NamespaceId nsId {protoReq.space()};
            const auto content = service->getResourceByUUID(nsId, protoReq.uuid(), protoReq.asjson());
            eResponse.set_content(content);
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->upsertResource(nsId, rType, protoReq.ymlcontent());
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
            const cm::store::NamespaceId nsId {protoReq.space()};
            service->deleteResourceByUUID(nsId, protoReq.uuid());
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
 * Resource handler – validate (public, no namespace)
 *********************************************/

adapter::RouteHandler resourceValidate(std::shared_ptr<cm::crud::ICrudService> crud)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud)](const auto& req, auto& res)
    {
        using RequestType = eContent::resourceValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        constexpr auto MESSAGE_RESOURCE_REQUIRED = "Field /resource cannot be empty";

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::cm::crud::ICrudService>(req, wCrud);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [service, protoReq] = adapter::getRes(result);

        if (protoReq.type().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_REQUIRED);
            return;
        }

        // In proto3, Struct presence is best checked via fields_size()
        if (protoReq.resource().fields_size() == 0)
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_RESOURCE_REQUIRED);
            return;
        }

        const auto rType = cm::store::resourceTypeFromString(protoReq.type());
        if (rType == cm::store::ResourceType::UNDEFINED)
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_UNSUPPORTED);
            return;
        }

        // Convert Struct -> json::Json without JSON stringify/parse
        auto payloadOrErr = eMessage::eStructToJson(protoReq.resource());
        if (std::holds_alternative<base::Error>(payloadOrErr))
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Error converting /resource to JSON: {}", std::get<base::Error>(payloadOrErr).message));
            return;
        }

        const auto& payload = std::get<json::Json>(payloadOrErr);

        try
        {
            service->validateResource(rType, payload);
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
