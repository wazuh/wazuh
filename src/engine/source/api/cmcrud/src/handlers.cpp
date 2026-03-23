#include <string>
#include <type_traits>
#include <utility>

#include <fmt/format.h>

#include <base/json.hpp>
#include <base/utils/generator.hpp>
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

        const std::string finalSessionName = protoReq.space();
        if (finalSessionName.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("Field /space cannot be empty");
            return;
        }

        // Generate unique temp namespace and session names to avoid conflicts with concurrent validations.
        const auto tmpPrefix = loadInTester ? "logtest_{}" : "tmp_policy_validate_{}";
        const std::string tmpName = fmt::format(tmpPrefix, base::utils::generators::randomHexString(6));
        const cm::store::NamespaceId tmpNsId {tmpName};
        const std::string& tmpSessionName = tmpName;

        // ---------------------------------------------------------------
        // RAII guard: best-effort cleanup of temp resources on scope exit.
        // Call release() to transfer ownership (e.g. after promote/rename).
        // For strict cleanup, delete explicitly first, then release().
        // ---------------------------------------------------------------
        struct TempGuard
        {
            std::shared_ptr<::router::ITesterAPI> tester;
            std::shared_ptr<cm::crud::ICrudService> service;
            std::string sessionName;
            cm::store::NamespaceId namespaceName;
            bool sessionOwned = false;
            bool namespaceOwned = false;

            ~TempGuard() noexcept
            {
                try
                {
                    if (sessionOwned)
                    {
                        (void)tester->deleteTestEntry(sessionName);
                    }
                    if (namespaceOwned)
                    {
                        service->deleteNamespace(namespaceName);
                    }
                }
                catch (...)
                {
                    // Swallow exceptions in destructor; nothing we can do about it at this point.
                }
            }

            void releaseSession() noexcept { sessionOwned = false; }
            void releaseNamespace() noexcept { namespaceOwned = false; }
            void releaseAll() noexcept
            {
                sessionOwned = false;
                namespaceOwned = false;
            }
        };

        TempGuard guard {testerLocked, service, tmpSessionName, tmpNsId};

        // Strict-cleanup helpers: return error on failure (used when
        // cleanup must succeed before returning OK to the caller).
        auto strictDeleteSession = [&](const std::string& name) -> base::OptError
        {
            auto err = testerLocked->deleteTestEntry(name);
            if (base::isError(err))
            {
                return base::Error {
                    fmt::format("Cleanup: failed deleting session '{}': {}", name, base::getError(err).message)};
            }
            return std::nullopt;
        };

        auto strictDeleteNamespace = [&](const std::string& name) -> base::OptError
        {
            try
            {
                service->deleteNamespace(cm::store::NamespaceId {name});
                return std::nullopt;
            }
            catch (const std::exception& e)
            {
                return base::Error {fmt::format("Cleanup: failed deleting namespace '{}': {}", name, e.what())};
            }
        };

        try
        {
            // ============================================================
            // Step 1: Import into temp namespace (validates structure).
            // ============================================================
            const cm::store::dataType::Policy pol =
                service->importNamespace(tmpNsId, fullPolicyStr, finalSessionName, /*force=*/true);
            guard.namespaceOwned = true;

            const bool isEnabled = pol.isEnabled();
            const bool hasIntegrations = !pol.getIntegrationsUUIDs().empty();

            // ============================================================
            // Step 2: If has integrations, post a tester entry to validate
            //         the policy can actually be instantiated.
            // ============================================================
            if (hasIntegrations)
            {
                const int lifetime = 0;
                ::router::test::EntryPost entryPost(tmpSessionName, tmpNsId, lifetime);
                entryPost.description("wazuh-indexer auto created session");

                auto err = testerLocked->postTestEntry(entryPost);
                if (base::isError(err))
                {
                    // guard will clean up the namespace on scope exit.
                    res = adapter::userErrorResponse<ResponseType>(base::getError(err).message);
                    return;
                }
                guard.sessionOwned = true;
            }
            // Policy is now validated.

            // ============================================================
            // Step 3: Decide what to do with the persistent test session.
            //
            //  shouldPromote      – replace the old test session with the
            //                       new one (only when we have integrations
            //                       and the policy is enabled).
            //  shouldDeleteOldTest – wipe the existing test session because
            //                        the policy has no integrations or is
            //                        disabled.
            //  Neither            – leave the existing test session untouched
            //                        (loadInTester is false).
            // ============================================================
            const bool shouldPromote = loadInTester && hasIntegrations && isEnabled;
            const bool shouldDeleteOldTest = loadInTester && (!hasIntegrations || !isEnabled);

            if (shouldPromote)
            {
                // Promote the temp session → finalSessionName, replacing the old one.
                std::optional<std::string> oldNsToDelete;

                auto entry = testerLocked->getTestEntry(finalSessionName);
                if (!base::isError(entry))
                {
                    oldNsToDelete = base::getResponse(entry).namespaceId().toStr();

                    if (auto serr = strictDeleteSession(finalSessionName))
                    {
                        // guard will clean temp session + namespace.
                        res = adapter::userErrorResponse<ResponseType>(serr->message);
                        return;
                    }
                }

                auto rerr = testerLocked->renameTestEntry(tmpSessionName, finalSessionName);
                if (base::isError(rerr))
                {
                    // guard will clean temp session + namespace.
                    res = adapter::userErrorResponse<ResponseType>(base::getError(rerr).message);
                    return;
                }
                // After rename the temp resources are now owned by the final session.
                guard.releaseAll();

                if (oldNsToDelete)
                {
                    if (auto nerr = strictDeleteNamespace(*oldNsToDelete))
                    {
                        res = adapter::userErrorResponse<ResponseType>(nerr->message);
                        return;
                    }
                }
            }
            else
            {
                // Not promoting: strict-delete temp resources, then release from guard.
                if (guard.sessionOwned)
                {
                    if (auto serr = strictDeleteSession(tmpSessionName))
                    {
                        // guard will still attempt best-effort cleanup on exit.
                        res = adapter::userErrorResponse<ResponseType>(serr->message);
                        return;
                    }
                    guard.releaseSession();
                }

                if (auto nerr = strictDeleteNamespace(tmpName))
                {
                    // namespace already failed strict delete; nothing more to clean.
                    guard.releaseNamespace();
                    res = adapter::userErrorResponse<ResponseType>(nerr->message);
                    return;
                }
                guard.releaseNamespace();

                // If requested, delete the old persistent test session and its namespace.
                if (shouldDeleteOldTest)
                {
                    auto entry = testerLocked->getTestEntry(finalSessionName);
                    if (!base::isError(entry))
                    {
                        const std::string oldNsName = base::getResponse(entry).namespaceId().toStr();

                        if (auto serr = strictDeleteSession(finalSessionName))
                        {
                            (void)strictDeleteNamespace(oldNsName);
                            res = adapter::userErrorResponse<ResponseType>(serr->message);
                            return;
                        }

                        if (auto nerr = strictDeleteNamespace(oldNsName))
                        {
                            res = adapter::userErrorResponse<ResponseType>(nerr->message);
                            return;
                        }
                    }
                }
            }

            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
            return;
        }
        catch (const std::exception& ex)
        {
            // guard destructor handles best-effort cleanup automatically.
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

adapter::RouteHandler resourceValidate(std::shared_ptr<cm::crud::ICrudService> crud,
                                       int64_t maxResourcePayloadBytes,
                                       int64_t maxKvdbPayloadBytes)
{
    return [wCrud = std::weak_ptr<cm::crud::ICrudService>(crud), maxResourcePayloadBytes, maxKvdbPayloadBytes](
               const auto& req, auto& res)
    {
        using RequestType = eContent::resourceValidate_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        constexpr auto MESSAGE_RESOURCE_REQUIRED = "Field /resource cannot be empty";

        auto service = wCrud.lock();
        if (!service)
        {
            res = adapter::internalErrorResponse<ResponseType>("Error: Handler is not initialized");
            return;
        }

        const auto bodySize = static_cast<int64_t>(req.body.size());
        const bool hasGlobalAbsoluteCap = (maxResourcePayloadBytes > 0 && maxKvdbPayloadBytes > 0);
        if (hasGlobalAbsoluteCap && bodySize > std::max(maxResourcePayloadBytes, maxKvdbPayloadBytes))
        {
            const auto maxAcceptedBytes = std::max(maxResourcePayloadBytes, maxKvdbPayloadBytes);
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Request body exceeds maximum allowed document size of {} bytes", maxAcceptedBytes));
            res.status = httplib::StatusCode::PayloadTooLarge_413;
            return;
        }

        auto result = adapter::parseRequest<RequestType, ResponseType>(req);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto protoReq = adapter::getRes(result);

        if (protoReq.type().empty())
        {
            res = adapter::userErrorResponse<ResponseType>(MESSAGE_TYPE_REQUIRED);
            return;
        }

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

        const auto typeLimit = (rType == cm::store::ResourceType::KVDB) ? maxKvdbPayloadBytes : maxResourcePayloadBytes;
        if (typeLimit > 0 && bodySize > typeLimit)
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Request body exceeds maximum allowed size of {} bytes for type '{}'",
                            typeLimit,
                            cm::store::resourceTypeToString(rType)));
            res.status = httplib::StatusCode::PayloadTooLarge_413;
            return;
        }

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
