#include "cmstore/icmstore.hpp"
#include <memory>
#include <sstream>

#include <eMessages/tester.pb.h>
#include <router/iapi.hpp>

#include <api/adapter/adapter.hpp>
#include <api/adapter/helpers.hpp>
#include <api/tester/handlers.hpp>
#include <base/dotPath.hpp>

namespace api::tester::handlers
{
namespace eTester = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;
using namespace adapter::helpers;

template<typename RequestType>
using TesterAndRequest = std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>; ///< Tester and request

namespace
{

/**
 * @brief Transform a router::test::Entry to a eTester::Session
 *
 * @param entry Entry to transform
 * @return eTester::Session
 */
eTester::Session toSession(const ::router::test::Entry& entry, const std::weak_ptr<cm::store::ICMStore>& wStore)
{
    eTester::Session session;
    session.set_name(entry.name());
    session.set_namespaceid(entry.namespaceId().toStr());
    session.set_lifetime(static_cast<uint32_t>(entry.lifetime()));
    if (entry.description().has_value())
    {
        session.mutable_description()->assign(entry.description().value());
    }

    eTester::State state = ::router::env::State::ENABLED == entry.status()    ? eTester::State::ENABLED
                           : ::router::env::State::DISABLED == entry.status() ? eTester::State::DISABLED
                                                                              : eTester::State::STATE_UNKNOWN;

    session.set_entry_status(state);
    session.set_last_use(static_cast<uint32_t>(entry.lastUse()));
    return session;
}

/**
 * @brief Transform a router::test::Output to a eTester::Result
 *
 * @param output Output to transform
 * @return eTester::Result
 */
eTester::Result fromOutput(const ::router::test::Output& output)
{
    eTester::Result result {};

    // Set event - Convert json::Json to google::protobuf::Struct
    auto structOrErr = eMessage::eMessageFromJson<google::protobuf::Struct>(output.event()->str());
    if (std::holds_alternative<base::Error>(structOrErr))
    {
        throw std::runtime_error(fmt::format("Error converting event JSON to protobuf Struct: {}",
                                             std::get<base::Error>(structOrErr).message));
    }
    *result.mutable_output() = std::get<google::protobuf::Struct>(structOrErr);

    // Set traces
    for (const auto& [assetName, assetTrace] : output.traceList())
    {
        eTester::Result_AssetTrace eTrace {};
        eTrace.set_asset(assetName);
        eTrace.set_success(assetTrace.success);
        for (const auto& trace : assetTrace.traces)
        {
            eTrace.add_traces(trace);
        }

        result.mutable_asset_traces()->Add(std::move(eTrace));
    }

    return result;
}

base::RespOrError<std::pair<json::Json, json::Json>>
parseAndValidatePublicMetadata(const google::protobuf::Struct& protoMetadata)
{
    auto metadataOrError = eMessage::eStructToJson(protoMetadata);
    if (std::holds_alternative<base::Error>(metadataOrError))
    {
        return base::Error {
            fmt::format("Error converting metadata to JSON: {}", std::get<base::Error>(metadataOrError).message)};
    }

    const auto& metadata = std::get<json::Json>(metadataOrError);
    if (!metadata.isObject())
    {
        return base::Error {"Metadata must be a JSON object"};
    }

    if (metadata.size() > 1)
    {
        return base::Error {"If not empty metadata must contain only 'wazuh' as the top-level key"};
    }

    // Empty metadata is allowed, but in that case we return an empty object for the 'wazuh' metadata
    // to avoid issues in the protocol handler
    if (metadata.isEmpty())
    {
        return std::make_pair(json::Json("{}"), json::Json("{}"));
    }

    auto wazuhMetadataObject = metadata.getJson("/wazuh");
    auto wazuhRootObjectOpt = wazuhMetadataObject ? wazuhMetadataObject->getJson() : std::nullopt;
    if (!wazuhMetadataObject.has_value() || !wazuhMetadataObject->isObject())
    {
        return base::Error {"Metadata must be a non-empty object with 'wazuh' as root"};
    }

    return std::make_pair(std::move(metadata), std::move(wazuhMetadataObject.value()));
}

bool validateMetadataLeaves(const json::Json& node,
                            const std::shared_ptr<schemf::IValidator>& schemaValidator,
                            std::string& currentPath,
                            std::string& error)
{
    if (node.isObject())
    {
        auto objOpt = node.getObject();
        if (!objOpt.has_value())
        {
            return true;
        }

        for (const auto& [key, value] : objOpt.value())
        {
            const auto originalSize = currentPath.size();
            if (!currentPath.empty())
            {
                currentPath.push_back('.');
            }
            currentPath.append(key);

            if (!validateMetadataLeaves(value, schemaValidator, currentPath, error))
            {
                return false;
            }

            currentPath.resize(originalSize);
        }

        return true;
    }

    try
    {
        const auto& dotPath = DotPath(currentPath);
        if (base::isError(schemaValidator->validate(dotPath, node)))
        {
            error = fmt::format("Metadata field '{}' doesn't exist or doesn't match the expected one from the schema",
                                dotPath.str());
            return false;
        }
    }
    catch (const std::exception& e)
    {
        error = fmt::format("Error validating metadata path '{}': {}", currentPath, e.what());
        return false;
    }

    return true;
}

} // namespace

adapter::RouteHandler sessionPost(const std::shared_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester)](const auto& req, auto& res)
    {
        using RequestType = eTester::SessionPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto protoSession = tryGetProperty<ResponseType, eTester::SessionPost>(
            protoReq.has_session(), [&protoReq]() { return protoReq.session(); }, "session", "session");
        if (adapter::isError(protoSession))
        {
            res = adapter::getErrorResp(protoSession);
            return;
        }

        auto namespaceId = tryGetProperty<ResponseType, cm::store::NamespaceId>(
            true,
            [&protoSession]() { return cm::store::NamespaceId(adapter::getRes(protoSession).namespaceid()); },
            "policy",
            "name");
        if (adapter::isError(namespaceId))
        {
            res = adapter::getErrorResp(namespaceId);
            return;
        }

        // Add the session
        ::router::test::EntryPost entryPost(
            protoReq.session().name(), adapter::getRes(namespaceId), protoReq.session().lifetime());

        if (protoReq.session().has_description() && !protoReq.session().description().empty())
        {
            entryPost.description(protoReq.session().description());
        }

        auto error = tester->postTestEntry(entryPost);
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

adapter::RouteHandler sessionDelete(const std::shared_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester)](const auto& req, auto& res)
    {
        using RequestType = eTester::SessionDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Validate request
        auto name = tryGetProperty<ResponseType, base::Name>(
            true, [&protoReq]() { return base::Name(protoReq.name()); }, "name", "name");
        if (adapter::isError(name))
        {
            res = adapter::getErrorResp(name);
            return;
        }

        // Delete the session
        auto error = tester->deleteTestEntry(adapter::getRes(name));
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

adapter::RouteHandler sessionGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                                 const std::shared_ptr<cm::store::ICMStore>& store)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wStore = std::weak_ptr<cm::store::ICMStore>(store)](const auto& req, auto& res)
    {
        using RequestType = eTester::SessionGet_Request;
        using ResponseType = eTester::SessionGet_Response;

        // Validate request
        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Get the session
        auto entry = tester->getTestEntry(protoReq.name());
        if (base::isError(entry))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(entry).message);
            return;
        }

        ResponseType eResponse;
        eResponse.mutable_session()->CopyFrom(toSession(base::getResponse(entry), wStore));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler sessionReload(const std::shared_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester)](const auto& req, auto& res)
    {
        using RequestType = eTester::SessionReload_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Validate the params request
        auto name = tryGetProperty<ResponseType, base::Name>(
            true, [&protoReq]() { return base::Name(protoReq.name()); }, "name", "name");
        if (adapter::isError(name))
        {
            res = adapter::getErrorResp(name);
            return;
        }

        // Execute the command
        const auto& getResult = tester->reloadTestEntry(adapter::getRes(name));
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

adapter::RouteHandler tableGet(const std::shared_ptr<::router::ITesterAPI>& tester,
                               const std::shared_ptr<cm::store::ICMStore>& store)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wStore = std::weak_ptr<cm::store::ICMStore>(store)](const auto& req, auto& res)
    {
        using RequestType = eTester::TableGet_Request;
        using ResponseType = eTester::TableGet_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Get the table
        auto entries = tester->getTestEntries();

        // Create the response
        ResponseType eResponse;
        for (const auto& entry : entries)
        {
            eResponse.add_sessions()->CopyFrom(toSession(entry, wStore));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler runPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                              const base::eventParsers::ProtocolHandler& protocolHandler)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester), protocolHandler](const auto& req, auto& res)
    {
        using RequestType = eTester::RunPost_Request;
        using ResponseType = eTester::RunPost_Response;

        // Validate request
        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        // Checks params
        using OTraceLavel = ::router::test::Options::TraceLevel;
        OTraceLavel traceLevel = protoReq.trace_level() == eTester::TraceLevel::NONE         ? OTraceLavel::NONE
                                 : protoReq.trace_level() == eTester::TraceLevel::ASSET_ONLY ? OTraceLavel::ASSET_ONLY
                                                                                             : OTraceLavel::ALL;

        // Find the list of assets to trace
        std::unordered_set<std::string> assetToTrace {};
        if (traceLevel != OTraceLavel::NONE)
        {
            // Get the assets of the policy filtered by namespaces
            auto resPolicyAssets = tester->getAssets(protoReq.name());
            if (base::isError(resPolicyAssets))
            {
                res = adapter::userErrorResponse<ResponseType>(base::getError(resPolicyAssets).message);
                return;
            }

            auto& policyAssets = base::getResponse(resPolicyAssets);

            if (protoReq.asset_trace_size() == 0)
            {
                assetToTrace = std::move(policyAssets);
            }
            else // If eRequest.assets() has assets, then only those assets should be traced
            {
                std::unordered_set<std::string> requestAssets {};
                for (const auto& asset : protoReq.asset_trace())
                {
                    if (policyAssets.find(asset) == policyAssets.end())
                    {
                        res =
                            adapter::userErrorResponse<ResponseType>(fmt::format("Asset {} not found in store", asset));
                        return;
                    }
                    requestAssets.insert(asset);
                }
                assetToTrace = std::move(requestAssets);
            }
        }

        // Create The event to test
        base::Event event;
        json::Json agentMetadata;

        // Use provided agent_metadata if available, otherwise use empty struct
        if (protoReq.has_agent_metadata())
        {
            auto jsonOrErr = eMessage::eStructToJson(protoReq.agent_metadata());
            if (std::holds_alternative<base::Error>(jsonOrErr))
            {
                res = adapter::userErrorResponse<ResponseType>(fmt::format(
                    "Error converting agent_metadata to JSON: {}", std::get<base::Error>(jsonOrErr).message));
                return;
            }

            agentMetadata = std::move(std::get<json::Json>(jsonOrErr));
        }
        else
        {
            agentMetadata = json::Json("{}");
        }

        try
        {
            event = protocolHandler(protoReq.event(), agentMetadata);
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Error parsing event: {}", e.what()));
            return;
        }

        // Run the test
        auto opt = ::router::test::Options(traceLevel, assetToTrace, protoReq.name());

        auto futureResult = tester->ingestTest(std::move(event), opt);
        event = nullptr;

        if (futureResult.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
        {
            res = adapter::userErrorResponse<ResponseType>("Timeout waiting for ingestTest");
            return;
        }
        auto response = futureResult.get();

        if (base::isError(response))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(response).message);
            return;
        }

        ResponseType eResponse {};
        eResponse.mutable_result()->CopyFrom(fromOutput(base::getResponse(response)));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler publicRunPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                                    const base::eventParsers::PublicProtocolHandler& protocolHandler,
                                    const std::shared_ptr<schemf::IValidator>& schemaValidator)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            protocolHandler,
            wSchemaValidator = std::weak_ptr<schemf::IValidator>(schemaValidator)](const auto& req, auto& res)
    {
        using RequestType = eTester::PublicRunPost_Request;
        using ResponseType = eTester::RunPost_Response;

        // Validate request
        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        const uint32_t q = protoReq.queue();
        if (q == 0)
        {
            res = adapter::userErrorResponse<ResponseType>("queue is required and must be non-zero (1..255)");
            return;
        }

        if (q > std::numeric_limits<uint8_t>::max())
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Invalid queue: {} (must be 1..255)", q));
            return;
        }

        const auto queue = static_cast<uint8_t>(q);

        // Checks params
        using OTraceLavel = ::router::test::Options::TraceLevel;
        OTraceLavel traceLevel = ::router::test::Options::stringToTraceLevel(protoReq.trace_level());
        if (traceLevel == OTraceLavel::UNKNOWN)
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Invalid trace level: {}. Only support: NONE, ASSET_ONLY, ALL", protoReq.trace_level()));
            return;
        }

        json::Json metadata {"{}"};
        std::string eventStr {};
        if (protoReq.has_metadata())
        {
            // Ensure schemaValidator is available
            auto schemaValidatorLocked = wSchemaValidator.lock();
            if (!schemaValidatorLocked)
            {
                res = adapter::userErrorResponse<ResponseType>("Schema is not available");
                return;
            }

            auto metadataOrError = parseAndValidatePublicMetadata(protoReq.metadata());
            if (base::isError(metadataOrError))
            {
                res = adapter::userErrorResponse<ResponseType>(base::getError(metadataOrError).message);
                return;
            }

            auto [tempMetadata, wazuhMetadataObject] = base::getResponse(metadataOrError);
            metadata = std::move(tempMetadata);

            std::string badFieldMsg {};
            std::string metadataPath {"wazuh"};
            if (!validateMetadataLeaves(wazuhMetadataObject, schemaValidatorLocked, metadataPath, badFieldMsg))
            {
                res = adapter::userErrorResponse<ResponseType>(badFieldMsg);
                return;
            }
        }

        eventStr = protoReq.event();
        if (eventStr.empty()
            || std::all_of(eventStr.begin(), eventStr.end(), [](unsigned char c) { return std::isspace(c); }))
        {
            res = adapter::userErrorResponse<ResponseType>("event is required and cannot be empty");
            return;
        }

        const std::string sessionName = protoReq.space();
        if (sessionName.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("space is required and cannot be empty");
            return;
        }

        // Create The event to test
        base::Event event;
        auto location = protoReq.location();
        try
        {
            event = protocolHandler(queue, location, eventStr, metadata);
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Error parsing event: {}", e.what()));
            return;
        }

        // Find the list of assets to trace
        std::unordered_set<std::string> assetToTrace {};
        if (traceLevel != OTraceLavel::NONE)
        {
            // Get the assets of the policy filtered by namespaces
            auto resPolicyAssets = tester->getAssets(sessionName);
            if (base::isError(resPolicyAssets))
            {
                res = adapter::userErrorResponse<ResponseType>(base::getError(resPolicyAssets).message);
                return;
            }

            auto& policyAssets = base::getResponse(resPolicyAssets);
            assetToTrace = std::move(policyAssets);
        }

        // Run the test
        auto opt = ::router::test::Options(traceLevel, assetToTrace, sessionName);

        auto futureResult = tester->ingestTest(std::move(event), opt);
        event = nullptr;

        if (futureResult.wait_for(std::chrono::seconds(5)) != std::future_status::ready)
        {
            res = adapter::userErrorResponse<ResponseType>("Timeout waiting for ingestTest");
            return;
        }
        auto response = futureResult.get();

        if (base::isError(response))
        {
            res = adapter::userErrorResponse<ResponseType>(base::getError(response).message);
            return;
        }

        ResponseType eResponse {};
        eResponse.mutable_result()->CopyFrom(fromOutput(base::getResponse(response)));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler logtestDelete(const std::shared_ptr<::router::ITesterAPI>& tester,
                                    const std::shared_ptr<cm::store::ICMStore>& store)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wStore = std::weak_ptr<cm::store::ICMStore>(store)](const auto& req, auto& res)
    {
        using RequestType = eTester::LogtestDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        auto result = adapter::getReqAndHandler<RequestType, ResponseType, ::router::ITesterAPI>(req, wTester);
        if (adapter::isError(result))
        {
            res = adapter::getErrorResp(result);
            return;
        }

        auto [tester, protoReq] = adapter::getRes(result);

        const std::string sessionName = protoReq.space();
        if (sessionName.empty())
        {
            res = adapter::userErrorResponse<ResponseType>("space is required and cannot be empty");
            return;
        }

        auto storeLocked = wStore.lock();
        if (!storeLocked)
        {
            res = adapter::userErrorResponse<ResponseType>("CMStore is not available");
            return;
        }

        auto cleanupSession = [&](const std::string& name) -> base::OptError
        {
            auto err = tester->deleteTestEntry(name);
            if (base::isError(err))
            {
                return base::Error {
                    fmt::format("Cleanup: failed deleting session '{}': {}", name, base::getError(err).message)};
            }
            return std::nullopt;
        };

        auto cleanupNamespace = [&](const cm::store::NamespaceId& nsId) -> base::OptError
        {
            try
            {
                storeLocked->deleteNamespace(nsId);
                return std::nullopt;
            }
            catch (const std::exception& e)
            {
                return base::Error {fmt::format("Cleanup: failed deleting namespace '{}': {}", nsId.toStr(), e.what())};
            }
        };

        auto entry = tester->getTestEntry(sessionName);
        if (base::isError(entry))
        {
            ResponseType eResponse;
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
            return;
        }

        const auto nsId = base::getResponse(entry).namespaceId();

        if (storeLocked->existsNamespace(nsId))
        {
            if (auto nerr = cleanupNamespace(nsId))
            {
                res = adapter::userErrorResponse<ResponseType>(nerr->message);
                return;
            }
        }

        if (auto serr = cleanupSession(sessionName))
        {
            res = adapter::userErrorResponse<ResponseType>(serr->message);
            return;
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

} // namespace api::tester::handlers
