#include <sstream>

#include <eMessages/tester.pb.h>
#include <router/iapi.hpp>

#include <api/adapter/adapter.hpp>
#include <api/adapter/helpers.hpp>
#include <api/tester/handlers.hpp>

#include <base/hostInfo.hpp>

namespace api::tester::handlers
{
namespace eTester = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;
using namespace adapter::helpers;

template<typename RequestType>
using TesterAndRequest = std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>; ///< Tester and request

namespace
{

eTester::Sync getHashStatus(const ::router::test::Entry& entry, const std::weak_ptr<cm::store::ICMStore>& wStore)
{
    auto store = wStore.lock();
    if (!store)
    {
        return eTester::Sync::SYNC_UNKNOWN;
    }

    std::string hash;
    try
    {
        auto nsId = store->getNSReader(entry.namespaceId());
        hash = nsId->getPolicy().getHash();
    }
    catch(const std::exception& e)
    {
        return eTester::Sync::ERROR;
    }

    return hash == entry.hash() ? eTester::Sync::UPDATED : eTester::Sync::OUTDATED;
}

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

    session.set_namespace_sync(getHashStatus(entry, wStore));
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

    // Set event
    result.mutable_output()->assign(output.event()->str());

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

adapter::RouteHandler sessionGet(const std::shared_ptr<::router::ITesterAPI>& tester, const std::shared_ptr<cm::store::ICMStore>& store)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester), wStore = std::weak_ptr<cm::store::ICMStore>(store)](const auto& req, auto& res)
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

adapter::RouteHandler tableGet(const std::shared_ptr<::router::ITesterAPI>& tester, const std::shared_ptr<cm::store::ICMStore>& store)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester), wStore = std::weak_ptr<cm::store::ICMStore>(store)](const auto& req, auto& res)
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
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            protocolHandler](const auto& req, auto& res)
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
        const auto hostInfo = base::hostInfo::toJson();
        try
        {
            event = protocolHandler(protoReq.event(), hostInfo);
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

        futureResult.wait_for(std::chrono::seconds(5));
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

} // namespace api::tester::handlers
