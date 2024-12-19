#include <sstream>

#include <eMessages/tester.pb.h>
#include <router/iapi.hpp>

#include <api/adapter/adapter.hpp>
#include <api/adapter/helpers.hpp>
#include <api/tester/handlers.hpp>

namespace api::tester::handlers
{
namespace eTester = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;
using namespace adapter::helpers;

template<typename RequestType>
using TesterAndRequest = std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>; ///< Tester and request

namespace
{

eTester::Sync getHashSatus(const ::router::test::Entry& entry,
                           const std::weak_ptr<api::policy::IPolicy>& wPolicyManager)
{
    auto policyManager = wPolicyManager.lock();
    if (!policyManager)
    {
        return eTester::Sync::SYNC_UNKNOWN;
    }

    auto resPolicy = policyManager->getHash(entry.policy());
    if (base::isError(resPolicy))
    {
        return eTester::Sync::ERROR;
    }

    return base::getResponse(resPolicy) == entry.hash() ? eTester::Sync::UPDATED : eTester::Sync::OUTDATED;
}

/**
 * @brief Transform a router::test::Entry to a eTester::Session
 *
 * @param entry Entry to transform
 * @param wPolicyManager Policy manager to get the policy hash
 * @return eTester::Session
 */
eTester::Session toSession(const ::router::test::Entry& entry,
                           const std::weak_ptr<api::policy::IPolicy>& wPolicyManager)
{
    eTester::Session session;
    session.set_name(entry.name());
    session.set_policy(entry.policy().fullName());
    session.set_lifetime(static_cast<uint32_t>(entry.lifetime()));
    if (entry.description().has_value())
    {
        session.mutable_description()->assign(entry.description().value());
    }

    eTester::State state = ::router::env::State::ENABLED == entry.status()    ? eTester::State::ENABLED
                           : ::router::env::State::DISABLED == entry.status() ? eTester::State::DISABLED
                                                                              : eTester::State::STATE_UNKNOWN;

    session.set_policy_sync(getHashSatus(entry, wPolicyManager));
    session.set_entry_status(state);
    session.set_last_use(static_cast<uint32_t>(entry.lastUse()));
    return session;
}

/**
 * @brief Filter the assets of a policy by namespaces and return them in a set of strings
 * or the error response
 *
 * @tparam RequestType
 * @tparam ResponseType
 * @param eRequest Request to get namespaces and policy name
 * @param wStore Store to use to get the namespaces of the assets
 * @param tester Tester to use to get the assets of the policy
 * @return std::variant<httplib::Response, std::unordered_set<std::string>>
 */
template<typename RequestType, typename ResponseType>
auto getNsFilterAssets(const RequestType& eRequest,
                       const std::weak_ptr<store::IStoreReader>& wStore,
                       const std::shared_ptr<::router::ITesterAPI>& tester)
    -> std::variant<httplib::Response, std::unordered_set<std::string>>
{
    // Validate the store
    auto store = wStore.lock();
    if (!store)
    {
        return adapter::internalErrorResponse<ResponseType>("Error: Store is not initialized");
    }

    // Get namespaces
    std::vector<std::string> namespaces {};
    for (const auto& ns : eRequest.namespaces())
    {
        namespaces.push_back(ns);
    }
    if (namespaces.empty())
    {
        return adapter::userErrorResponse<ResponseType>("Error: Namespaces parameter is required");
    }

    // Get all assets of the running policy
    auto resPolicyAssets = tester->getAssets(eRequest.name());
    if (base::isError(resPolicyAssets))
    {
        return adapter::userErrorResponse<ResponseType>(base::getError(resPolicyAssets).message);
    }
    auto& policyAssets = base::getResponse(resPolicyAssets);

    // Filter assets by namespace, and store them in a set
    std::unordered_set<std::string> assets {};
    for (const auto& asset : policyAssets)
    {
        auto assetNamespace = store->getNamespace(asset);
        if (!assetNamespace)
        {
            return adapter::userErrorResponse<ResponseType>(fmt::format("Asset {} not found in store", asset));
        }
        if (std::find(namespaces.begin(), namespaces.end(), assetNamespace.value()) != namespaces.end())
        {
            assets.insert(asset);
        }
    }
    return assets;
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

        auto policyName = tryGetProperty<ResponseType, base::Name>(
            true, [&protoSession]() { return base::Name(adapter::getRes(protoSession).policy()); }, "policy", "name");
        if (adapter::isError(policyName))
        {
            res = adapter::getErrorResp(policyName);
            return;
        }

        // Add the session
        ::router::test::EntryPost entryPost(
            protoReq.session().name(), adapter::getRes(policyName), protoReq.session().lifetime());

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
                                 const std::shared_ptr<api::policy::IPolicy>& policy)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wPolicyManager = std::weak_ptr<api::policy::IPolicy>(policy)](const auto& req, auto& res)
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

        auto policy = wPolicyManager.lock();
        if (!policy)
        {
            res = adapter::internalErrorResponse<ResponseType>("Error: Policy Manager is not initialized");
            return;
        }

        // Get the session
        auto entry = tester->getTestEntry(protoReq.name());
        if (base::isError(entry))
        {
            return;
        }

        ResponseType eResponse;
        eResponse.mutable_session()->CopyFrom(toSession(base::getResponse(entry), wPolicyManager));
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
                               const std::shared_ptr<api::policy::IPolicy>& policy)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wPolicyManager = std::weak_ptr<api::policy::IPolicy>(policy)](const auto& req, auto& res)
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
            eResponse.add_sessions()->CopyFrom(toSession(entry, wPolicyManager));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        res = adapter::userResponse(eResponse);
    };
}

adapter::RouteHandler runPost(const std::shared_ptr<::router::ITesterAPI>& tester,
                              const std::shared_ptr<store::IStoreReader>& store,
                              const event::protocol::ProtocolHandler& protocolHandler)
{
    return [wTester = std::weak_ptr<::router::ITesterAPI>(tester),
            wStore = std::weak_ptr<store::IStoreReader>(store),
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
            auto resFilteredAssets = getNsFilterAssets<RequestType, ResponseType>(protoReq, wStore, tester);
            if (std::holds_alternative<httplib::Response>(resFilteredAssets))
            {
                res = std::get<httplib::Response>(resFilteredAssets);
                return;
            }
            auto& filteredAssets = std::get<std::unordered_set<std::string>>(resFilteredAssets);

            if (protoReq.asset_trace_size() == 0)
            {
                assetToTrace = std::move(filteredAssets);
            }
            else // If eRequest.assets() has assets, then only those assets should be traced
            {
                std::unordered_set<std::string> requestAssets {};
                for (const auto& asset : protoReq.asset_trace())
                {
                    if (filteredAssets.find(asset) == filteredAssets.end())
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
        auto ndJsonEvents = protoReq.ndjson_event();
        std::queue<base::Event> events;
        try
        {
            events = protocolHandler(std::move(ndJsonEvents));
        }
        catch (const std::exception& e)
        {
            res = adapter::userErrorResponse<ResponseType>(fmt::format("Error parsing events: {}", e.what()));
            return;
        }

        if (events.size() != 1)
        {
            res = adapter::userErrorResponse<ResponseType>(
                fmt::format("Can only test one event at a time, but got {}", events.size()));
        }

        // Run the test
        auto opt = ::router::test::Options(traceLevel, assetToTrace, protoReq.name());

        auto responseCallback = [&res](base::RespOrError<::router::test::Output>&& output)
        {
            ResponseType eResponse {};
            if (base::isError(output))
            {
                res = adapter::userErrorResponse<ResponseType>("Error running test: " + base::getError(output).message);
                return;
            }
            eResponse.mutable_result()->CopyFrom(fromOutput(base::getResponse(output)));
            eResponse.set_status(eEngine::ReturnStatus::OK);
            res = adapter::userResponse(eResponse);
        };

        auto error = tester->ingestTest(std::move(events.front()), opt, responseCallback);
        if (error)
        {
            res = adapter::userErrorResponse<ResponseType>(error.value().message);
            return;
        }
    };
}

} // namespace api::tester::handlers
