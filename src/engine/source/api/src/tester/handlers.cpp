#include <eMessages/tester.pb.h>
#include <router/iapi.hpp>

#include <api/adapter.hpp>
#include <api/tester/handlers.hpp>

namespace api::tester::handlers
{
namespace eTester = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;

namespace
{

template<typename RequestType, typename ResponseType>
std::variant<api::wpResponse, std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>
getRequest(const api::wpRequest& wRequest, const std::weak_ptr<::router::ITesterAPI>& wTester)
{
    auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);
    // validate the request
    if (std::holds_alternative<api::wpResponse>(res))
    {
        return std::move(std::get<api::wpResponse>(res));
    }

    // validate the router
    auto tester = wTester.lock();
    if (!tester)
    {
        return ::api::adapter::genericError<ResponseType>("Tester is not available");
    }

    return std::make_pair(tester, std::get<RequestType>(res));
}

eTester::Session toSession(const ::router::test::Entry& entry)
{
    eTester::Session session;
    session.set_name(entry.name());
    session.set_policy(entry.policy().fullName());
    session.set_lifetime(entry.lifetime());
    if (entry.description().has_value())
    {
        session.mutable_description()->assign(entry.description().value());
    }
    // TODO: set the status and sync
    session.set_policy_sync(eTester::Sync::SYNC_UNKNOWN);
    session.set_entry_status(eTester::State::STATE_UNKNOWN);
    session.set_last_use(entry.lastUse());
    return session;
}

template<typename RequestType, typename ResponseType>
auto getAssetsForTrace(const RequestType& eRequest,
                       const std::weak_ptr<store::IStoreReader>& wStore,
                       const std::shared_ptr<::router::ITesterAPI>& tester)
    -> std::variant<api::wpResponse, std::unordered_set<std::string>>
{
    // Validate the store
    auto store = wStore.lock();
    if (!store)
    {
        return ::api::adapter::genericError<ResponseType>("Store is not available");
    }

    // Get namespaces
    std::vector<std::string> namespaces {};
    for (const auto& ns : eRequest.namespaces())
    {
        namespaces.push_back(ns);
    }
    if (namespaces.empty())
    {
        return ::api::adapter::genericError<ResponseType>("Namespaces parameter is required");
    }

    // Get all assets of the running policy
    auto resPolicyAssets = tester->getAssets(eRequest.name());
    if (base::isError(resPolicyAssets))
    {
        return ::api::adapter::genericError<ResponseType>(base::getError(resPolicyAssets).message);
    }
    auto& policyAssets = base::getResponse(resPolicyAssets);

    // Filter assets by namespace, and store them in a set
    std::unordered_set<std::string> assets {};
    for (const auto& asset : policyAssets)
    {
        auto assetNamespace = store->getNamespace(asset);
        if (!assetNamespace)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format("Asset {} not found in store", asset));
        }
        if (std::find(namespaces.begin(), namespaces.end(), assetNamespace.value()) != namespaces.end())
        {
            assets.insert(asset);
        }
    }
    return assets;
}

eTester::Result fromOutput(const ::router::test::Output& output)
{
    eTester::Result result {};

    // Set event
    auto resProtoEvent = eMessage::eMessageFromJson<google::protobuf::Value>(output.event()->str());
    if (std::holds_alternative<base::Error>(resProtoEvent))
    {
        throw std::runtime_error {std::get<base::Error>(resProtoEvent).message}; // Should never happen
    }
    auto& protoEvent = std::get<google::protobuf::Value>(resProtoEvent);
    result.mutable_output()->CopyFrom(protoEvent);

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

api::Handler sessionPost(const std::weak_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = tester](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::SessionPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        if (!eRequest.has_session())
        {
            return ::api::adapter::genericError<ResponseType>("Session parameter is required");
        }

        // Create the query
        base::Name policy;
        try
        {
            policy = base::Name(eRequest.session().policy());
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format("Invalid policy for session: {}", e.what()));
        }

        ::router::test::EntryPost entry(eRequest.session().name(), policy, eRequest.session().lifetime());
        if (eRequest.session().has_description() && !eRequest.session().description().empty())
        {
            entry.description(eRequest.session().description());
        }

        // Create the session
        auto error = tester->postTestEntry(entry);
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Error creating session: {}", error.value().message));
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler sessionDelete(const std::weak_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = tester](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::SessionDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        // Delete the session
        auto error = tester->deleteTestEntry(eRequest.name());
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Error deleting session: {}", error.value().message));
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler sessionGet(const std::weak_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = tester](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::SessionGet_Request;
        using ResponseType = eTester::SessionGet_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        // Get the session
        auto entry = tester->getTestEntry(eRequest.name());
        if (base::isError(entry))
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Error getting session: {}", base::getError(entry).message));
        }

        // Create the response
        ResponseType eResponse;
        eResponse.mutable_session()->CopyFrom(toSession(base::getResponse(entry)));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler sessionReload(const std::weak_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = tester](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::SessionReload_Request;
        using ResponseType = eEngine::GenericStatus_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        // Reload the session
        auto error = tester->reloadTestEntry(eRequest.name());
        if (error)
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Error reloading session: {}", error.value().message));
        }
        return ::api::adapter::genericSuccess<ResponseType>();
    };
}

api::Handler tableGet(const std::weak_ptr<::router::ITesterAPI>& tester)
{
    return [wTester = tester](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::TableGet_Request;
        using ResponseType = eTester::TableGet_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        // Get the table
        auto entries = tester->getTestEntries();

        // Create the response
        ResponseType eResponse;
        for (const auto& entry : entries)
        {
            eResponse.add_sessions()->CopyFrom(toSession(entry));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::Handler runPost(const std::weak_ptr<::router::ITesterAPI>& tester, const std::weak_ptr<store::IStoreReader>& store)
{
    return [wTester = tester, wStore = store](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::RunPost_Request;
        using ResponseType = eTester::RunPost_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>>(res);

        // Checks params
        using OTraceLavel = ::router::test::Options::TraceLevel;
        OTraceLavel traceLevel = eRequest.trace_level() == eTester::TraceLevel::NONE         ? OTraceLavel::NONE
                                 : eRequest.trace_level() == eTester::TraceLevel::ASSET_ONLY ? OTraceLavel::ASSET_ONLY
                                                                                             : OTraceLavel::ALL;

        // Find the list of assets to trace
        std::unordered_set<std::string> assetToTrace {};
        if (traceLevel != OTraceLavel::NONE)
        {
            // Get the assets of the policy filtered by namespaces
            auto resFilteredAssets = getAssetsForTrace<RequestType, ResponseType>(eRequest, wStore, tester);
            if (std::holds_alternative<api::wpResponse>(resFilteredAssets))
            {
                return std::move(std::get<api::wpResponse>(resFilteredAssets));
            }
            auto& filteredAssets = std::get<std::unordered_set<std::string>>(resFilteredAssets);

            if (eRequest.asset_trace_size() == 0)
            {
                assetToTrace = std::move(filteredAssets);
            }
            else // If eRequest.assets() has assets, then only those assets should be traced
            {
                std::unordered_set<std::string> requestAssets {};
                for (const auto& asset : eRequest.asset_trace())
                {
                    if (filteredAssets.find(asset) == filteredAssets.end())
                    {
                        return ::api::adapter::genericError<ResponseType>(
                            fmt::format("Asset {} not found in store", asset));
                    }
                    requestAssets.insert(asset);
                }
                assetToTrace = std::move(requestAssets);
            }
        }

        // Create The event to test
        std::string eventStr {};
        {
            auto location = eRequest.location();
            size_t pos;
            while ((pos = location.find(':')) != std::string::npos)
            {
                location.replace(pos, 1, "|:");
            }
            eventStr = eRequest.queue() + ":" + location + ":" + eRequest.message();
        }

        // Run the test
        try
        {
            auto opt = ::router::test::Options(traceLevel, assetToTrace, eRequest.name());
            auto result = tester->ingestTest(eventStr, opt);

            // Create the response
            auto r = result.wait_for(std::chrono::milliseconds(100));
            if (r == std::future_status::ready)
            {
                auto output = result.get();
                if (base::isError(output))
                {
                    return ::api::adapter::genericError<ResponseType>("Error running test: "
                                                                      + base::getError(output).message);
                }
                ResponseType eResponse {};
                eResponse.mutable_result()->CopyFrom(fromOutput(base::getResponse(output)));
                eResponse.set_status(eEngine::ReturnStatus::OK);
                return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);

            }
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format("Error running test: {}", e.what()));
        }

        return ::api::adapter::genericError<ResponseType>("Error running test: Timeout");
    };
}

void registerHandlers(const std::weak_ptr<::router::ITesterAPI>& tester,
                      const std::weak_ptr<store::IStoreReader>& store,
                      std::shared_ptr<api::Api> api)
{
    if (!(api->registerHandler("tester.session/post", sessionPost(tester))
          && api->registerHandler("tester.session/delete", sessionDelete(tester))
          && api->registerHandler("tester.session/get", sessionGet(tester))
          && api->registerHandler("tester.session/reload", sessionReload(tester))
          && api->registerHandler("tester.table/get", tableGet(tester))
          // && api->registerHandler("tester.table/delete", tableDelete(tester))
          && api->registerHandler("tester.run/post", runPost(tester, store))))
    {
        throw std::runtime_error("Tester API handlers registration failed");
    }
}

} // namespace api::tester::handlers