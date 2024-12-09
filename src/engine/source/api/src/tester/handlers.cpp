#include <sstream>

#include <eMessages/tester.pb.h>
#include <router/iapi.hpp>

#include <api/adapter.hpp>
#include <api/tester/handlers.hpp>

namespace api::tester::handlers
{
namespace eTester = ::com::wazuh::api::engine::tester;
namespace eEngine = ::com::wazuh::api::engine;

using api::adapter::genericError;
using api::adapter::genericSuccess;

template<typename RequestType>
using TesterAndRequest = std::pair<std::shared_ptr<::router::ITesterAPI>, RequestType>; ///< Tester and request

namespace
{

/**
 * @brief Get the request, validate it and return the tester and the request
 * or the error response
 *
 * @tparam RequestType Type of the request
 * @tparam ResponseType Type of the response
 * @param wRequest Request to validate
 * @param wTester Tester to use
 * @return std::variant<api::wpResponse, TesterAndRequest<RequestType>>
 */
template<typename RequestType, typename ResponseType>
std::variant<api::wpResponse, TesterAndRequest<RequestType>>
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
        return genericError<ResponseType>("Tester is not available");
    }

    return std::make_pair(tester, std::get<RequestType>(res));
}

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
 * @return std::variant<api::wpResponse, std::unordered_set<std::string>>
 */
template<typename RequestType, typename ResponseType>
auto getNsFilterAssets(const RequestType& eRequest,
                       const std::weak_ptr<store::IStoreReader>& wStore,
                       const std::shared_ptr<::router::ITesterAPI>& tester)
    -> std::variant<api::wpResponse, std::unordered_set<std::string>>
{
    // Validate the store
    auto store = wStore.lock();
    if (!store)
    {
        return genericError<ResponseType>("Store is not available");
    }

    // Get namespaces
    std::vector<std::string> namespaces {};
    for (const auto& ns : eRequest.namespaces())
    {
        namespaces.push_back(ns);
    }
    if (namespaces.empty())
    {
        return genericError<ResponseType>("Namespaces parameter is required");
    }

    // Get all assets of the running policy
    auto resPolicyAssets = tester->getAssets(eRequest.name());
    if (base::isError(resPolicyAssets))
    {
        return genericError<ResponseType>(base::getError(resPolicyAssets).message);
    }
    auto& policyAssets = base::getResponse(resPolicyAssets);

    // Filter assets by namespace, and store them in a set
    std::unordered_set<std::string> assets {};
    for (const auto& asset : policyAssets)
    {
        auto assetNamespace = store->getNamespace(asset);
        if (!assetNamespace)
        {
            return genericError<ResponseType>(fmt::format("Asset {} not found in store", asset));
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

api::HandlerSync sessionPost(const std::weak_ptr<::router::ITesterAPI>& tester)
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
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

        if (!eRequest.has_session())
        {
            return genericError<ResponseType>("Session parameter is required");
        }

        // Create the query
        base::Name policy;
        try
        {
            policy = base::Name(eRequest.session().policy());
        }
        catch (const std::exception& e)
        {
            return genericError<ResponseType>(fmt::format("Invalid policy for session: {}", e.what()));
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
            return genericError<ResponseType>(fmt::format("Error creating session: {}", error.value().message));
        }
        return genericSuccess<ResponseType>();
    };
}

api::HandlerSync sessionDelete(const std::weak_ptr<::router::ITesterAPI>& tester)
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
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

        // Delete the session
        auto error = tester->deleteTestEntry(eRequest.name());
        if (error)
        {
            return genericError<ResponseType>(fmt::format("Error deleting session: {}", error.value().message));
        }
        return genericSuccess<ResponseType>();
    };
}

api::HandlerSync sessionGet(const std::weak_ptr<::router::ITesterAPI>& tester,
                            const std::weak_ptr<api::policy::IPolicy>& policy)
{
    return [wTester = tester, wPolicyManager = policy](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::SessionGet_Request;
        using ResponseType = eTester::SessionGet_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

        // Get the session
        auto entry = tester->getTestEntry(eRequest.name());
        if (base::isError(entry))
        {
            return genericError<ResponseType>(fmt::format("Error getting session: {}", base::getError(entry).message));
        }

        // Create the response
        ResponseType eResponse;
        eResponse.mutable_session()->CopyFrom(toSession(base::getResponse(entry), wPolicyManager));
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerSync sessionReload(const std::weak_ptr<::router::ITesterAPI>& tester)
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
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

        // Reload the session
        auto error = tester->reloadTestEntry(eRequest.name());
        if (error)
        {
            return genericError<ResponseType>(fmt::format("Error reloading session: {}", error.value().message));
        }
        return genericSuccess<ResponseType>();
    };
}

api::HandlerSync tableGet(const std::weak_ptr<::router::ITesterAPI>& tester,
                          const std::weak_ptr<api::policy::IPolicy>& policy)
{
    return [wTester = tester, wPolicyManager = policy](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTester::TableGet_Request;
        using ResponseType = eTester::TableGet_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

        // Get the table
        auto entries = tester->getTestEntries();

        // Create the response
        ResponseType eResponse;
        for (const auto& entry : entries)
        {
            eResponse.add_sessions()->CopyFrom(toSession(entry, wPolicyManager));
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);
        return ::api::adapter::toWazuhResponse<ResponseType>(eResponse);
    };
}

api::HandlerAsync runPost(const std::weak_ptr<::router::ITesterAPI>& tester,
                          const std::weak_ptr<store::IStoreReader>& store)
{
    return [wTester = tester, wStore = store](const api::wpRequest& wRequest,
                                              std::function<void(const api::wpResponse&)> callbackFn)
    {
        using RequestType = eTester::RunPost_Request;
        using ResponseType = eTester::RunPost_Response;

        // Validate request
        auto res = getRequest<RequestType, ResponseType>(wRequest, wTester);
        if (std::holds_alternative<api::wpResponse>(res))
        {
            callbackFn(std::get<api::wpResponse>(res));
            return;
        }
        auto& [tester, eRequest] = std::get<TesterAndRequest<RequestType>>(res);

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
            auto resFilteredAssets = getNsFilterAssets<RequestType, ResponseType>(eRequest, wStore, tester);
            if (std::holds_alternative<api::wpResponse>(resFilteredAssets))
            {
                callbackFn(std::get<api::wpResponse>(resFilteredAssets));
                return;
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
                        callbackFn(genericError<ResponseType>(fmt::format("Asset {} not found in store", asset)));
                        return;
                    }
                    requestAssets.insert(asset);
                }
                assetToTrace = std::move(requestAssets);
            }
        }

        // Create The event to test
        std::string eventStr {};
        {
            std::stringstream streamLocation;
            // Escape the ':' character in the location (Wazuh protocol)
            for (const auto& c : eRequest.location())
            {
                if (c == ':')
                {
                    streamLocation << "|:";
                }
                else
                {
                    streamLocation << c;
                }
            }

            eventStr = eRequest.queue() + ":" + streamLocation.str() + ":" + eRequest.message();
        }

        // Run the test
        auto opt = ::router::test::Options(traceLevel, assetToTrace, eRequest.name());

        auto responseCallback = [callbackFn](base::RespOrError<::router::test::Output>&& output)
        {
            ResponseType eResponse {};
            if (base::isError(output))
            {
                eResponse.set_status(eEngine::ReturnStatus::ERROR);
                eResponse.set_error("Error running test: " + base::getError(output).message);
                callbackFn(::api::adapter::toWazuhResponse<ResponseType>(eResponse));
                return;
            }
            eResponse.mutable_result()->CopyFrom(fromOutput(base::getResponse(output)));
            eResponse.set_status(eEngine::ReturnStatus::OK);
            callbackFn(::api::adapter::toWazuhResponse<ResponseType>(eResponse));
        };

        auto error = tester->ingestTest(eventStr, opt, responseCallback);
        if (error)
        {
            callbackFn(genericError<ResponseType>(error.value().message));
        }
    };
}

void registerHandlers(const std::weak_ptr<::router::ITesterAPI>& tester,
                      const std::weak_ptr<store::IStoreReader>& store,
                      const std::weak_ptr<api::policy::IPolicy>& policy,
                      std::shared_ptr<api::Api> api)
{
    if (!(api->registerHandler("tester.session/post", Api::convertToHandlerAsync(sessionPost(tester)))
          && api->registerHandler("tester.session/delete", Api::convertToHandlerAsync(sessionDelete(tester)))
          && api->registerHandler("tester.session/get", Api::convertToHandlerAsync(sessionGet(tester, policy)))
          && api->registerHandler("tester.session/reload", Api::convertToHandlerAsync(sessionReload(tester)))
          && api->registerHandler("tester.table/get", Api::convertToHandlerAsync(tableGet(tester, policy)))
          // && api->registerHandler("tester.table/delete", tableDelete(tester))
          && api->registerHandler("tester.run/post", runPost(tester, store))))
    {
        throw std::runtime_error("Tester API handlers registration failed");
    }
}

} // namespace api::tester::handlers
