#include "api/test/handlers.hpp"

#include <algorithm>
#include <optional>
#include <regex>
#include <string>

#include <fmt/format.h>

#include <eMessages/eMessage.h>
#include <eMessages/test.pb.h>

#include <api/adapter.hpp>
#include <api/catalog/resource.hpp>
#include <json/json.hpp>

namespace
{
// TODO: Add private namespaces to store
constexpr auto TEST_NAMESPACE = "__test__"; ///< Test namespace

using namespace api::sessionManager;

using api::catalog::Catalog;
using api::catalog::Resource;

using api::adapter::fromWazuhRequest;
using api::adapter::genericError;
using api::adapter::toWazuhResponse;

using router::Router;
using router::TEST_ROUTE_MAXIMUM_PRIORITY;
using router::TEST_ROUTE_MINIMUM_PRIORITY;

constexpr uint8_t TEST_DEFAULT_PROTOCOL_QUEUE {1}; ///< Default protocol queue
constexpr uint8_t TEST_MIN_PROTOCOL_QUEUE {0};     ///< Minimum protocol queue
constexpr uint8_t TEST_MAX_PROTOCOL_QUEUE {255};   ///< Maximum protocol queue

constexpr auto API_SESSIONS_DATA_FORMAT = R"({"name":"","id":"","creationdate":0,"lifespan":0,"description":"",)"
                                          R"("filtername":"","policyname":"","routename":""})"; ///< API session data
                                                                                                ///< format

constexpr auto ASSET_NAME_FIELD_FORMAT = R"("name":"{}")";    ///< JSON name field format, where '{}' is the asset name
constexpr auto FILTER_CONTENT_FORMAT =
    R"({{"name": "{}", "check":[{{"TestSessionID":{}}}]}})"; ///< Filter content format
constexpr auto TEST_FILTER_FULL_NAME_FORMAT = "filter/{}_filter/0"; ///< Filter name format, '{}' is the session name
constexpr auto TEST_POLICY_FULL_NAME_FORMAT = "policy/{}_policy/0"; ///< Policy name format, '{}' is the session name
constexpr auto TEST_ROUTE_NAME_FORMAT = "{}_route";                 ///< Route name format, '{}' is the session name
constexpr auto TEST_FIELD_TO_CHECK_IN_FILTER = "TestSessionID";    ///< Field to check in filter.
constexpr auto TEST_DEFAULT_PROTOCOL_LOCATION = "api.test";         ///< Default protocol location

constexpr auto FILTER_NOT_REMOVED_MSG = "Filter '{}' could not be removed from the catalog: {}";
constexpr auto POLICY_NOT_REMOVED_MSG = "Policy '{}' could not be removed from the catalog: {}";
constexpr auto ROUTE_NOT_REMOVED_MSG = "Route '{}' could not be removed from the router: {}";
constexpr auto SESSION_NOT_FOUND_MSG = "Session '{}' could not be found";
constexpr auto SESSION_NOT_REMOVED_MSG = "Session '{}' could not be removed from the sessions manager";

constexpr auto WAZUH_EVENT_FORMAT = "{}:{}:{}"; ///< Wazuh event format

constexpr auto DEFAULT_TIMEOUT {1000};

auto getOutputCallbackFn(std::shared_ptr<api::sessionManager::OutputTraceDataSync> dataSync)
    -> std::function<void(const rxbk::RxEvent&)>
{
    return [dataSync](const rxbk::RxEvent& event)
    {
        std::stringstream output;
        output << event->payload()->prettyStr() << std::endl;
        dataSync->m_output = output.str();

        {
            std::unique_lock<std::mutex> lock(dataSync->m_sync);
            if (dataSync->m_hasTimedout)
            {
                dataSync->m_hasTimedout = false;
                dataSync->m_output.clear();
                dataSync->m_history.clear();
                dataSync->m_trace.clear();
            }
            else
            {
                dataSync->m_processedData = true;
            }
        }

        dataSync->m_cvData.notify_all();
    };
}

auto getTraceCallbackFn(std::shared_ptr<api::sessionManager::OutputTraceDataSync> dataSync)
    -> std::function<void(const std::string&)>
{
    return [dataSync](const std::string& trace)
    {
        constexpr auto opPatternTrace = R"(\[([^\]]+)\] \[condition\]:(.+))";
        const std::regex opRegex(opPatternTrace);
        std::smatch match;
        if (std::regex_search(trace, match, opRegex))
        {
            dataSync->m_history.emplace_back(std::make_pair(match[1].str(), match[2].str()));
        }
        constexpr auto opPatternTraceVerbose = R"(^\[([^\]]+)\] (.+))";
        const std::regex opRegexVerbose(opPatternTraceVerbose);
        std::smatch matchVerbose;
        if (std::regex_search(trace, matchVerbose, opRegexVerbose))
        {
            auto traceStream = std::make_shared<std::stringstream>();
            *traceStream << trace;
            dataSync->m_trace[matchVerbose[1].str()].push_back(traceStream);
        }
    };
}

using namespace api::test::handlers;
std::variant<std::tuple<std::string, std::string>, base::Error>
getData(std::shared_ptr<api::sessionManager::OutputTraceDataSync> dataSync,
        DebugMode debugMode,
        const std::string& assetTrace)
{
    // Wait until callbacks have been executed
    {
        std::unique_lock<std::mutex> lock(dataSync->m_sync);
        if (!dataSync->m_cvData.wait_for(lock, std::chrono::milliseconds(DEFAULT_TIMEOUT), [dataSync] { return dataSync->m_processedData; }))
        {
            dataSync->m_hasTimedout = true;
            return base::Error {"The maximum time to process the event has expired"};
        }
        dataSync->m_processedData = false;
    }

    auto trace = json::Json {R"({})"};
    if (DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS == debugMode)
    {
        if (dataSync->m_history.empty())
        {
            dataSync->m_trace.clear();
            return base::Error {fmt::format(
                "Policy '{}' has not been configured for trace tracking and output subscription", dataSync->m_asset)};
        }

        for (const auto& [asset, condition] : dataSync->m_history)
        {
            if (dataSync->m_trace.find(asset) == dataSync->m_trace.end())
            {
                dataSync->m_trace.clear();
                return base::Error {fmt::format(
                    "Policy '{}' has not been configured for trace tracking and output subscription", dataSync->m_asset)};
            }

            std::set<std::string> uniqueTraces; // Set for warehouses single traces
            for (const auto& traceStream : dataSync->m_trace[asset])
            {
                uniqueTraces.insert(traceStream->str()); // Insert unique traces in the set
            }

            std::stringstream combinedTrace;
            for (const auto info : uniqueTraces)
            {
                combinedTrace << info;
            }

            if (assetTrace.empty() || assetTrace == asset)
            {
                trace.setString(combinedTrace.str(), std::string("/") + asset);
            }
            else
            {
                trace.setString(condition, std::string("/") + asset);
            }
        }

        dataSync->m_trace.clear();
    }
    else if (DebugMode::OUTPUT_AND_TRACES == debugMode)
    {
        if (dataSync->m_history.empty())
        {
            dataSync->m_trace[dataSync->m_asset].clear();
            return base::Error {fmt::format(
                "Policy '{}' has not been configured for trace tracking and output subscription", dataSync->m_asset)};
        }

        for (const auto& [asset, condition] : dataSync->m_history)
        {
            trace.setString(condition, std::string("/") + asset);
        }
        dataSync->m_trace.clear();
    }

    dataSync->m_trace.clear();
    // TODO: Add a method to verify that a json is empty
    if (R"({})" == trace.prettyStr())
    {
        dataSync->m_trace[dataSync->m_asset].clear();
        return std::make_tuple(dataSync->m_output, std::string());
    }
    return std::make_tuple(dataSync->m_output, trace.prettyStr());
}

} // namespace

namespace api::test::handlers
{

namespace eEngine = ::com::wazuh::api::engine;
namespace eTest = ::com::wazuh::api::engine::test;

// TODO: Consider the chance of adapting the session to incorporate methods to be imported and exported as Json
std::optional<base::Error> loadSessionsFromJson(const std::shared_ptr<SessionManager>& sessionManager,
                                                const std::shared_ptr<Catalog>& catalog,
                                                const std::shared_ptr<Router>& router,
                                                const json::Json& jsonSessions)
{

    if (!jsonSessions.isArray())
    {
        return base::Error {"Invalid sessions JSON format"};
    }

    for (const auto& jsonSession : jsonSessions.getArray().value_or(std::vector<json::Json> {}))
    {
        if (!jsonSession.isObject())
        {
            return base::Error {"Invalid session JSON format"};
        }

        const auto creationDate = jsonSession.getInt("/creationdate");
        const auto description = jsonSession.getString("/description");
        const auto filterName = jsonSession.getString("/filtername");
        const auto lifespan = jsonSession.getInt("/lifespan");
        const auto policyName = jsonSession.getString("/policyname");
        const auto routeName = jsonSession.getString("/routename");
        const auto sessionID = jsonSession.getInt("/id");
        const auto sessionName = jsonSession.getString("/name");

        std::string missingFields;
        if (!sessionName.has_value())
        {
            missingFields += "/name, ";
        }
        if (!sessionID.has_value())
        {
            missingFields += "/id, ";
        }
        if (!creationDate.has_value())
        {
            missingFields += "/creationDate, ";
        }
        if (!lifespan.has_value())
        {
            missingFields += "/lifespan, ";
        }
        if (!description.has_value())
        {
            missingFields += "/description, ";
        }
        if (!filterName.has_value())
        {
            missingFields += "/filtername, ";
        }
        if (!policyName.has_value())
        {
            missingFields += "/policyname, ";
        }
        if (!routeName.has_value())
        {
            missingFields += "/routename, ";
        }
        if (!missingFields.empty())
        {
            missingFields = missingFields.substr(0, missingFields.size() - 2); // Remove the last ", "
            return base::Error {"An error occurred while loading the sessions. The following fields are missing: "
                                + missingFields};
        }

        auto&& createSessionError = sessionManager->createSession(sessionName.value(),
                                                                  policyName.value(),
                                                                  filterName.value(),
                                                                  routeName.value(),
                                                                  sessionID.value(),
                                                                  lifespan.value(),
                                                                  description.value(),
                                                                  creationDate.value());
        if (createSessionError.has_value())
        {
            return createSessionError;
        }

        // Suscribe to output and Trace
        auto dataSync = sessionManager->getSession(sessionName.value())->getDataSync();
        const auto subscriptionError = router->subscribeOutputAndTraces(
            getOutputCallbackFn(dataSync), getTraceCallbackFn(dataSync), policyName.value());
        if (subscriptionError.has_value())
        {
            std::string errorMsg {subscriptionError.value().message};

            if (!sessionManager->deleteSession(sessionName.value()))
            {
                errorMsg += std::string(". ") + fmt::format(SESSION_NOT_REMOVED_MSG, sessionName.value());
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName.value());
            if (deleteRouteError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName.value(), deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName.value());
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    std::string(". ")
                    + fmt::format(FILTER_NOT_REMOVED_MSG, filterName.value(), deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName.value());
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    std::string(". ")
                    + fmt::format(POLICY_NOT_REMOVED_MSG, policyName.value(), deletePolicyError.value().message);
            }

            return base::Error {errorMsg};
        }
    }

    return std::nullopt;
}

json::Json getSessionsAsJson(const std::shared_ptr<SessionManager>& sessionManager)
{
    json::Json jsonSessions;
    jsonSessions.setArray();

    auto list = sessionManager->getSessionsList();

    for (auto& sessionName : list)
    {
        const auto session = sessionManager->getSession(sessionName);
        auto jsonSession = json::Json(API_SESSIONS_DATA_FORMAT);

        jsonSession.setInt(static_cast<int>(session->getCreationDate()), "/creationdate");
        jsonSession.setInt(static_cast<int>(session->getLifespan()), "/lifespan");
        jsonSession.setInt(static_cast<int>(session->getSessionID()), "/id");
        jsonSession.setString(session->getDescription(), "/description");
        jsonSession.setString(session->getFilterName(), "/filtername");
        jsonSession.setString(session->getPolicyName(), "/policyname");
        jsonSession.setString(session->getRouteName(), "/routename");
        jsonSession.setString(session->getSessionName(), "/name");

        jsonSessions.appendJson(jsonSession);
    }

    return jsonSessions;
}

std::optional<base::Error> saveSessionsToStore(const std::shared_ptr<SessionManager>& sessionManager,
                                               const std::shared_ptr<store::IStore>& store)
{
    const auto sessionsJson = getSessionsAsJson(sessionManager);
    return store->updateInternalDoc(API_SESSIONS_TABLE_NAME, sessionsJson);
}

inline int32_t getMaximumAvailablePriority(const std::shared_ptr<Router>& router)
{
    // Create a set to store the taken priorities given the table
    std::unordered_set<uint32_t> takenPriorities;

    const auto routerTable = router->getRouteTable();
    for (const auto& [name, priority, filter, policy] : routerTable)
    {
        takenPriorities.insert(priority);
    }

    int32_t maxAvailablePriority {TEST_ROUTE_MAXIMUM_PRIORITY};

    // The condition may be confusing as the actual priority increases while the value decreases
    while (takenPriorities.count(maxAvailablePriority) > 0 && TEST_ROUTE_MINIMUM_PRIORITY >= maxAvailablePriority)
    {
        // If priority is taken, decrease the value (so, increase the priority)
        maxAvailablePriority++;
    }

    return maxAvailablePriority;
}

inline std::optional<base::Error> addAssetToCatalog(const std::shared_ptr<Catalog>& catalog,
                                                    const std::string& assetType,
                                                    const std::string& assetContent)
{
    Resource targetResource;

    std::optional<base::Error> addAssetError;

    try
    {
        targetResource = Resource {base::Name {assetType}, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        addAssetError = std::optional<base::Error> {base::Error {e.what()}};
    }

    // If no error occurred, post the resource
    if (!addAssetError.has_value())
    {
        const auto postResourceError = catalog->postResource(targetResource, TEST_NAMESPACE, assetContent);
        if (postResourceError)
        {
            addAssetError = std::optional<base::Error> {base::Error {postResourceError.value().message}};
        }
    }

    return addAssetError;
}

inline std::optional<base::Error>
addTestFilterToCatalog(const std::shared_ptr<Catalog>& catalog, const std::string& filterName, const uint32_t sessionID)
{
    const auto filterContent = fmt::format(FILTER_CONTENT_FORMAT, filterName, sessionID);
    return addAssetToCatalog(catalog, "filter", filterContent);
}

inline std::optional<base::Error> addTestPolicyToCatalog(const std::shared_ptr<Catalog>& catalog,
                                                         const std::string& sessionName,
                                                         const std::string& policyName)
{
    std::optional<base::Error> addTestPolicyToCatalogError;

    // Build target resource
    Resource targetResource;
    try
    {
        base::Name name {policyName};
        targetResource = Resource {name, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        addTestPolicyToCatalogError = std::optional<base::Error> {base::Error {e.what()}};
    }

    if (!addTestPolicyToCatalogError.has_value())
    {
        // Get the original policy's content
        // TODO implement namespaces
        const auto getResourceResult = catalog->getResource(targetResource);
        if (std::holds_alternative<base::Error>(getResourceResult))
        {
            addTestPolicyToCatalogError = std::optional<base::Error> {std::get<base::Error>(getResourceResult)};
        }
        else
        {
            std::string policyContent {std::get<std::string>(getResourceResult)};

            // Replace the policy's name
            const auto oldJsonNameField = fmt::format(ASSET_NAME_FIELD_FORMAT, policyName);
            const auto newPolicyName = fmt::format(TEST_POLICY_FULL_NAME_FORMAT, sessionName);
            const auto newJsonNameField = fmt::format(ASSET_NAME_FIELD_FORMAT, newPolicyName);
            const auto newPolicyContent =
                policyContent.replace(policyContent.find(oldJsonNameField), oldJsonNameField.size(), newJsonNameField);

            // Add the new policy to the catalog
            addTestPolicyToCatalogError = addAssetToCatalog(catalog, "policy", newPolicyContent);
        }
    }

    return addTestPolicyToCatalogError;
}

inline std::optional<base::Error> deleteAssetFromCatalog(const std::shared_ptr<Catalog>& catalog,
                                                         const std::string& assetName)
{
    std::optional<base::Error> deleteAssetError;

    // Build target resource
    Resource targetResource;
    try
    {
        base::Name name {assetName};
        targetResource = Resource {name, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        deleteAssetError = std::optional<base::Error> {base::Error {e.what()}};
    }

    if (!deleteAssetError.has_value())
    {
        const auto deleteResourceError = catalog->deleteResource(targetResource);
        if (deleteResourceError.has_value())
        {
            const auto error = fmt::format(
                "Asset '{}' could not be removed from the catalog: {}", assetName, deleteResourceError.value().message);
            deleteAssetError = std::optional<base::Error> {base::Error {error}};
        };
    }

    return deleteAssetError;
}

inline std::optional<base::Error> deleteRouteFromRouter(const std::shared_ptr<Router>& router,
                                                        const std::string& routeName)
{
    std::optional<base::Error> deleteRouteFromRouterError;

    try
    {
        router->removeRoute(routeName);
    }
    catch (const std::exception& e)
    {
        deleteRouteFromRouterError = std::optional<base::Error> {base::Error {e.what()}};
    }

    return deleteRouteFromRouterError;
}

inline std::optional<base::Error> handleDeleteSession(const std::shared_ptr<SessionManager>& sessionManager,
                                                      const std::shared_ptr<Router>& router,
                                                      const std::shared_ptr<Catalog>& catalog,
                                                      const std::string& sessionName)
{
    std::string errorMsg {};

    const auto session = sessionManager->getSession(sessionName);
    if (!session.has_value())
    {
        return base::Error {fmt::format(SESSION_NOT_FOUND_MSG, sessionName)};
    }

    const auto deleteRouteError = deleteRouteFromRouter(router, session->getRouteName());
    if (deleteRouteError.has_value())
    {
        errorMsg += fmt::format(ROUTE_NOT_REMOVED_MSG, session->getRouteName(), deleteRouteError.value().message);
    }

    const auto deleteFilterError = deleteAssetFromCatalog(catalog, session->getFilterName());
    if (deleteFilterError.has_value())
    {
        if (!errorMsg.empty())
        {
            errorMsg += ". ";
        }
        errorMsg += fmt::format(FILTER_NOT_REMOVED_MSG, session->getFilterName(), deleteFilterError.value().message);
    }

    const auto deletePolicyError = deleteAssetFromCatalog(catalog, session->getPolicyName());
    if (deletePolicyError.has_value())
    {
        if (!errorMsg.empty())
        {
            errorMsg += ". ";
        }
        errorMsg += fmt::format(POLICY_NOT_REMOVED_MSG, session->getPolicyName(), deletePolicyError.value().message);
    }

    if (!sessionManager->deleteSession(sessionName))
    {
        if (!errorMsg.empty())
        {
            errorMsg += ". ";
        }
        errorMsg += fmt::format(SESSION_NOT_REMOVED_MSG, sessionName);
    }

    return (errorMsg.empty() ? std::nullopt : std::optional<base::Error> {base::Error {errorMsg}});
}

// TODO: consider using a "stack executor" to undo previous operations in case of failure
api::Handler sessionPost(const std::shared_ptr<SessionManager>& sessionManager,
                         const std::shared_ptr<Catalog>& catalog,
                         const std::shared_ptr<Router>& router,
                         const std::shared_ptr<store::IStore>& store)
{
    return [sessionManager, catalog, router, store](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionPost_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        if (!eRequest.has_name())
        {
            return genericError<ResponseType>("Field /name is required");
        }

        if (eRequest.name().empty())
        {
            return genericError<ResponseType>("Field /name cannot be empty");
        }

        const auto& sessionName = eRequest.name();

        // Check if the session name is valid
        for (char c : sessionName)
        {
            if (!std::isalnum(c) && '_' != c)
            {
                return genericError<ResponseType>(fmt::format(
                    "Session name ('{}') can only contain alphanumeric characters and underscores", sessionName));
            }
        }

        // Check if the session already exists
        if (sessionManager->doesSessionExist(sessionName))
        {
            return genericError<ResponseType>(fmt::format("Session '{}' already exists", sessionName));
        }

        // Set up the test session's policy

        // If the policy is not set, use the default policy
        const auto originalPolicyName = eRequest.has_policy() ? eRequest.policy() : DEFAULT_POLICY_FULL_NAME;

        const auto addPolicyError = addTestPolicyToCatalog(catalog, sessionName, originalPolicyName);
        if (addPolicyError.has_value())
        {
            return genericError<ResponseType>(addPolicyError.value().message);
        }
        const auto policyName = fmt::format(TEST_POLICY_FULL_NAME_FORMAT, sessionName);

        // Set up the test session's filter

        // A session ID is obtained, which will be used to create the filter
        const uint32_t sessionID {sessionManager->getNewSessionID()};

        const auto filterName = fmt::format(TEST_FILTER_FULL_NAME_FORMAT, sessionName);

        const auto addFilterError = addTestFilterToCatalog(catalog, filterName, sessionID);
        if (addFilterError.has_value())
        {
            std::string errorMsg {addFilterError.value().message};

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Set up the test session's route

        const auto routeName = fmt::format(TEST_ROUTE_NAME_FORMAT, sessionName);

        // Find the maximum priority that is not already taken (priority is inversely proportional to the value)
        const int32_t maxAvailablePriority = getMaximumAvailablePriority(router);
        if (TEST_ROUTE_MINIMUM_PRIORITY < maxAvailablePriority)
        {
            std::string errorMsg {"There is no available priority"};

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        const auto addRouteError = router->addRoute(routeName, maxAvailablePriority, filterName, policyName);
        if (addRouteError.has_value())
        {
            std::string errorMsg {addRouteError.value().message};

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Create the session

        // If the description is not set, use an empty string
        const std::string description {eRequest.has_description() ? eRequest.description() : ""};
        // If the lifespan is not set, use 0 (no expiration). TODO: review what to do in this case
        const uint32_t lifespan {eRequest.has_lifespan() ? eRequest.lifespan() : 0};

        const auto createSessionError = sessionManager->createSession(
            sessionName, policyName, filterName, routeName, sessionID, lifespan, description);
        if (createSessionError.has_value())
        {
            std::string errorMsg {createSessionError.value().message};

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    std::string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Suscribe to output and Trace
        auto dataSync = sessionManager->getSession(sessionName)->getDataSync();
        const auto subscriptionError =
            router->subscribeOutputAndTraces(getOutputCallbackFn(dataSync), getTraceCallbackFn(dataSync), policyName);
        if (subscriptionError.has_value())
        {
            std::string errorMsg {subscriptionError.value().message};

            if (!sessionManager->deleteSession(sessionName))
            {
                errorMsg += std::string(". ") + fmt::format(SESSION_NOT_REMOVED_MSG, sessionName);
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    std::string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Save the sessions to the store
        const auto saveSessionsToStoreError = saveSessionsToStore(sessionManager, store);
        if (saveSessionsToStoreError.has_value())
        {
            std::string errorMsg {saveSessionsToStoreError.value().message};

            if (!sessionManager->deleteSession(sessionName))
            {
                errorMsg += fmt::format(SESSION_NOT_REMOVED_MSG, sessionName);
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    std::string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg += std::string(". ")
                            + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionGet(const std::shared_ptr<SessionManager>& sessionManager)
{
    return [sessionManager](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionGet_Request;
        using ResponseType = eTest::SessionGet_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        if (!eRequest.has_name())
        {
            return genericError<ResponseType>("Session name is required");
        }

        const auto session = sessionManager->getSession(eRequest.name());
        if (!session.has_value())
        {
            return genericError<ResponseType>(fmt::format(SESSION_NOT_FOUND_MSG, eRequest.name()));
        }

        ResponseType eResponse;

        // TODO: improve creation date representation
        eResponse.mutable_session()->set_name(session->getSessionName());
        eResponse.mutable_session()->set_creation_date(session->getCreationDate());
        eResponse.mutable_session()->set_description(session->getDescription());
        eResponse.mutable_session()->set_filter(session->getFilterName());
        eResponse.mutable_session()->set_id(session->getSessionID());
        eResponse.mutable_session()->set_lifespan(session->getLifespan());
        eResponse.mutable_session()->set_policy(session->getPolicyName());
        eResponse.mutable_session()->set_route(session->getRouteName());

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionsGet(const std::shared_ptr<SessionManager>& sessionManager)
{
    return [sessionManager](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionsGet_Request;
        using ResponseType = eTest::SessionsGet_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        const auto list = sessionManager->getSessionsList();

        ResponseType eResponse;
        for (const auto& sessionName : list)
        {
            eResponse.add_list(sessionName);
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionsDelete(const std::shared_ptr<SessionManager>& sessionManager,
                            const std::shared_ptr<Catalog>& catalog,
                            const std::shared_ptr<Router>& router,
                            const std::shared_ptr<store::IStore>& store)
{
    return [sessionManager, catalog, router, store](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionsDelete_Request;
        using ResponseType = eEngine::GenericStatus_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg = ((!eRequest.has_name() && !eRequest.delete_all())
                                   ? std::make_optional("Missing field /name while /delete_all field is 'false'")
                                   : std::nullopt);
        if (errorMsg.has_value())
        {
            return genericError<ResponseType>(errorMsg.value());
        }

        if (eRequest.delete_all())
        {
            std::string errorMsg {};
            for (auto& sessionName : sessionManager->getSessionsList())
            {
                const auto deleteSessionError = handleDeleteSession(sessionManager, router, catalog, sessionName);
                if (deleteSessionError.has_value())
                {
                    if (!errorMsg.empty())
                    {
                        errorMsg += ". ";
                    }
                    errorMsg += deleteSessionError.value().message;
                }
            }
            if (!errorMsg.empty())
            {
                return genericError<ResponseType>(errorMsg);
            }
        }
        else if (eRequest.has_name())
        {
            const auto deleteSessionError = handleDeleteSession(sessionManager, router, catalog, eRequest.name());
            if (deleteSessionError.has_value())
            {
                return genericError<ResponseType>(deleteSessionError.value().message);
            }
        }
        else
        {
            return genericError<ResponseType>("Invalid request");
        }

        const auto saveSessionsToStoreError = saveSessionsToStore(sessionManager, store);
        if (saveSessionsToStoreError.has_value())
        {
            return genericError<ResponseType>(saveSessionsToStoreError.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler runPost(const std::shared_ptr<SessionManager>& sessionManager, const std::shared_ptr<Router>& router)
{
    return [sessionManager, router](const api::wpRequest& wRequest) -> api::wpResponse
    {
        using RequestType = eTest::RunPost_Request;
        using ResponseType = eTest::RunPost_Response;
        const auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::get<api::wpResponse>(res);
        }

        // Validate the params request
        const auto& eRequest = std::get<RequestType>(res);
        const auto errorMsg = !eRequest.has_name()    ? std::make_optional("Missing /name field")
                              : !eRequest.has_event() ? std::make_optional("Missing /event field")
                                                      : std::nullopt;

        if (errorMsg.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(errorMsg.value());
        }

        // Set std::optional parameters
        const auto debugMode = eRequest.has_debug_mode() ? eRequest.debug_mode() : eTest::DebugMode::OUTPUT_ONLY;

        const std::string defaultQueue {static_cast<char>(TEST_DEFAULT_PROTOCOL_QUEUE)};
        const std::string strProtocolQueue {(eRequest.has_protocol_queue()) ? eRequest.protocol_queue() : defaultQueue};
        if (eRequest.protocol_queue().size() > 1)
        {
            return ::api::adapter::genericError<ResponseType>("Protocol queue must be a single character long");
        }

        const uint8_t protocolQueue {static_cast<uint8_t>(strProtocolQueue.at(0))};
        if (TEST_MAX_PROTOCOL_QUEUE < protocolQueue)
        {
            return ::api::adapter::genericError<ResponseType>(
                fmt::format("Protocol queue ({}) must be a value between {} and {}",
                            protocolQueue,
                            TEST_MIN_PROTOCOL_QUEUE,
                            TEST_MAX_PROTOCOL_QUEUE));
        }

        const auto protocolLocation =
            eRequest.has_protocol_location() ? eRequest.protocol_location() : TEST_DEFAULT_PROTOCOL_LOCATION;

        // Set debug mode
        DebugMode routerDebugMode;
        switch (debugMode)
        {
            case eTest::DebugMode::OUTPUT_AND_TRACES: routerDebugMode = DebugMode::OUTPUT_AND_TRACES; break;
            case eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS:
                routerDebugMode = DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS;
                break;
            case eTest::DebugMode::OUTPUT_ONLY:
            default: routerDebugMode = DebugMode::OUTPUT_ONLY;
        }

        const auto assetTrace = eRequest.has_asset_trace() ? eRequest.asset_trace() : std::string();

        // Get session
        const auto session = sessionManager->getSession(eRequest.name());
        if (!session.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(fmt::format(SESSION_NOT_FOUND_MSG, eRequest.name()));
        }

        // Event in Wazuh format
        const auto eventFormat =
            fmt::format(WAZUH_EVENT_FORMAT, strProtocolQueue, protocolLocation, eRequest.event().string_value());
        base::Event event;
        try
        {
            event = base::parseEvent::parseWazuhEvent(eventFormat);
        }
        catch (const std::exception& e)
        {
            return ::api::adapter::genericError<ResponseType>(e.what());
        }

        // Add session ID to the event to filter it on the route
        const auto sessionID = session.value().getSessionID();
        const auto formattedPath = json::Json::formatJsonPath(TEST_FIELD_TO_CHECK_IN_FILTER);
        event->setInt(static_cast<int>(sessionID), formattedPath);

        auto dataSync = session->getDataSync();
        auto expected {false};
        if (dataSync->m_sessionVisit.compare_exchange_strong(expected, true))
        {
            // Enqueue event
            const auto enqueueEventError = router->enqueueEvent(std::move(event));
            if (enqueueEventError.has_value())
            {
                return ::api::adapter::genericError<ResponseType>(enqueueEventError.value().message);
            }
        }
        else
        {
            return ::api::adapter::genericError<ResponseType>("An event is still being processed");
        }

        // Get payload (output and traces)
        const auto payload = getData(dataSync, routerDebugMode, assetTrace);
        dataSync->m_sessionVisit.store(false);
        if (std::holds_alternative<base::Error>(payload))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(payload).message);
        }

        ResponseType eResponse;

        // Get output
        const auto output = eMessage::eMessageFromJson<google::protobuf::Value>(
            std::get<0>(std::get<std::tuple<std::string, std::string>>(payload)));
        if (std::holds_alternative<base::Error>(output))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(output).message);
        }
        else
        {
            const auto jsonOutput = std::get<google::protobuf::Value>(output);
            eResponse.mutable_run()->mutable_output()->CopyFrom(jsonOutput);
        }

        // Get traces
        if (!std::get<1>(std::get<std::tuple<std::string, std::string>>(payload)).empty())
        {
            const auto trace = eMessage::eMessageFromJson<google::protobuf::Value>(
                std::get<1>(std::get<std::tuple<std::string, std::string>>(payload)));
            if (std::holds_alternative<base::Error>(trace))
            {
                return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(trace).message);
            }
            const auto jsonTrace = std::get<google::protobuf::Value>(trace);
            eResponse.mutable_run()->mutable_traces()->CopyFrom(jsonTrace);
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, std::shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler(TEST_GET_SESSION_DATA_API_CMD, sessionGet(config.sessionManager));
        api->registerHandler(TEST_POST_SESSION_API_CMD,
                             sessionPost(config.sessionManager, config.catalog, config.router, config.store));
        api->registerHandler(TEST_DELETE_SESSIONS_API_CMD,
                             sessionsDelete(config.sessionManager, config.catalog, config.router, config.store));
        api->registerHandler(TEST_GET_SESSIONS_LIST_API_CMD, sessionsGet(config.sessionManager));
        api->registerHandler(TEST_RUN_API_CMD, runPost(config.sessionManager, config.router));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Test API commands could not be registered: {}", e.what()));
    }
}

} // namespace api::test::handlers
