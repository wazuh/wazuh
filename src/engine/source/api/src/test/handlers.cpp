#include "api/test/handlers.hpp"

#include <optional>
#include <string>

#include <fmt/format.h>

#include <eMessages/eMessage.h>
#include <eMessages/test.pb.h>

#include <api/adapter.hpp>
#include <api/catalog/resource.hpp>
#include <api/test/sessionManager.hpp>
#include <json/json.hpp>

namespace
{

using namespace api::sessionManager;

using api::catalog::Catalog;
using api::catalog::Resource;

using ::api::adapter::fromWazuhRequest;
using ::api::adapter::genericError;
using ::api::adapter::toWazuhResponse;

using router::Router;
using router::TEST_ROUTE_MAXIMUM_PRIORITY;
using router::TEST_ROUTE_MINIMUM_PRIORITY;

using std::optional;
using std::shared_ptr;
using std::string;

} // namespace

namespace api::test::handlers
{

namespace eEngine = ::com::wazuh::api::engine;
namespace eTest = ::com::wazuh::api::engine::test;

optional<base::Error> loadSessionsFromJson(const shared_ptr<Catalog>& catalog,
                                           const shared_ptr<Router>& router,
                                           const json::Json& jsonSessions)
{
    auto& sessionManager = SessionManager::getInstance();

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

        string missingFields;
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

        const auto createSessionError = sessionManager.createSession(sessionName.value(),
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
        const auto subscriptionError = router->subscribeOutputAndTraces(policyName.value());
        if (subscriptionError.has_value())
        {
            string errorMsg {subscriptionError.value().message};

            if (!sessionManager.deleteSession(sessionName.value()))
            {
                errorMsg += string(". ") + fmt::format(SESSION_NOT_REMOVED_MSG, sessionName.value());
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName.value());
            if (deleteRouteError.has_value())
            {
                errorMsg += string(". ")
                            + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName.value(), deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName.value());
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ")
                    + fmt::format(FILTER_NOT_REMOVED_MSG, filterName.value(), deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName.value());
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ")
                    + fmt::format(POLICY_NOT_REMOVED_MSG, policyName.value(), deletePolicyError.value().message);
            }

            return base::Error {errorMsg};
        }
    }

    return std::nullopt;
}

json::Json getSessionsAsJson(void)
{
    auto jsonSessions = json::Json("[]");

    auto& sessionManager = SessionManager::getInstance();
    const auto list = sessionManager.getSessionsList();
    for (auto& sessionName : list)
    {
        const auto session = sessionManager.getSession(sessionName);
        auto jsonSession = json::Json(API_SESSIONS_DATA_FORMAT);

        jsonSession.setInt(session->getCreationDate(), "/creationdate");
        jsonSession.setInt(session->getLifespan(), "/lifespan");
        jsonSession.setInt(session->getSessionID(), "/id");
        jsonSession.setString(session->getDescription(), "/description");
        jsonSession.setString(session->getFilterName(), "/filtername");
        jsonSession.setString(session->getPolicyName(), "/policyname");
        jsonSession.setString(session->getRouteName(), "/routename");
        jsonSession.setString(session->getSessionName(), "/name");

        jsonSessions.appendJson(jsonSession);
    }

    return jsonSessions;
}

optional<base::Error> saveSessionsToStore(const shared_ptr<store::IStore>& store)
{
    const auto sessionsJson = getSessionsAsJson();
    return store->update(API_SESSIONS_TABLE_NAME, sessionsJson);
}

inline int32_t getMaximumAvailablePriority(const shared_ptr<Router>& router)
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

inline optional<base::Error>
addAssetToCatalog(const shared_ptr<Catalog>& catalog, const string& assetType, const string& assetContent)
{
    Resource targetResource;

    optional<base::Error> addAssetError;

    try
    {
        targetResource = Resource {base::Name {assetType}, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        addAssetError = optional<base::Error> {base::Error {e.what()}};
    }

    // If no error occurred, post the resource
    if (!addAssetError.has_value())
    {
        const auto postResourceError = catalog->postResource(targetResource, assetContent);
        if (postResourceError)
        {
            addAssetError = optional<base::Error> {base::Error {postResourceError.value().message}};
        }
    }

    return addAssetError;
}

inline optional<base::Error>
addTestFilterToCatalog(const shared_ptr<Catalog>& catalog, const string& filterName, const uint32_t sessionID)
{
    const auto filterContent = fmt::format(FILTER_CONTENT_FORMAT, filterName, sessionID);
    return addAssetToCatalog(catalog, "filter", filterContent);
}

inline optional<base::Error>
addTestPolicyToCatalog(const shared_ptr<Catalog>& catalog, const string& sessionName, const string& policyName)
{
    optional<base::Error> addTestPolicyToCatalogError;

    // Build target resource
    Resource targetResource;
    try
    {
        base::Name name {policyName};
        targetResource = Resource {name, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        addTestPolicyToCatalogError = optional<base::Error> {base::Error {e.what()}};
    }

    if (!addTestPolicyToCatalogError.has_value())
    {
        // Get the original policy's content
        const auto getResourceResult = catalog->getResource(targetResource);
        if (std::holds_alternative<base::Error>(getResourceResult))
        {
            addTestPolicyToCatalogError = optional<base::Error> {std::get<base::Error>(getResourceResult)};
        }
        else
        {
            string policyContent {std::get<string>(getResourceResult)};

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

inline optional<base::Error> deleteAssetFromCatalog(const shared_ptr<Catalog>& catalog, const string& assetName)
{
    optional<base::Error> deleteAssetError;

    // Build target resource
    Resource targetResource;
    try
    {
        base::Name name {assetName};
        targetResource = Resource {name, Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        deleteAssetError = optional<base::Error> {base::Error {e.what()}};
    }

    if (!deleteAssetError.has_value())
    {
        const auto deleteResourceError = catalog->deleteResource(targetResource);
        if (deleteResourceError.has_value())
        {
            const auto error = fmt::format(
                "Asset '{}' could not be removed from the catalog: {}", assetName, deleteResourceError.value().message);
            deleteAssetError = optional<base::Error> {base::Error {error}};
        };
    }

    return deleteAssetError;
}

inline optional<base::Error> deleteRouteFromRouter(const shared_ptr<Router>& router, const string& routeName)
{
    optional<base::Error> deleteRouteFromRouterError;

    try
    {
        router->removeRoute(routeName);
    }
    catch (const std::exception& e)
    {
        deleteRouteFromRouterError = optional<base::Error> {base::Error {e.what()}};
    }

    return deleteRouteFromRouterError;
}

inline optional<base::Error>
handleDeleteSession(const shared_ptr<Router>& router, const shared_ptr<Catalog>& catalog, const string& sessionName)
{
    auto& sessionManager = SessionManager::getInstance();

    const auto session = sessionManager.getSession(sessionName);
    if (!session.has_value())
    {
        return base::Error {fmt::format(SESSION_NOT_FOUND_MSG, sessionName)};
    }

    const auto deleteRouteError = deleteRouteFromRouter(router, session->getRouteName());
    if (deleteRouteError.has_value())
    {
        return deleteRouteError;
    }

    const auto deleteFilterError = deleteAssetFromCatalog(catalog, session->getFilterName());
    if (deleteFilterError.has_value())
    {
        return deleteFilterError;
    }

    const auto deletePolicyError = deleteAssetFromCatalog(catalog, session->getPolicyName());
    if (deletePolicyError.has_value())
    {
        return deletePolicyError;
    }

    if (!sessionManager.deleteSession(sessionName))
    {
        return base::Error {fmt::format(SESSION_NOT_REMOVED_MSG, sessionName)};
    }

    return std::nullopt;
}

api::Handler sessionPost(const shared_ptr<Catalog>& catalog,
                         const shared_ptr<Router>& router,
                         const shared_ptr<store::IStore>& store)
{
    return [catalog, router, store](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionPost_Request;
        using ResponseType = eTest::SessionPost_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }
        const auto& eRequest = std::get<RequestType>(res);

        // Field name is required
        const auto parametersError = (!eRequest.has_name()) ? std::make_optional("Missing /name field") : std::nullopt;
        if (parametersError.has_value())
        {
            return genericError<ResponseType>(parametersError.value());
        }

        if (eRequest.name().empty())
        {
            return genericError<ResponseType>("Session name cannot be empty");
        }

        auto& sessionManager = SessionManager::getInstance();

        const auto& sessionName = eRequest.name();

        // Check if the session already exists
        if (sessionManager.doesSessionExist(sessionName))
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
        const uint32_t sessionID {sessionManager.getNewSessionID()};

        const auto filterName = fmt::format(TEST_FILTER_FULL_NAME_FORMAT, sessionName);

        const auto addFilterError = addTestFilterToCatalog(catalog, filterName, sessionID);
        if (addFilterError.has_value())
        {
            string errorMsg {addFilterError.value().message};

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Set up the test session's route

        const auto routeName = fmt::format(TEST_ROUTE_NAME_FORMAT, sessionName);

        // Find the maximum priority that is not already taken (priority is inversely proportional to the value)
        const int32_t maxAvailablePriority = getMaximumAvailablePriority(router);
        if (TEST_ROUTE_MINIMUM_PRIORITY < maxAvailablePriority)
        {
            string errorMsg {"There is no available priority"};

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        const auto addRouteError = router->addRoute(routeName, maxAvailablePriority, filterName, policyName);
        if (addRouteError.has_value())
        {
            string errorMsg {addRouteError.value().message};

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Create the session

        // If the description is not set, use an empty string
        const string description {eRequest.has_description() ? eRequest.description() : ""};
        // If the lifespan is not set, use 0 (no expiration). TODO: review what to do in this case
        const uint32_t lifespan {eRequest.has_lifespan() ? eRequest.lifespan() : 0};

        const auto createSessionError = sessionManager.createSession(
            sessionName, policyName, filterName, routeName, sessionID, lifespan, description);
        if (createSessionError.has_value())
        {
            string errorMsg {createSessionError.value().message};

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Suscribe to output and Trace
        const auto subscriptionError = router->subscribeOutputAndTraces(policyName);
        if (subscriptionError.has_value())
        {
            string errorMsg {subscriptionError.value().message};

            if (!sessionManager.deleteSession(sessionName))
            {
                errorMsg += string(". ") + fmt::format(SESSION_NOT_REMOVED_MSG, sessionName);
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        // Save the sessions to the store
        const auto saveSessionsToStoreError = saveSessionsToStore(store);
        if (saveSessionsToStoreError.has_value())
        {
            string errorMsg {saveSessionsToStoreError.value().message};

            if (!sessionManager.deleteSession(sessionName))
            {
                errorMsg += fmt::format(SESSION_NOT_REMOVED_MSG, sessionName);
            }

            const auto deleteRouteError = deleteRouteFromRouter(router, routeName);
            if (deleteRouteError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(ROUTE_NOT_REMOVED_MSG, routeName, deleteRouteError.value().message);
            }

            const auto deleteFilterError = deleteAssetFromCatalog(catalog, filterName);
            if (deleteFilterError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(FILTER_NOT_REMOVED_MSG, filterName, deleteFilterError.value().message);
            }

            const auto deletePolicyError = deleteAssetFromCatalog(catalog, policyName);
            if (deletePolicyError.has_value())
            {
                errorMsg +=
                    string(". ") + fmt::format(POLICY_NOT_REMOVED_MSG, policyName, deletePolicyError.value().message);
            }

            return genericError<ResponseType>(errorMsg);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionGet(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
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

        const auto errorMsg = !eRequest.has_name() ? std::make_optional("Missing /name field") : std::nullopt;
        if (errorMsg.has_value())
        {
            return genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = SessionManager::getInstance();
        const auto session = sessionManager.getSession(eRequest.name());
        if (!session.has_value())
        {
            return genericError<ResponseType>(fmt::format(SESSION_NOT_FOUND_MSG, eRequest.name()));
        }

        ResponseType eResponse;

        // TODO: improve creation date representation
        eResponse.set_creation_date(session->getCreationDate());
        eResponse.set_description(session->getDescription());
        eResponse.set_filter(session->getFilterName());
        eResponse.set_id(session->getSessionID());
        eResponse.set_lifespan(session->getLifespan());
        eResponse.set_policy(session->getPolicyName());
        eResponse.set_route(session->getRouteName());

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionsGet(void)
{
    return [](api::wpRequest wRequest) -> api::wpResponse
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

        auto& sessionManager = SessionManager::getInstance();
        const auto list = sessionManager.getSessionsList();

        ResponseType eResponse;
        for (const auto& sessionName : list)
        {
            eResponse.add_list(sessionName);
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionsDelete(const shared_ptr<Catalog>& catalog,
                            const shared_ptr<Router>& router,
                            const shared_ptr<store::IStore>& store)
{
    return [catalog, router, store](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::SessionsDelete_Request;
        using ResponseType = eTest::SessionsDelete_Response;
        auto res = fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
        }

        const auto& eRequest = std::get<RequestType>(res);

        const auto errorMsg =
            ((!eRequest.has_name() && !eRequest.has_delete_all())
                 ? std::make_optional("Missing both /name and /delete_all fields, at least one field must be set")
                 : std::nullopt);
        if (errorMsg.has_value())
        {
            return genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = SessionManager::getInstance();

        if (eRequest.has_delete_all() && eRequest.delete_all())
        {
            for (auto& sessionName : sessionManager.getSessionsList())
            {
                const auto deleteSessionError = handleDeleteSession(router, catalog, sessionName);
                if (deleteSessionError.has_value())
                {
                    return genericError<ResponseType>(deleteSessionError.value().message);
                }
            }
        }
        else if (eRequest.has_name())
        {
            const auto deleteSessionError = handleDeleteSession(router, catalog, eRequest.name());
            if (deleteSessionError.has_value())
            {
                return genericError<ResponseType>(deleteSessionError.value().message);
            }
        }
        else
        {
            return genericError<ResponseType>("Invalid request");
        }

        const auto saveSessionsToStoreError = saveSessionsToStore(store);
        if (saveSessionsToStoreError.has_value())
        {
            return genericError<ResponseType>(saveSessionsToStoreError.value().message);
        }

        ResponseType eResponse;
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler runPost(const shared_ptr<Router>& router)
{
    return [router](api::wpRequest wRequest) -> api::wpResponse
    {
        using RequestType = eTest::RunPost_Request;
        using ResponseType = eTest::RunPost_Response;
        const auto res = ::api::adapter::fromWazuhRequest<RequestType, ResponseType>(wRequest);

        // If the request is not valid, return the error
        if (std::holds_alternative<api::wpResponse>(res))
        {
            return std::move(std::get<api::wpResponse>(res));
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

        // Set optional parameters
        const auto debugMode = eRequest.has_debug_mode() ? eRequest.debug_mode() : eTest::DebugMode::OUTPUT_ONLY;

        const string defaultQueue {static_cast<char>(TEST_DEFAULT_PROTOCOL_QUEUE)};
        const string strProtocolQueue {(eRequest.has_protocol_queue()) ? eRequest.protocol_queue() : defaultQueue};
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
        router::DebugMode routerDebugMode;
        switch (debugMode)
        {
            case eTest::DebugMode::OUTPUT_AND_TRACES: routerDebugMode = router::DebugMode::OUTPUT_AND_TRACES; break;
            case eTest::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS:
                routerDebugMode = router::DebugMode::OUTPUT_AND_TRACES_WITH_DETAILS;
                break;
            case eTest::DebugMode::OUTPUT_ONLY:
            default: routerDebugMode = router::DebugMode::OUTPUT_ONLY;
        }

        // Get session
        auto& sessionManager = SessionManager::getInstance();
        const auto session = sessionManager.getSession(eRequest.name());
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
        event->setInt(sessionID, TEST_FIELD_TO_CHECK_IN_FILTER);

        // Enqueue event
        const auto enqueueEventError = router->enqueueEvent(std::move(event));
        if (enqueueEventError.has_value())
        {
            return ::api::adapter::genericError<ResponseType>(enqueueEventError.value().message);
        }

        // Get payload (output and traces)
        const auto payload = router->getData(session.value().getPolicyName(), routerDebugMode);
        if (std::holds_alternative<base::Error>(payload))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(payload).message);
        }

        ResponseType eResponse;

        // Get output
        const auto output = eMessage::eMessageFromJson<google::protobuf::Value>(
            std::get<0>(std::get<std::tuple<string, string>>(payload)));
        if (std::holds_alternative<base::Error>(output))
        {
            return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(output).message);
        }
        else
        {
            const auto jsonOutput = std::get<google::protobuf::Value>(output);
            eResponse.mutable_output()->CopyFrom(jsonOutput);
        }

        // Get traces
        if (!std::get<1>(std::get<std::tuple<string, string>>(payload)).empty())
        {
            const auto trace = eMessage::eMessageFromJson<google::protobuf::Value>(
                std::get<1>(std::get<std::tuple<string, string>>(payload)));
            if (std::holds_alternative<base::Error>(trace))
            {
                return ::api::adapter::genericError<ResponseType>(std::get<base::Error>(trace).message);
            }
            const auto jsonTrace = std::get<google::protobuf::Value>(trace);
            eResponse.mutable_traces()->CopyFrom(jsonTrace);
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return ::api::adapter::toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler(TEST_GET_SESSION_DATA_API_CMD, sessionGet());
        api->registerHandler(TEST_POST_SESSION_API_CMD, sessionPost(config.catalog, config.router, config.store));
        api->registerHandler(TEST_DELETE_SESSIONS_API_CMD, sessionsDelete(config.catalog, config.router, config.store));
        api->registerHandler(TEST_GET_SESSIONS_LIST_API_CMD, sessionsGet());
        api->registerHandler(TEST_RUN_API_CMD, runPost(config.router));
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Test API commands could not be registered: {}", e.what()));
    }
}

} // namespace api::test::handlers
