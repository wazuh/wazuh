#include "api/test/handlers.hpp"

#include <optional>
#include <string>

#include <fmt/format.h>

#include <api/adapter.hpp>
#include <api/catalog/resource.hpp>

#include <eMessages/eMessage.h>
#include <eMessages/test.pb.h>

#include "api/test/sessionManager.hpp"

namespace
{

using namespace api::sessionManager;

using std::optional;
using std::shared_ptr;
using std::string;

using ::api::adapter::fromWazuhRequest;
using ::api::adapter::genericError;
using ::api::adapter::toWazuhResponse;

using ::router::Router;

using api::catalog::Catalog;
using api::catalog::Resource;

} // namespace

namespace api::test::handlers
{

namespace eEngine = ::com::wazuh::api::engine;
namespace eTest = ::com::wazuh::api::engine::test;

inline int32_t getMinimumAvailablePriority(const shared_ptr<Router>& router)
{
    // Create a set to store the taken priorities given the table
    std::unordered_set<uint32_t> takenPriorities;

    const auto routerTable = router->getRouteTable();
    for (const auto& [name, priority, filter, policy] : routerTable)
    {
        takenPriorities.insert(priority);
    }

    int32_t minAvailablePriority {MINIMUM_PRIORITY};

    // The condition may be confusing as the actual priority increases while the value decreases
    while (takenPriorities.count(minAvailablePriority) > 0 && MAXIMUM_PRIORITY < minAvailablePriority)
    {
        // If priority is taken, decrease the value (so, increase the priority)
        minAvailablePriority--;
    }

    return minAvailablePriority;
}

inline optional<base::Error>
addAssetToCatalog(shared_ptr<Catalog> catalog, const string& assetType, const string& assetContent)
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
addTestFilterToCatalog(shared_ptr<Catalog> catalog, const string& sessionName, const string& filterName)
{
    const auto filterContent = fmt::format(FILTER_CONTENT_FORMAT, filterName, sessionName);
    return addAssetToCatalog(catalog, "filter", filterContent);
}

inline optional<base::Error>
addTestPolicyToCatalog(shared_ptr<Catalog> catalog, const string& sessionName, const string& policyName)
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

inline optional<base::Error> deleteAssetFromStore(shared_ptr<Catalog> catalog, const string& assetName)
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
                "Asset '{}' could not be removed from the store: {}", assetName, deleteResourceError.value().message);
            deleteAssetError = optional<base::Error> {base::Error {error}};
        };
    }

    return deleteAssetError;
}

inline optional<base::Error> deleteRouteFromRouter(shared_ptr<Router> router, const string& routeName)
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
deleteSession(shared_ptr<Router> router, shared_ptr<Catalog> catalog, const string& sessionName)
{
    auto& sessionManager = SessionManager::getInstance();

    auto session = sessionManager.getSession(sessionName);
    if (!session.has_value())
    {
        return base::Error {fmt::format("Session '{}' could not be found", sessionName)};
    }

    const auto deleteRouteError = deleteRouteFromRouter(router, session->getRouteName());
    if (deleteRouteError.has_value())
    {
        return deleteRouteError;
    }

    const auto deleteFilterError = deleteAssetFromStore(catalog, session->getFilterName());
    if (deleteFilterError.has_value())
    {
        return deleteFilterError;
    }

    const auto deletePolicyError = deleteAssetFromStore(catalog, session->getPolicyName());
    if (deletePolicyError.has_value())
    {
        return deletePolicyError;
    }

    if (!sessionManager.deleteSession(sessionName))
    {
        return base::Error {fmt::format("Session '{}' could not be removed from the sessions manager", sessionName)};
    }

    return std::nullopt;
}

api::Handler sessionPost(shared_ptr<Router> router, shared_ptr<Catalog> catalog)
{
    return [router, catalog](api::wpRequest wRequest) -> api::wpResponse
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

        // Field name, policy and lifespan are required
        const auto parametersError = (!eRequest.has_name()) ? std::make_optional("Missing /name field") : std::nullopt;
        if (parametersError.has_value())
        {
            return genericError<ResponseType>(parametersError.value());
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

        const auto filterName = fmt::format(TEST_FILTER_FULL_NAME_FORMAT, sessionName);

        const auto addFilterError = addTestFilterToCatalog(catalog, sessionName, filterName);
        if (addFilterError.has_value())
        {
            deleteAssetFromStore(catalog, policyName);
            return genericError<ResponseType>(addFilterError.value().message);
        }

        // Set up the test session's route

        const auto routeName = fmt::format(TEST_ROUTE_NAME_FORMAT, sessionName);

        // Find the minimum priority that is not already taken
        const int32_t minAvailablePriority = getMinimumAvailablePriority(router);
        if (0 > minAvailablePriority)
        {
            deleteAssetFromStore(catalog, filterName);
            deleteAssetFromStore(catalog, policyName);
            return genericError<ResponseType>("There is no available priority");
        }

        const auto addRouteError = router->addRoute(routeName, minAvailablePriority, filterName, policyName);
        if (addRouteError.has_value())
        {
            deleteAssetFromStore(catalog, filterName);
            deleteAssetFromStore(catalog, policyName);
            return genericError<ResponseType>(addRouteError.value().message);
        }

        // Create the session

        // If the lifespan is not set, use 0 (no expiration). TODO: review what to do in this case
        const auto lifespan = eRequest.has_lifespan() ? eRequest.lifespan() : 0;
        const auto description = eRequest.has_description() ? eRequest.description() : "";
        const auto createSessionError =
            sessionManager.createSession(sessionName, policyName, filterName, routeName, lifespan, description);
        if (createSessionError.has_value())
        {
            deleteRouteFromRouter(router, routeName);
            deleteAssetFromStore(catalog, filterName);
            deleteAssetFromStore(catalog, policyName);
            return genericError<ResponseType>(createSessionError.value().message);
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
            return genericError<ResponseType>(fmt::format("Session '{}' could not be found", eRequest.name()));
        }

        ResponseType eResponse;

        // TODO: improve creation date representation
        eResponse.set_creationdate(std::to_string(session->getCreationDate()));
        eResponse.set_description(session->getDescription());
        eResponse.set_filtername(session->getFilterName());
        eResponse.set_id(session->getSessionID());
        eResponse.set_lifespan(session->getLifespan());
        eResponse.set_policyname(session->getPolicyName());
        eResponse.set_routename(session->getRouteName());

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
        auto list = sessionManager.getSessionsList();

        ResponseType eResponse;
        for (const auto& sessionName : list)
        {
            eResponse.add_list(sessionName);
        }
        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

api::Handler sessionsDelete(shared_ptr<Router> router, shared_ptr<Catalog> catalog)
{
    return [router, catalog](api::wpRequest wRequest) -> api::wpResponse
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
            ((!eRequest.has_name() && !eRequest.has_removeall())
                 ? std::make_optional("Missing both /name and /removeall fields, at least one field must be set")
                 : std::nullopt);
        if (errorMsg.has_value())
        {
            return genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = SessionManager::getInstance();

        if (eRequest.has_removeall() && eRequest.removeall())
        {
            for (auto& sessionName : sessionManager.getSessionsList())
            {
                const auto deleteSessionError = deleteSession(router, catalog, sessionName);
                if (deleteSessionError.has_value())
                {
                    return genericError<ResponseType>(deleteSessionError.value().message);
                }
            }
        }
        else if (eRequest.has_name())
        {
            const auto deleteSessionError = deleteSession(router, catalog, eRequest.name());
            if (deleteSessionError.has_value())
            {
                return genericError<ResponseType>(deleteSessionError.value().message);
            }
        }
        else
        {
            return genericError<ResponseType>("Invalid request");
        }

        eResponse.set_status(eEngine::ReturnStatus::OK);

        return toWazuhResponse(eResponse);
    };
}

void registerHandlers(const Config& config, shared_ptr<api::Api> api)
{
    try
    {
        api->registerHandler("test.session/get", sessionGet());
        api->registerHandler("test.session/post", sessionPost(config.router, config.catalog));
        api->registerHandler("test.sessions/delete", sessionsDelete(config.router, config.catalog));
        api->registerHandler("test.sessions/get", sessionsGet());
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("test API commands could not be registered: {}", e.what()));
    }
}

} // namespace api::test::handlers
