#include "api/test/handlers.hpp"

#include <api/adapter.hpp>
#include <api/catalog/resource.hpp>

#include <eMessages/eMessage.h>
#include <eMessages/test.pb.h>

#include "api/test/sessionManager.hpp"

namespace
{

using namespace api::sessionManager;

using std::shared_ptr;
using std::string;

using ::api::adapter::fromWazuhRequest;
using ::api::adapter::genericError;
using ::api::adapter::toWazuhResponse;

} // namespace

namespace api::test::handlers
{

namespace eEngine = ::com::wazuh::api::engine;
namespace eTest = ::com::wazuh::api::engine::test;

/**
 * @brief Get the minimum available priority for a route.
 *
 * @param router Router instance.
 * @return int32_t Minimum available priority. If no priority is available, returns -1.
 */
static inline int32_t getMinimumAvailablePriority(const shared_ptr<::router::Router>& router)
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
    while (takenPriorities.count(minAvailablePriority) > 0 && MAXIMUM_PRIORITY > minAvailablePriority)
    {
        // If priority is taken, decrease the value (so, increase the priority)
        minAvailablePriority--;
    }

    return minAvailablePriority;
}

/**
 * @brief Add a filter to the catalog.
 *
 * @param catalog Catalog instance.
 * @param filterName Filter name.
 * @param filterContent Filter content.
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
static inline std::optional<base::Error>
addFilterToCatalog(shared_ptr<catalog::Catalog> catalog, const string& filterName, const string& filterContent)
{
    std::string error;

    catalog::Resource targetResource;

    try
    {
        targetResource = catalog::Resource {base::Name {"filter"}, catalog::Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        error = e.what();
    }

    // If no error occurred, post the resource
    if (error.empty())
    {
        const auto postResourceError = catalog->postResource(targetResource, filterContent);
        if (postResourceError)
        {
            error = postResourceError.value().message;
        }
    }

    return (error.empty() ? std::nullopt : std::make_optional(base::Error {error}));
}

/**
 * @brief Delete a filter from the catalog.
 *
 * @param filterName Filter name.
 * @param catalog Catalog instance.
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
static inline std::optional<base::Error> deleteFilterFromStore(const string& filterName,
                                                               shared_ptr<catalog::Catalog> catalog)
{
    std::string error;

    // Build target resource
    catalog::Resource targetResource;
    try
    {
        base::Name name {filterName};
        targetResource = catalog::Resource {name, catalog::Resource::Format::json};
    }
    catch (const std::exception& e)
    {
        error = e.what();
    }

    if (error.empty())
    {
        const auto deleteResourceError = catalog->deleteResource(targetResource);
        if (deleteResourceError.has_value())
        {
            error = fmt::format(
                "Filter '{}' could not be removed from the store: {}", filterName, deleteResourceError.value().message);
        };
    }

    return (error.empty() ? std::nullopt : std::make_optional(base::Error {error}));
}

/**
 * @brief Delete a route from the router.
 *
 * @param routeName Route name.
 * @param router Router instance.
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
static inline std::optional<base::Error> deleteRouteFromRouter(const string& routeName,
                                                               shared_ptr<::router::Router> router)
{
    std::string error;

    try
    {
        router->removeRoute(routeName);
    }
    catch(const std::exception& e)
    {
        error = e.what();
    }

    return (error.empty() ? std::nullopt : std::make_optional(base::Error {error}));
}

/**
 * @brief Delete a session and the resources created along with it.
 *
 * @param sessionName Session name.
 * @param router Router instance.
 * @param catalog Catalog instance.
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
static inline std::optional<base::Error>
deleteSession(const string& sessionName, shared_ptr<::router::Router> router, shared_ptr<catalog::Catalog> catalog)
{
    auto& sessionManager = SessionManager::getInstance();

    auto session = sessionManager.getSession(sessionName);
    if (!session.has_value())
    {
        return base::Error {fmt::format("Session '{}' could not be found", sessionName)};
    }

    const auto deleteFilterError = deleteFilterFromStore(session->getFilterName(), catalog);
    if (deleteFilterError.has_value())
    {
        return deleteFilterError;
    }

    const auto deleteRouteError = deleteRouteFromRouter(session->getRouteName(), router);
    if (deleteRouteError.has_value())
    {
        return deleteRouteError;
    }

    if (!sessionManager.deleteSession(sessionName))
    {
        return base::Error {fmt::format("Session '{}' could not be removed from the sessions manager", sessionName)};
    }

    return std::nullopt;
}

api::Handler sessionPost(shared_ptr<::router::Router> router, shared_ptr<catalog::Catalog> catalog)
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
        const auto parametersError = !eRequest.has_name()     ? std::make_optional("Missing /name field")
                                     : !eRequest.has_policy() ? std::make_optional("Missing /policy field")
                                                              : std::nullopt;
        if (parametersError.has_value())
        {
            return genericError<ResponseType>(parametersError.value());
        }

        auto& sessionManager = SessionManager::getInstance();

        const auto filterName = fmt::format(FILTER_NAME_FORMAT, eRequest.name());

        const auto filterContent = fmt::format(FILTER_CONTENT_FORMAT, filterName, eRequest.name());

        const auto addFilterError = addFilterToCatalog(catalog, filterName, filterContent);

        if (addFilterError.has_value())
        {
            return genericError<ResponseType>(addFilterError.value().message);
        }

        const auto routeName = fmt::format(ROUTE_NAME_FORMAT, eRequest.name());

        // Find the minimum priority that is not already taken
        const int32_t minAvailablePriority = getMinimumAvailablePriority(router);

        if (0 > minAvailablePriority)
        {
            return genericError<ResponseType>("There is no available priority");
        }

        const auto addRouteError = router->addRoute(routeName, minAvailablePriority, filterName, eRequest.policy());
        if (addRouteError.has_value())
        {
            return genericError<ResponseType>(addRouteError.value().message);
        }

        const auto createSessionError =
            sessionManager.createSession(eRequest.name(), routeName, eRequest.policy(), eRequest.lifespan());
        if (createSessionError.has_value())
        {
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

api::Handler sessionsDelete(shared_ptr<::router::Router> router, shared_ptr<catalog::Catalog> catalog)
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
            !eRequest.has_name() && !eRequest.has_removeall()
                ? std::make_optional("Missing both /name and /removeall fields, at least one field must be set")
                : std::nullopt;
        if (errorMsg.has_value())
        {
            return genericError<ResponseType>(errorMsg.value());
        }

        auto& sessionManager = SessionManager::getInstance();

        if (eRequest.has_removeall() && eRequest.removeall())
        {
            for (auto& sessionName : sessionManager.getSessionsList())
            {
                const auto deleteSessionError = deleteSession(sessionName, router, catalog);
                if (deleteSessionError.has_value())
                {
                    return genericError<ResponseType>(deleteSessionError.value().message);
                }
            }
        }
        else if (eRequest.has_name())
        {
            const auto deleteSessionError = deleteSession(eRequest.name(), router, catalog);
            if (deleteSessionError.has_value())
            {
                return genericError<ResponseType>(deleteSessionError.value().message);
            }
        }
        else
        {
            return genericError<ResponseType>("Invalid request");
        }

        ResponseType eResponse;
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
