#ifndef _API_TEST_HANDLERS_HPP
#define _API_TEST_HANDLERS_HPP

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <api/test/sessionManager.hpp>
#include <router/router.hpp>
#include <store/drivers/fileDriver.hpp>

namespace api::test::handlers
{

constexpr auto API_SESSIONS_TABLE_NAME = "internal/api_sessions/0";   ///< Name of the sessions table in the store

constexpr auto DEFAULT_POLICY_FULL_NAME = "policy/wazuh/0";           ///< Default policy full name

constexpr auto TEST_DELETE_SESSIONS_API_CMD = "test.sessions/delete"; ///< API command to delete sessions
constexpr auto TEST_GET_SESSION_DATA_API_CMD = "test.session/get";    ///< API command to get a session data
constexpr auto TEST_GET_SESSIONS_LIST_API_CMD = "test.sessions/get";  ///< API command to get the list of sessions
constexpr auto TEST_POST_SESSION_API_CMD = "test.session/post";       ///< API command to create a new session
constexpr auto TEST_RUN_API_CMD = "test.run/post";                    ///< API command to test an event in a session

/**
 * @brief Enumeration representing debugging modes.
 *
 * Debugging modes control the amount and type of debugging information that will be displayed during program execution.
 */
enum class DebugMode
{
    OUTPUT_ONLY,
    OUTPUT_AND_TRACES,
    OUTPUT_AND_TRACES_WITH_DETAILS
};

/**
 * @brief Test configuration parameters.
 *
 */
struct Config
{
    std::shared_ptr<api::sessionManager::SessionManager> sessionManager;
    std::shared_ptr<::router::Router> router;
    std::shared_ptr<catalog::Catalog> catalog;
    std::shared_ptr<store::IStore> store;
};

/**
 * @brief Loads the stored sessions from a JSON string.
 *
 * @param sessionManager Session Manager instance.
 * @param catalog Catalog instance.
 * @param router Router instance.
 * @param jsonSessions JSON string containing the sessions.
 *
 * @return optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error>
loadSessionsFromJson(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                     const std::shared_ptr<catalog::Catalog>& catalog,
                     const std::shared_ptr<::router::Router>& router,
                     const json::Json& jsonSessions);

/**
 * @brief Retrieves a list of sessions as a JSON object.
 *
 * This function takes a shared pointer to the SessionManager and returns a JSON object representing the sessions.
 *
 * @param sessionManager A shared pointer to the SessionManager object.
 * @return json::Json A JSON object containing the sessions.
 */
json::Json getSessionsAsJson(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager);

/**
 * @brief Loads stored sessions given a JSON object.
 *
 * This function takes a shared pointer to the SessionManager, Catalog, Router, and a JSON object representing sessions.
 * It parses the JSON sessions, validates the required fields, and creates sessions in the session manager.
 * Additionally, it subscribes to the output and traces of the created sessions in the router.
 *
 * @param sessionManager A shared pointer to the SessionManager object.
 * @param catalog A shared pointer to the Catalog object.
 * @param router A shared pointer to the Router object.
 * @param jsonSessions A JSON object representing the sessions.
 *
 * @return std::optional<base::Error> An optional Error object indicating any error that occurred during the loading
 * process, or std::nullopt if the loading was successful.
 */
std::optional<base::Error>
saveSessionsToStore(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                    const std::shared_ptr<store::IStore>& store);

/**
 * @brief Get the maximum available priority for a route.
 *
 * @param router Router instance.
 *
 * @return int32_t Maximum available priority.
 */
int32_t getMaximumAvailablePriority(const std::shared_ptr<::router::Router>& router);

/**
 * @brief Add an asset to the catalog.
 *
 * @param catalog Catalog instance.
 * @param assetType Asset type string.
 * @param assetContent Asset content as a string.
 *
 * @todo Consider moving this method to the catalog scope.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> addAssetToCatalog(const std::shared_ptr<catalog::Catalog>& catalog,
                                             const std::string& assetType,
                                             const std::string& assetContent);

/**
 * @brief Add the test's filter to the catalog.
 *
 * @param catalog Catalog instance.
 * @param sessionName Session name.
 * @param filterName Filter name.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> addTestFilterToCatalog(const std::shared_ptr<catalog::Catalog>& catalog,
                                                  const std::string& sessionName,
                                                  const std::string& filterName);

/**
 * @brief Add the test's policy to the catalog.
 *
 * @param catalog Catalog instance.
 * @param sessionName Session name.
 * @param policyName Policy name.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> addTestPolicyToCatalog(const std::shared_ptr<catalog::Catalog>& catalog,
                                                  const std::string& sessionName,
                                                  const std::string& policyName);

/**
 * @brief Delete a route from the router.
 *
 * @param router Router instance.
 * @param routeName Route name.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> deleteRouteFromRouter(const std::shared_ptr<::router::Router>& router,
                                                 const std::string& routeName);

/**
 * @brief Delete an asset from the catalog.
 *
 * @param catalog Catalog instance.
 * @param assetName Asset name.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> deleteAssetFromCatalog(const std::shared_ptr<catalog::Catalog>& catalog,
                                                  const std::string& assetName);

/**
 * @brief Delete a session and the resources created along with it.
 *
 * @param sessionManager Session Manager instance.
 * @param router Router instance.
 * @param catalog Catalog instance.
 * @param sessionName Session name.
 *
 * @return std::optional<base::Error> If an error occurs, returns the error. Otherwise, returns std::nullopt.
 */
std::optional<base::Error> deleteSession(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                                         const std::shared_ptr<::router::Router>& router,
                                         const std::shared_ptr<catalog::Catalog>& catalog,
                                         const std::string& sessionName);

/**
 * @brief API command handler to get the parameters of an active session.
 *
 * @param sessionManager Session Manager instance.
 *
 * @return api::Handler
 */
api::Handler sessionGet(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager);

/**
 * @brief API command handler to create a new session.
 *
 * @param sessionManager Session Manager instance.
 * @param catalog Catalog instance.
 * @param router Router instance.
 * @param store Store instance.
 *
 * @return api::Handler
 */
api::Handler sessionPost(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                         const std::shared_ptr<catalog::Catalog>& catalog,
                         const std::shared_ptr<::router::Router>& router,
                         const std::shared_ptr<store::IStore>& store);

/**
 * @brief API command handler to delete a session or all the sessions.
 *
 * @param sessionManager Session Manager instance.
 * @param catalog Catalog instance.
 * @param router Router instance.
 * @param store Store instance.
 *
 * @return api::Handler
 */
api::Handler sessionsDelete(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                            const std::shared_ptr<catalog::Catalog>& catalog,
                            const std::shared_ptr<::router::Router>& router,
                            const std::shared_ptr<store::IStore>& store);

/**
 * @brief API command handler to get the list of active sessions.
 *
 * @param sessionManager Session Manager instance.
 *
 * @return api::Handler
 */
api::Handler sessionsGet(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager);

/**
 * @brief API command handler to test an event in a certain session.
 *
 * @param sessionManager Session Manager instance.
 * @param router Router instance.
 *
 * @return api::Handler
 */
api::Handler runPost(const std::shared_ptr<api::sessionManager::SessionManager>& sessionManager,
                     const std::shared_ptr<::router::Router>& router,
                     const std::shared_ptr<store::IStore>& store);

/**
 * @brief Register all handlers for the test API.
 *
 * @param config Test configuration.
 * @param api API instance.
 *
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::test::handlers

#endif // _API_TEST_HANDLERS_HPP
