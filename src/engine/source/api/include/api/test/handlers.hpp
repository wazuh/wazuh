#ifndef _API_TEST_HANDLERS_HPP
#define _API_TEST_HANDLERS_HPP

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <router/router.hpp>

namespace api::test::handlers
{

constexpr auto MINIMUM_PRIORITY = 255;                      ///< Minimum priority allowed for a route
constexpr auto MAXIMUM_PRIORITY = 0;                        ///< Maximum priority allowed for a route

constexpr auto DEFAULT_POLICY_FULL_NAME = "policy/wazuh/0"; ///< Default policy full name

constexpr auto ASSET_NAME_FIELD_FORMAT = R"("name":"{}")";  ///< JSON name field format, where '{}' is the asset name
constexpr auto FILTER_CONTENT_FORMAT =
    R"({{"name": "{}", "check":[{{"~TestSessionName":"{}"}}]}})";   ///< Filter content format
constexpr auto TEST_FILTER_FULL_NAME_FORMAT = "filter/{}_filter/0"; ///< Filter name format, '{}' is the session name
constexpr auto TEST_POLICY_FULL_NAME_FORMAT = "policy/{}_policy/0"; ///< Policy name format, '{}' is the session name
constexpr auto TEST_ROUTE_NAME_FORMAT = "{}_route";                 ///< Route name format, '{}' is the session name

/**
 * @brief Test configuration parameters.
 *
 */
struct Config
{
    std::shared_ptr<::router::Router> router;
    std::shared_ptr<catalog::Catalog> catalog;
};

/**
 * @brief API command handler to get the parameters of an active session.
 *
 * @return api::Handler
 */
api::Handler sessionGet(void);

/**
 * @brief API command handler to create a new session.
 *
 * @param router Router instance.
 * @param catalog Catalog instance.
 * @return api::Handler
 */
api::Handler sessionPost(std::shared_ptr<::router::Router> router, std::shared_ptr<catalog::Catalog> catalog);

/**
 * @brief API command handler to delete a session or all the sessions.
 *
 * @param router Router instance.
 * @param catalog Catalog instance.
 * @return api::Handler
 */
api::Handler sessionsDelete(std::shared_ptr<::router::Router> router, std::shared_ptr<catalog::Catalog> catalog);

/**
 * @brief API command handler to get the list of active sessions.
 *
 * @return api::Handler
 */
api::Handler sessionsGet(void);

/**
 * @brief Register all handlers for the test API.
 *
 * @param config Test configuration.
 * @param api API instance.
 * @throw std::runtime_error If the command registration fails for any reason and at any
 */
void registerHandlers(const Config& config, std::shared_ptr<api::Api> api);

} // namespace api::test::handlers

#endif // _API_TEST_HANDLERS_HPP
