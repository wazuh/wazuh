#ifndef _API_TEST_HANDLERS_HPP
#define _API_TEST_HANDLERS_HPP

#include <api/api.hpp>
#include <api/catalog/catalog.hpp>
#include <router/router.hpp>

namespace api::test::handlers
{

constexpr auto MINIMUM_PRIORITY = 255; ///< Minimum priority allowed for a route
constexpr auto MAXIMUM_PRIORITY = 0;   ///< Maximum priority allowed for a route

constexpr auto FILTER_CONTENT_FORMAT =
    R"({{"name": "{}", "check":[{{"~TestSessionName":"{}"}}]}})"; ///< Filter content format, where '{}' is the session
                                                                  ///< name
constexpr auto FILTER_NAME_FORMAT = "filter/test-{}/0"; ///< Filter name format, where '{}' is the session name
constexpr auto ROUTE_NAME_FORMAT = "{}_route";          ///< Route name format, where '{}' is the session name

/**
 * @brief Test configuration parameters.
 *
 */
struct Config
{
    std::shared_ptr<::router::Router> router;
    std::shared_ptr<catalog::Catalog> catalog;
};

api::Handler sessionGet(void);
api::Handler sessionPost(std::shared_ptr<::router::Router> router, std::shared_ptr<catalog::Catalog> catalog);

api::Handler sessionsDelete(std::shared_ptr<::router::Router> router, std::shared_ptr<catalog::Catalog> catalog);
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
