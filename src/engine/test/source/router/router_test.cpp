#include <router/router.hpp>

#include <string>

#include <gtest/gtest.h>

#include "register.hpp"

namespace
{
const json::Json jRouteExistQueue = json::Json(R"(
        {
            "name": "Exist wazuh.queue",
            "check": [
                {
                    "wazuh.queue": "+ef_exists"
                }
            ],
            "destination": "env wazuh queue"
        }
    )");

const json::Json jRouteAllowAll = json::Json(R"(
        {
            "name": "Allow all",
            "destination": "env default allow all"
        }
    )");

} // namespace

TEST(Router, build_ok)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    router::Router router(registry);
}

TEST(Router, build_fail)
{
    GTEST_SKIP();
    ASSERT_THROW(router::Router router(nullptr), std::exception);
}

/*******************************************************************************
 *           Get expression
 ******************************************************************************/
TEST(Router, get_expression_empty_router)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    router::Router router(registry);

    auto expression = router.getExpression();
}

TEST(Router, get_expression_1_route)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    router::Router router(registry);

    router.addRoute(jRouteExistQueue);

    auto expression = router.getExpression();
}

TEST(Router, get_expression_1_route_wout_check)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    router::Router router(registry);

    router.addRoute(jRouteAllowAll);

    auto expression = router.getExpression();
}

TEST(Router, get_expression_2_routes)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    router::Router router(registry);

    router.addRoute(jRouteExistQueue);
    router.addRoute(jRouteAllowAll);

    auto expression = router.getExpression();
}
