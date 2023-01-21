#include <router/router.hpp>

#include <string>

#include <gtest/gtest.h>

#include "parseEvent.hpp"
#include "register.hpp"

#include "testAuxiliar/routerAuxiliarFunctions.hpp"

TEST(Router, build_ok)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();

    router::Router router(builder);
}
// Add more test
TEST(Router, build_fail)
{

    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();

    try {
        router::Router router(builder, 0);
        FAIL() << "Router: The router was created with 0 threads";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "Router: The number of threads must be greater than 0.");
    } catch (...) {
        FAIL() << "Router: The router was created with 0 threads";
    }

    try {
        router::Router router(nullptr);
        FAIL() << "Router: The router was created with a null builder";
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "Router: Builder can't be null.");
    } catch (...) {
        FAIL() << "Router: The router was created with a null builder";
    }
}

TEST(Router, add_list_remove_routes)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();

    router::Router router(builder);

    // Add a route
    auto error = router.addRoute("route/e_wazuh_queue/0");
    EXPECT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto routes = router.listRoutes();
    EXPECT_EQ(routes.size(), 1) << error.value().message;

    // Add a route
    error = router.addRoute("route/allow_all/0");
    EXPECT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto list = router.listRoutes();
    EXPECT_EQ(list.size(), 2) << error.value().message;

    std::sort(list.begin(), list.end());
    list[0] == "route/allow_all/0";
    list[1] == "route/e_wazuh_queue/0";

    // Remove a route
    error = router.removeRoute("route/e_wazuh_queue/0");
    EXPECT_FALSE(error.has_value());

    // List routes
    routes = router.listRoutes();
    EXPECT_EQ(routes.size(), 1);
    EXPECT_EQ(routes[0], "route/allow_all/0");

    // Remove a route
    error = router.removeRoute("route/allow_all/0");
    EXPECT_FALSE(error.has_value());

    // List routes
    routes = router.listRoutes();
    EXPECT_EQ(routes.size(), 0);
}
