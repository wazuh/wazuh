#include <router/router.hpp>

#include <string>

#include <gtest/gtest.h>

#include "register.hpp"

#include "testAuxiliar/routerAuxiliarFunctions.hpp"

TEST(Router, build_ok)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();
    auto store = aux::getFakeStore();

    router::Router router(builder, store);
}
// Add more test
TEST(Router, build_fail)
{

    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();
    auto store = aux::getFakeStore();

    try {
        router::Router router(builder, store, 0);
        FAIL() << "Router: The router was created with 0 threads";
    } catch (const std::runtime_error& e) {
        ASSERT_STREQ(e.what(), "Router: The number of threads must be between 1 and 128.");
    } catch (...) {
        FAIL() << "Router: The router was created with 0 threads";
    }

    try {
        router::Router router(nullptr, store, 1);
        FAIL() << "Router: The router was created with a null builder";
    } catch (const std::runtime_error& e) {
        ASSERT_STREQ(e.what(), "Router: Builder can't be null.");
    } catch (...) {
        FAIL() << "Router: The router was created with a null builder";
    }

    try {
        router::Router router(builder, nullptr, 1);
        FAIL() << "Router: The router was created with a null store";
    } catch (const std::runtime_error& e) {
        ASSERT_STREQ(e.what(), "Router: Store can't be null.");
    } catch (...) {
        FAIL() << "Router: The router was created with a null store";
    }
}

TEST(Router, add_list_remove_routes)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();
    auto store = aux::getFakeStore();

    router::Router router(builder, store);

    EXPECT_EQ(router.getRouteTable().size(), 0);

    // Add a route
    auto error = router.addRoute("filter/e_wazuh_queue/0", "environment/env_1/0", 2);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto routes = router.getRouteTable();
    EXPECT_EQ(routes.size(), 1);

    // Add a route
    error = router.addRoute("filter/allow_all/0", "environment/env_2/0", 1);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;

    std::get<0>(list[0]) == "filter/allow_all/0";
    std::get<0>(list[1]) == "filter/e_wazuh_queue/0";

    // Change priority
    error = router.changeRoutePriority("filter/e_wazuh_queue/0", 0);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;
    std::get<0>(list[0]) == "filter/e_wazuh_queue/0";
    std::get<0>(list[1]) == "filter/allow_all/0";

    // Remove a route
    error = router.removeRoute("filter/e_wazuh_queue/0");
    ASSERT_FALSE(error.has_value());

    // List routes
    routes = router.getRouteTable();
    EXPECT_EQ(routes.size(), 1);
    EXPECT_EQ(std::get<0>(routes[0]), "filter/allow_all/0");

    // Remove a route
    error = router.removeRoute("filter/allow_all/0");
    ASSERT_FALSE(error.has_value());

    // List routes
    routes = router.getRouteTable();
    EXPECT_EQ(routes.size(), 0);
}

TEST(Router, priorityChanges) {
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();
    auto store = aux::getFakeStore();

    router::Router router(builder, store);

    // Add a route
    auto error = router.addRoute("filter/e_wazuh_queue/0", "environment/env_1/0", 2);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto routes = router.getRouteTable();
    EXPECT_EQ(routes.size(), 1);

    // Add a route
    error = router.addRoute("filter/allow_all/0", "environment/env_2/0", 1);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    auto list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;

    std::get<0>(list[0]) == "filter/allow_all/0";
    std::get<0>(list[1]) == "filter/e_wazuh_queue/0";

    // Change priority
    error = router.changeRoutePriority("filter/allow_all/0", 100);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    error = router.changeRoutePriority("filter/e_wazuh_queue/0", 200);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;
    std::get<0>(list[0]) == "filter/e_wazuh_queue/0";
    std::get<0>(list[1]) == "filter/allow_all/0";

    // Change priority
    error = router.changeRoutePriority("filter/allow_all/0", 201);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    error = router.changeRoutePriority("filter/e_wazuh_queue/0", 100);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // List routes
    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;
    std::get<0>(list[0]) == "filter/allow_all/0";
    std::get<0>(list[1]) == "filter/e_wazuh_queue/0";


    // Change same priority
    const auto p_allow_all = 1;
    const auto p_e_wazuh_queue = 2;

    error = router.changeRoutePriority("filter/allow_all/0", p_allow_all);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    error = router.changeRoutePriority("filter/allow_all/0", p_allow_all);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    error = router.changeRoutePriority("filter/e_wazuh_queue/0", p_e_wazuh_queue);
    ASSERT_FALSE(error.has_value()) << error.value().message;
    error = router.changeRoutePriority("filter/e_wazuh_queue/0", p_e_wazuh_queue);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // Change negative priority
    error = router.changeRoutePriority("filter/allow_all/0", -1);
    ASSERT_TRUE(error.has_value()) << error.value().message;
    ASSERT_STREQ(error.value().message.c_str(), "Route 'filter/allow_all/0' has an invalid priority. Priority must be between 0 and 255.");
    error = router.changeRoutePriority("filter/e_wazuh_queue/0", -1);
    ASSERT_TRUE(error.has_value()) << error.value().message;
    ASSERT_STREQ(error.value().message.c_str(), "Route 'filter/e_wazuh_queue/0' has an invalid priority. Priority must be between 0 and 255.");

    // Check priority
    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;
    EXPECT_EQ(std::get<1>(list[0]), p_allow_all);
    EXPECT_EQ(std::get<1>(list[1]), p_e_wazuh_queue);

    // Change out of range priority
    error = router.changeRoutePriority("filter/allow_all/0", 256);
    ASSERT_TRUE(error.has_value()) << error.value().message;
    ASSERT_STREQ(error.value().message.c_str(), "Route 'filter/allow_all/0' has an invalid priority. Priority must be between 0 and 255.");
    error = router.changeRoutePriority("filter/e_wazuh_queue/0", 256);
    ASSERT_TRUE(error.has_value()) << error.value().message;
    ASSERT_STREQ(error.value().message.c_str(), "Route 'filter/e_wazuh_queue/0' has an invalid priority. Priority must be between 0 and 255.");

    // Check priority
    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2) << error.value().message;
    EXPECT_EQ(std::get<1>(list[0]), p_allow_all);
    EXPECT_EQ(std::get<1>(list[1]), p_e_wazuh_queue);

}


TEST(Router, checkRouting) {
    const auto sleepTime = (const struct timespec[]){{0, 100000000L}};
    const auto ENV_A1 = "deco_A1";
    const auto ENV_B2 = "deco_B2";
    const auto ENV_C3 = "deco_C3";
    const auto PATH_DECODER = json::Json::formatJsonPath("~decoder");

    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);
    auto builder = aux::getFakeBuilder();
    auto store = aux::getFakeStore();

    // Run the router
    auto testQueue = aux::testQueue{};

    router::Router router(builder, store);
    router.run(testQueue.getQueue());

    /*************************************************************************************
     *     Verify that the routes are working  before start the tests
    *************************************************************************************/
    /* Check route 1 */
    // Create a fake message
    auto message = aux::createFakeMessage();

    // Add a route
    auto error = router.addRoute("filter/allow_all_A1/0", "environment/env_A1/0", 101);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // Push the message && and check
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    auto decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_A1) << message->prettyStr();

    router.removeRoute("filter/allow_all_A1/0");

    /* Check route 2 */
    // Create a fake message
    message = aux::createFakeMessage();

    error = router.addRoute("filter/allow_all_B2/0", "environment/env_B2/0", 102);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // Push the message && and check
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_B2) << message->prettyStr();

    router.removeRoute("filter/allow_all_B2/0");

    /* Check route 3 */
    // Create a fake message
    message = aux::createFakeMessage();

    error = router.addRoute("filter/allow_all_C3/0", "environment/env_C3/0", 103);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    // Push the message && and check
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_C3) << message->prettyStr();

    router.removeRoute("filter/allow_all_C3/0");

    /*************************************************************************************
    *                  Add 3 routes and test the priority
    *************************************************************************************/
    auto list = router.getRouteTable();
    EXPECT_EQ(list.size(), 0);

    /* Add route 1 */
    error = router.addRoute("filter/allow_all_A1/0", "environment/env_A1/0", 101);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    /* Add route 2 */
    error = router.addRoute("filter/allow_all_B2/0", "environment/env_B2/0", 102);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    /* Add route 3 */
    error = router.addRoute("filter/allow_all_C3/0", "environment/env_C3/0", 103);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);

    /* Check route 1 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_A1) << std::get<0>(router.getRouteTable()[0]);

    // Move route 1 to the end
    error = router.changeRoutePriority("filter/allow_all_A1/0", 201);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_B2/0");

    /* Check route 2 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_B2) << std::get<0>(router.getRouteTable()[0]);

    // Move route 2 to the end
    error = router.changeRoutePriority("filter/allow_all_B2/0", 202);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_C3/0");

    /* Check route 3 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_C3) << std::get<0>(router.getRouteTable()[0]);

    // Move route 3 to the end
    error = router.changeRoutePriority("filter/allow_all_C3/0", 203);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_A1/0");

    /* Check route 1 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_A1) << std::get<0>(router.getRouteTable()[0]);

    // Move route 1 to the begin
    error = router.changeRoutePriority("filter/allow_all_A1/0", 50);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_A1/0");

    /* Check route 1 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_A1) << std::get<0>(router.getRouteTable()[0]);

    // Delete route 3
    error = router.removeRoute("filter/allow_all_C3/0");
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 2);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_A1/0");
    EXPECT_EQ(std::get<1>(list[0]), 50);

    /* Check route 1 */
    // Add route 3 in first position
    error = router.addRoute("filter/allow_all_C3/0", "environment/env_C3/0", 1);
    ASSERT_FALSE(error.has_value()) << error.value().message;

    list = router.getRouteTable();
    EXPECT_EQ(list.size(), 3);
    EXPECT_EQ(std::get<0>(list[0]), "filter/allow_all_C3/0");
    EXPECT_EQ(std::get<1>(list[0]), 1);

    /* Check route 3 */
    message = aux::createFakeMessage();
    testQueue.pushEvent(message);
    nanosleep(sleepTime, NULL);

    decoder = message->getString(PATH_DECODER);
    ASSERT_TRUE(decoder.has_value()) << message->prettyStr();
    ASSERT_STREQ(decoder.value().c_str(), ENV_C3) << std::get<0>(router.getRouteTable()[0]);

    router.stop();

}
