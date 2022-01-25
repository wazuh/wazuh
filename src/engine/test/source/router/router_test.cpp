/**
 * @brief Router Test Suite
 */
#include "router/router.hpp"

#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "nlohmann/json.hpp"
#include "router_test.hpp"
#include "rxcpp/rx-test.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"

using json = nlohmann::ordered_json;

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

// Util to generate a json, with the current date
// as the wazuh.event.ingested value.
json JSONGenerator(int id, std::string name, std::string source)
{
    auto t = std::time(nullptr);
    auto tm = *std::gmtime(&t);

    std::string cstr(30, '\0');
    auto len = std::strftime(&cstr[0], cstr.size(), "%FT%TZ%z", &tm);
    cstr.erase(len, std::string::npos);

    return json{
        {"event",
         {
             {"original", "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},
         }},
        {"wazuh",
         {
             {"agent",
              {
                  {"id", "001"},
                  {"name", "agentSim"},
                  {"version", "PoC"},
              }},
             {"event",
              {
                  {"format", "text"},
                  {"id", id},
                  {"ingested", cstr},
                  {"kind", "event"},
              }},
             {"host",
              {
                  {"architecture", "x86_64"},
                  {"hostname", "hive"},
                  {"ip", "127.0.1.1"},
                  {"mac", "B0:7D:64:11:B3:13"},
                  {"os",
                   {
                       {"kernel", "5.14.14-arch1-1"},
                       {"name", "Linux"},
                       {"type", "posix"},
                       {"version", "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"},
                   }},
              }},
             {"module",
              {
                  {"name", name},
                  {"source", source},
              }},
         }},
    };
}

TEST(RouterTest, WhiteBoard)
{
    auto handler = [](rxcpp::subscriber<json> s)
    {
        s.on_next(JSONGenerator(1, "logcollector", "apache-access"));
        s.on_next(JSONGenerator(2, "logcollector", "apache-error"));
        s.on_completed();
    };

    auto router = rxcpp::observable<>::create<json>(handler);

    auto r1 = router.filter([](const json j) { return j.at("wazuh").at("module").at("name") == "logcollector"; });

    auto r2 = router.filter([](const json j) { return j.at("wazuh").at("module").at("name") == "logcollector"; });

    rxcpp::subjects::subject<json> s;

    r1.concat(r2).subscribe(s.get_subscriber());

    s.get_observable().subscribe([](const json j) { GTEST_COUT << "on_next " << std::endl; },
                                 []() { GTEST_COUT << "on_complete" << std::endl; });

    // auto env = std::begin(envs);

    // for(auto iter { std::begin(envs) }; iter != std::end(envs); ++iter) {
    //   GTEST_COUT << std::get<0>(*iter) << std::endl;
    //}
}

TEST(RouterTestAdd, AddSingleRoute)
{
    // Protocol Handler from server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [builder](std::string name) { return builder->build(name, "logcollector"); };

    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j)
    { return j.at("wazuh").at("module").at("name") == "logcollector"; };

    router->add(std::string("test_route"), filter, std::string("test_environment"));
}

TEST(RouterTestAdd, AddSingleRouteAndSendAMessage)
{

    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    rxcpp::subjects::subject<json> built;

    auto testBuilder = [&built, builder](std::string name)
    {
        built = builder->build(name, "logcollector");
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j)
    { return j.at("wazuh").at("module").at("name") == "logcollector"; };

    router->add(std::string("test_route"), filter, std::string("test_environment"));

    // Test
    std::atomic<int> got = 0;
    std::atomic<int> expected = 1;
    built.get_observable().subscribe(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    auto w = fph->run(1);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, 1);
}

TEST(RouterTestAdd, AddSingleRouteAndSend100Message)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    rxcpp::subjects::subject<json> built;

    auto testBuilder = [&built, builder](std::string name)
    {
        built = builder->build(name, "logcollector");
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j)
    { return j.at("wazuh").at("module").at("name") == "logcollector"; };

    router->add(std::string("test_route"), filter, std::string("test_environment"));

    // Test
    std::atomic<int> got = 0;
    std::atomic<int> expected = 100;
    built.get_observable().subscribe(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    auto w = fph->run(100);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, 100);
}

TEST(RouterTestAdd, AddSingleRouteAndFilterOut100Message)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test

    std::atomic<int> got = 0;
    std::atomic<int> expected = 0;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j) { return j.at("wazuh").at("module").at("name") == "unknown"; };

    router->add(std::string("test_route"), filter, std::string("test_environment"));

    // Run
    auto w = fph->run(100);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, expected);
}

TEST(RouterTestAdd, AddSingleRouteAndFilterOut5Of10)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test

    std::atomic<int> got = 0;
    std::atomic<int> expected = 5;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    int counter = 0;
    std::function<bool(json)> filter = [&counter](const json j)
    {
        ++counter;
        return counter % 2 == 0;
    };

    router->add(std::string("test_route"), filter, std::string("test_environment"));

    // Run
    auto w = fph->run(10);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, expected);
}

TEST(RouterTestAdd, AddTwoRoutes)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test
    std::atomic<int> got = 0;
    int expected = 10;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    // Add route 1
    std::atomic<int> r1got = 0;
    std::atomic<int> r1expected = 10;

    std::function<bool(json)> f1 = [&r1got](const json j)
    {
        ++r1got;
        return r1got % 2 == 0;
    };

    try
    {
        router->add(std::string("test_route_1"), f1, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }

    // Add route 2 for the same environment
    std::atomic<int> r2got = 0;
    std::atomic<int> r2expected = 10;
    std::function<bool(json)> f2 = [&r2got](const json j)
    {
        ++r2got;
        return r2got % 2 != 0;
    };
    try
    {
        router->add(std::string("test_route_2"), f2, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }
    // Run
    auto w = fph->run(10);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, expected);
    ASSERT_EQ(r1got, r1expected);
    ASSERT_EQ(r2got, r2expected);
}

TEST(RouterTestAdd, AddADuplicateRoute)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test
    std::atomic<int> got = 0;
    int expected = 10;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    // Add route 1
    std::atomic<int> r1got = 0;
    std::atomic<int> r1expected = 10;

    std::function<bool(json)> f1 = [&r1got](const json j)
    {
        ++r1got;
        return r1got % 2 == 0;
    };

    router->add(std::string("test_route"), f1, std::string("test_environment"));

    try
    {
        router->add(std::string("test_route"), f1, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to add a route, but it's name is already in use by another route", err.what());
    }
}

TEST(RouterTestAdd, AddTwoRoutesHalf)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test
    std::atomic<int> got = 0;
    int expected = 5;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    // Add route 1
    std::atomic<int> r1got = 0;
    std::atomic<int> r1expected = 10;

    std::function<bool(json)> f1 = [&r1got](const json j)
    {
        ++r1got;
        return r1got % 2 == 0;
    };

    router->add(std::string("test_route_1"), f1, std::string("test_environment"));

    // Add route 2 for the same environment
    std::atomic<int> r2got = 0;
    std::atomic<int> r2expected = 10;
    std::function<bool(json)> f2 = [&r2got](const json j)
    {
        ++r2got;
        return false;
    };

    router->add(std::string("test_route_2"), f2, std::string("test_environment"));

    // Run
    auto w = fph->run(10);
    std::chrono::milliseconds span(1000);
    while (w.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, expected);
    ASSERT_EQ(r1got, r1expected);
    ASSERT_EQ(r2got, r2expected);
}

TEST(RouterTestRemove, RemoveRoute)
{
    // Protocol Handler from server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [builder](std::string name) { return builder->build(name, "logcollector"); };

    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j)
    { return j.at("wazuh").at("module").at("name") == "logcollector"; };

    router->add(std::string("test_route"), filter, std::string("test_environment"));
    ASSERT_EQ(router->list().size(), 1);

    try
    {
        router->remove(std::string("test_route"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
        FAIL();
    }
    ASSERT_EQ(router->list().size(), 0);
}

TEST(RouterTestRemove, RemoveRouteAndEnvironment)
{
    // Protocol Handler from server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    int count = 0;
    auto testBuilder = [&count, builder](std::string name)
    {
        ++count;
        return builder->build(name, "logcollector");
    };

    auto router = new Router::Router<json>(handler, testBuilder);

    std::function<bool(json)> filter = [](const json j)
    { return j.at("wazuh").at("module").at("name") == "logcollector"; };

    router->add(std::string("test_route_1"), filter, std::string("test_environment"));
    ASSERT_EQ(router->list().size(), 1);

    router->add(std::string("test_route_2"), filter, std::string("test_environment"));
    ASSERT_EQ(router->list().size(), 2);

    try
    {
        router->remove(std::string("test_route_1"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
        FAIL();
    }
    ASSERT_EQ(router->list().size(), 1);

    try
    {
        router->remove(std::string("test_route_2"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
        FAIL();
    }
    ASSERT_EQ(router->list().size(), 0);

    router->add(std::string("test_route_3"), filter, std::string("test_environment"));
    ASSERT_EQ(router->list().size(), 1);

    ASSERT_EQ(count, 2);
}

TEST(RouterTestRemove, RemoveRouteStopReceiving)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test
    std::atomic<int> got = 0;
    std::atomic<int> expected = 5;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [](std::exception_ptr ep)
        {
            try
            {
                std::rethrow_exception(ep);
            }
            catch (const std::exception & ex)
            {
                GTEST_COUT << "OnError: " << ex.what() << std::endl;
            }
        },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    // Add route 1
    int r1got = 0;
    int r1expected = 10;

    std::function<bool(json)> f1 = [&r1got](const json j)
    {
        ++r1got;
        return r1got % 2 == 0;
    };

    try
    {
        router->add(std::string("test_route_1"), f1, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }

    // Add route 2 for the same environment
    std::atomic<int> r2got = 0;
    std::atomic<int> r2expected = 10;
    std::function<bool(json)> f2 = [&r2got](const json j)
    {
        ++r2got;
        return false;
    };

    try
    {
        router->add(std::string("test_route_2"), f2, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }

    // Run
    auto w = fph->run(10);
    std::chrono::milliseconds span(1000);
    GTEST_COUT << '.';
    while (w.wait_for(span) == std::future_status::timeout)
    {
        std::cerr << '.' << std::flush;
    }
    std::cerr << std::endl;

    ASSERT_EQ(got, expected);
    ASSERT_EQ(r1got, r1expected);
    ASSERT_EQ(r2got, r2expected);

    try
    {
        router->remove(std::string("test_route_1"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
        FAIL();
    }

    // Run again and test that route 1 is not sending events to the
    // environment, so it got no new event, as route 2 does not let
    // pass any event.
    auto w2 = fph->run(10);
    while (w2.wait_for(span) == std::future_status::timeout)
        GTEST_COUT << '.' << std::flush;

    ASSERT_EQ(got, expected);
    ASSERT_EQ(r1got, r1expected);
    ASSERT_EQ(r2got, r2expected);
}

TEST(RouterTestRemove, RemoveRouteWhileReceiving)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test

    std::atomic<int> got = 0;
    std::atomic<int> expected = 10000;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    std::atomic<int> counter = 0;
    std::function<bool(json)> filter = [&counter](const json j)
    {
        ++counter;
        return counter % 2 == 0;
    };

    try
    {
        router->add(std::string("test_route"), filter, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }

    // Run
    auto w = fph->run(10000);
    std::chrono::milliseconds span(1000);
    GTEST_COUT << '.';
    while (w.wait_for(span) == std::future_status::timeout)
    {
        // Remove the route while we're still receiving
        std::cerr << '.' << std::flush;
        try
        {
            router->remove(std::string("test_route"));
        }
        catch (std::invalid_argument & err)
        {
            ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
            FAIL();
        }
    }
    std::cerr << std::endl;
    // We should bet less messages than we sent
    ASSERT_LT(got, expected);
}

TEST(RouterTestRemove, AddReceiveRemoveReceiveAddReceive)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Test

    std::atomic<int> got = 0;
    std::atomic<int> expected = 10000;

    auto testSub = rxcpp::make_subscriber<json>(
        [&got](const json j) { ++got; },
        [&got, &expected]() { GTEST_COUT << "Builder expects " << expected << " and got " << got << std::endl; });

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [testSub, builder](std::string name)
    {
        auto built = builder->build(name, "logcollector");
        built.get_observable().subscribe(testSub);
        return built;
    };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    std::atomic<int> counter = 0;
    std::function<bool(json)> filter = [&counter](const json j)
    {
        ++counter;
        return counter % 2 == 0;
    };

    try
    {
        router->add(std::string("test_route"), filter, std::string("test_environment"));
    }
    catch (std::invalid_argument & err)
    {
        FAIL();
    }

    // Run
    auto w = fph->run(10000);
    std::chrono::milliseconds span(1000);

    try
    {
        router->remove(std::string("test_route"));
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
        FAIL();
    }
    router->add(std::string("test_route"), filter, std::string("test_environment"));

    GTEST_COUT << '.';
    while (w.wait_for(span) == std::future_status::timeout)
    {
        std::cerr << '.' << std::flush;
    }
    std::cerr << std::endl;

    // We should bet less messages than we sent
    ASSERT_LT(got, expected);
}

TEST(RouterTestRemove, RemoveNonExistentRoute)
{
    // Server
    auto fph = new FakeProtocolHandler<json>([](int i) { return JSONGenerator(i, "logcollector", "apache-access"); });

    auto handler = [&, fph](rxcpp::subscriber<json> s)
    {
        fph->on_message = [&, s](const json j) { s.on_next(j); };

        fph->on_close = [&, s]() { s.on_completed(); };
    };

    // Builder
    auto builder = new FakeBuilder<json>();

    auto testBuilder = [builder](std::string name) { return builder->build(name, "logcollector"); };

    // Router
    auto router = new Router::Router<json>(handler, testBuilder);

    // Test
    try
    {
        router->remove("unknown");
    }
    catch (std::invalid_argument & err)
    {
        ASSERT_STREQ("Tried to delete a route, but it's name is not in the route table.", err.what());
    }
}

TEST(RXCPPTest, StepbyStepScheduler)
{
    auto sc = rxcpp::schedulers::make_test();
    auto worker = sc.create_worker();
    auto test = rxcpp::identity_same_worker(worker);
    int count = 0;

    auto router = rxcpp::observable<>::interval(std::chrono::milliseconds(1),
                                                test // on the test scheduler
    );

    auto route = router.filter([](int i) { return i % 2; });

    rxcpp::subjects::subject<long int> subject;

    route.subscribe(subject.get_subscriber());

    auto sub = subject.get_observable().subscribe([&count](int) { count++; });

    worker.sleep(2 /* ms */);
    ASSERT_EQ(count, 0);

    worker.advance_by(8 /* ms */);
    ASSERT_EQ(count, 5);

    sub.unsubscribe();

    worker.advance_by(8 /* ms */);
    ASSERT_EQ(count, 5);
}
