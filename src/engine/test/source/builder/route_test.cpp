#include "route_test.hpp"

#include "parseEvent.hpp"
#include "register.hpp"

#include <gtest/gtest.h>

TEST(Route, build_ok)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    ASSERT_NO_THROW(builder::Route(testRoutes::allowAll, registry));
    ASSERT_NO_THROW(builder::Route(testRoutes::existQNQ, registry));
    ASSERT_NO_THROW(builder::Route(testRoutes::queue49or50, registry));
}

TEST(Route, check_filters)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    auto routeNoChecks = builder::Route {testRoutes::allowAll, registry};
    auto routeCheckQNQ = builder::Route {testRoutes::existQNQ, registry};
    auto routeCheckAndOr = builder::Route {testRoutes::queue49or50, registry};

    std::vector<base::Event> events {};

    ASSERT_NO_THROW(std::transform(testRoutes::sampleEvents4550Str.begin(),
                                   testRoutes::sampleEvents4550Str.end(),
                                   std::back_inserter(events),
                                   [](const auto& eventStr) { return base::parseEvent::parseOssecEvent(eventStr); }))
        << "Error parsing events";

    for (const auto& event : events)
    {
        // Route with no checks acepts all events
        ASSERT_TRUE(routeNoChecks.accept(event)) << event->prettyStr();

        ASSERT_TRUE(routeCheckAndOr.accept(event)) << event->prettyStr();
        auto tmpEvent = std::make_shared<json::Json>(*event);
        tmpEvent->setInt(48, json::Json::formatJsonPath("wazuh.queue"));
        ASSERT_FALSE(routeCheckAndOr.accept(tmpEvent)) << tmpEvent->prettyStr();

        ASSERT_FALSE(routeCheckQNQ.accept(event)) << event->prettyStr();
        tmpEvent->setInt(49, json::Json::formatJsonPath("wazuh.no_queue"));
        ASSERT_TRUE(routeCheckQNQ.accept(tmpEvent)) << tmpEvent->prettyStr();
    }
}
