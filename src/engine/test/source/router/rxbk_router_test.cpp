#include <router/router.hpp>

#include <string>

#include <gtest/gtest.h>

#include <rxbk/rxFactory.hpp>
#include "register.hpp"
#include "parseEvent.hpp"

namespace
{

void printEventAndTracer(rxbk::Controller& controller) {
    {
        // output
        auto stderrSubscriber = rxcpp::make_subscriber<rxbk::RxEvent>(
            [&](const rxbk::RxEvent& event) { std::cout << event->payload()->prettyStr() << std::endl; });
        controller.getOutput().subscribe(stderrSubscriber);
    }
    {
        // Trace
        controller.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
            [](const std::string& event) { std::cout << "Trace: " << event << std::endl; }));
    }
}

const json::Json jRouteExistQueue = json::Json(R"(
        {
            "name": "Exist wazuh.queue",
            "check": [
                {
                    "wazuh.queue": "+ef_exists"
                },
                {
                    "wazuh.no_queue": "+ef_exists"
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

TEST(Router_rxkb, get_expression_2_routes)
{
    auto registry = std::make_shared<builder::internals::Registry>();
    builder::internals::registerBuilders(registry);

    std::shared_ptr<router::Router> router = std::make_shared<router::Router>(registry);

    std::optional<base::Error> error = {};
    ASSERT_FALSE(error = router->addRoute(jRouteAllowAll)) << error.value().message;
    ASSERT_FALSE(error = router->addRoute(jRouteExistQueue)) << error.value().message;

    std::unordered_set<std::string> assetsNames {};
    for (const auto& route : router->getRouteNames())
    {
        assetsNames.insert(route);
    }
    auto controller = rxbk::buildRxPipeline(router->getExpression()[0], assetsNames);
    printEventAndTracer(controller);

    // Inyect event
    std::string event {R"(2:192.168.0.5:Mensaje Syslog)"};
    try
    {
        auto result = base::result::makeSuccess(base::parseEvent::parseOssecEvent(event));


        controller.ingestEvent(std::make_shared<base::result::Result<base::Event>>(std::move(result)));
    }
    catch (const std::exception& e)
    {
        FAIL() << fmt::format("Engine runtime environment: An error "
                        "ocurred while parsing a message: \"{}\"",
                        e.what());
    }
}
