#include "testUtils.hpp"

#include "_builder/builder.hpp"
#include "_builder/expression.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/registration.hpp"
#include "_builder/rxcppBackend/rxcppFactory.hpp"
#include "builder_test.hpp"

TEST(Builder, EndToEnd)
{
    builder::internals::registerBuilders();
    FakeCatalog catalog;
    builder::Builder builder {catalog};

    std::string env = "testEnvironment";
    auto environment = builder.buildEnvironment(env);
    GTEST_COUT << environment.getGraphivzStr() << std::endl;
    auto expression = environment.getExpression();
    GTEST_COUT << toGraphvizStr(expression) << std::endl;
    // auto asGroup =
    //     connectableEnv->getPtr<builder::internals::ConnectableGroup>();
    // GTEST_COUT << builder::internals::getGraphivStr(asGroup) << std::endl <<
    // std::endl;
    // // builder::internals::Optimize(connectableEnv);
    // // asGroup =
    // //     connectableEnv->getPtr<builder::internals::ConnectableGroup>();
    // // GTEST_COUT << builder::internals::getGraphivStr(asGroup) << std::endl;

    auto rxcppController =
        builder::internals::rxcppBackend::buildRxcppPipeline(environment);
    rxcppController.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
        [](std::string s) { GTEST_COUT << s << std::endl; }));
    rxcppController.m_envOutput.subscribe(
        [](builder::internals::rxcppBackend::RxcppEvent e)
        { GTEST_COUT << e->payload() << std::endl; });

    auto event1 = std::make_shared<Result<Event>>(makeSuccess(Event {Json {R"({
            "source": "test",
            "type": "A",
            "threat": {
                "level": 6
            },
            "weird": {
                "field": "value"
            }
        })"}}));
    GTEST_COUT << std::endl
               << std::endl
               << std::endl
               << "Sending event" << std::endl
               << event1->payload() << std::endl;
    rxcppController.ingestEvent(std::move(event1));

    event1 = std::make_shared<Result<Event>>(makeSuccess(Event {Json {R"({
            "source": "test",
            "type": "B",
            "threat": {
                "level": 6
            },
            "weird": {
                "field": "value"
            }
        })"}}));
    GTEST_COUT << std::endl
               << std::endl
               << std::endl
               << "Sending event" << std::endl
               << event1->payload() << std::endl;
    rxcppController.ingestEvent(std::move(event1));

    event1 = std::make_shared<Result<Event>>(makeSuccess(Event {Json {R"({
            "source": "test",
            "type": "A",
            "threat": {
                "level": 6
            },
            "weird": {
                "field": "value"
            }
        })"}}));
    GTEST_COUT << std::endl
               << std::endl
               << std::endl
               << "Sending event" << std::endl
               << event1->payload() << std::endl;
    rxcppController.ingestEvent(std::move(event1));
}
