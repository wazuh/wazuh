#include "testUtils.hpp"

#include "_builder/builder.hpp"
#include "_builder/event.hpp"
#include "_builder/json.hpp"
#include "_builder/operation.hpp"
#include "_builder/registry.hpp"
#include "_builder/rxcppBackend/rxcppFactory.hpp"
#include "builder_test.hpp"

TEST(Builder, EndToEnd)
{
    FakeCatalog catalog;
    builder::Builder builder {catalog};

    std::string env = "testEnvironment";
    auto connectableEnv = builder.buildEnvironment(env);
    auto asGroup =
        connectableEnv->getPtr<builder::internals::ConnectableGroup>();
    GTEST_COUT << builder::internals::getGraphivStr(asGroup) << std::endl << std::endl;
    // builder::internals::Optimize(connectableEnv);
    // asGroup =
    //     connectableEnv->getPtr<builder::internals::ConnectableGroup>();
    // GTEST_COUT << builder::internals::getGraphivStr(asGroup) << std::endl;


    auto rxcppController =
        builder::internals::rxcppBackend::buildRxcppPipeline(connectableEnv);
    rxcppController.listenOnAllTrace(rxcpp::make_subscriber<std::string>(
        [](std::string s) { GTEST_COUT << s << std::endl; }));
    rxcppController.m_envOutput.subscribe([](builder::internals::rxcppBackend::RxcppEvent
    e) {
        GTEST_COUT << e->popEvent().payload() << std::endl;
    });
    rxcppController.ingestEvent(std::make_shared<Result<Event<Json>>>(
        makeSuccess(Event<Json> {Json {R"({
            "source": "test",
            "type": "A",
            "threat": {
                "level": 6
            },
            "weird": {
                "field": "value"
            }
        })"}}, "init")));
}
