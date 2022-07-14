#include <gtest/gtest.h>
#include <rxbk/rxFactory.hpp>

#include <memory>

using namespace rxbk;

/****************************************************************************************/
// Tracer tests
/****************************************************************************************/
TEST(rxbkTracerTest, DefaultConstructor)
{
    ASSERT_NO_THROW(Tracer {});
}

TEST(rxbkTracerTest, GetTracerFn)
{
    Tracer tracer;
    ASSERT_NO_THROW(tracer.getTracerFn("test"));
    auto fn = tracer.getTracerFn("test");
    ASSERT_NO_THROW(fn("test"));
}

TEST(rxbkTracerTest, SubscribeUnsubscribe)
{
    Tracer tracer;
    auto fakeLogger = [](const std::string& message) {
    };
    auto sub = rx::make_subscriber<std::string>(
        fakeLogger, [](auto) {}, []() {});
    rx::composite_subscription cs;
    ASSERT_NO_THROW(cs = tracer.subscribe(sub));
    ASSERT_NO_THROW(cs.unsubscribe());
}

TEST(rxbkTracerTest, UseCaseOneSubscriber)
{
    Tracer tracer;
    auto check = std::make_shared<bool>(false);
    auto fakeLogger = [check](const std::string& message)
    {
        *check = !*check;
    };
    auto sub = rx::make_subscriber<std::string>(
        fakeLogger, [](auto) {}, []() {});
    rx::composite_subscription cs;
    ASSERT_NO_THROW(cs = tracer.subscribe(sub));
    ASSERT_NO_THROW(tracer.getTracerFn("test")("test"));
    ASSERT_TRUE(*check);
    ASSERT_NO_THROW(cs.unsubscribe());
    ASSERT_NO_THROW(tracer.getTracerFn("test")("test"));
    ASSERT_TRUE(*check);
}

TEST(rxbkTracerTest, UseCaseMultipleSubscribers)
{
    Tracer tracer;
    rx::composite_subscription cs;
    std::vector<std::shared_ptr<bool>> checks;
    auto n = {0, 1, 2, 3, 4, 5};
    for (auto i : n)
    {
        auto check = std::make_shared<bool>(false);
        auto fakeLogger = [check](const std::string& message)
        {
            *check = !*check;
        };
        auto sub = rx::make_subscriber<std::string>(
            fakeLogger, [](auto) {}, []() {});
        ASSERT_NO_THROW(cs.add(tracer.subscribe(sub)));
        checks.push_back(check);
    }

    ASSERT_NO_THROW(tracer.getTracerFn("test")("test"));
    for (auto check : checks)
    {
        ASSERT_TRUE(*check);
    }
    cs.unsubscribe();
    ASSERT_NO_THROW(tracer.getTracerFn("test")("test"));
    for (auto check : checks)
    {
        ASSERT_TRUE(*check);
    }
}

/****************************************************************************************/
// Controller tests
/****************************************************************************************/
TEST(rxbkControllerTest, DefaultConstructor)
{
    ASSERT_NO_THROW(Controller {});
}

TEST(rxbkControllerTest, GetInternalInput)
{
    Controller controller;
    ASSERT_NO_THROW(controller.getInternalInput());
}

TEST(rxbkControllerTest, GetOutput)
{
    Controller controller;
    ASSERT_NO_THROW(controller.getOutput());
}

TEST(rxbkControllerTest, SetOutput)
{
    Controller controller;
    ASSERT_NO_THROW(controller.setOutput(Observable {}));
}

TEST(rxbkControllerTest, AddTracer)
{
    Controller controller;
    ASSERT_NO_THROW(controller.addTracer("tracer", Tracer {}));
}

TEST(rxbkControllerTest, ListenOnTrace)
{
    Controller controller;
    auto fakeLogger = [](const std::string& message) {
    };
    auto sub = rx::make_subscriber<std::string>(
        fakeLogger, [](auto) {}, []() {});
    ASSERT_THROW(controller.listenOnTrace("tracer", sub), std::runtime_error);
    ASSERT_NO_THROW(controller.addTracer("tracer", Tracer {}));
    ASSERT_NO_THROW(controller.listenOnTrace("tracer", sub));
}

TEST(rxbkControllerTest, ListenOnAllTrace)
{
    Controller controller;
    auto fakeLogger = [](const std::string& message) {
    };
    auto sub = rx::make_subscriber<std::string>(
        fakeLogger, [](auto) {}, []() {});
    ASSERT_NO_THROW(controller.listenOnAllTrace(sub));
    ASSERT_NO_THROW(controller.addTracer("tracer", Tracer {}));
    ASSERT_NO_THROW(controller.listenOnAllTrace(sub));
}

TEST(rxbkControllerTest, IngestEvent)
{
    Controller controller;
    auto event = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(std::make_shared<json::Json>(R"({})")));
    ASSERT_NO_THROW(controller.ingestEvent(std::move(event)));
}

TEST(rxbkControllerTest, Complete)
{
    Controller controller;
    ASSERT_NO_THROW(controller.complete());
}

// TODO: use somenthing more elaborated and readable
TEST(rxbkControllerTest, UseCase)
{
    Controller controller;
    auto event = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(
            std::make_shared<json::Json>(R"({"field": "value"})")));

    auto tracerFn1 = controller.addTracer("tracer1", Tracer {});
    auto tracerFn2 = controller.addTracer("tracer2", Tracer {});

    std::vector<std::shared_ptr<bool>> checksAll;
    rx::composite_subscription csAll;
    auto n = {0, 1, 2, 3, 4, 5};
    for (auto i : n)
    {
        auto check = std::make_shared<bool>(false);
        auto fakeLogger = [check](const std::string& message)
        {
            *check = !*check;
        };
        auto sub = rx::make_subscriber<std::string>(
            fakeLogger, [](auto) {}, []() {});
        ASSERT_NO_THROW(csAll.add(controller.listenOnAllTrace(sub)));
        checksAll.push_back(check);
    }

    std::vector<std::shared_ptr<bool>> checksSpecific;
    rx::composite_subscription csSpecific;
    for (auto i : n)
    {
        auto check = std::make_shared<bool>(false);
        auto fakeLogger = [check](const std::string& message)
        {
            *check = !*check;
        };
        auto sub = rx::make_subscriber<std::string>(
            fakeLogger, [](auto) {}, []() {});
        ASSERT_NO_THROW(csSpecific.add(controller.listenOnTrace("tracer2", sub)));
        checksSpecific.push_back(check);
    }

    ASSERT_NO_THROW(controller.setOutput(controller.getInternalInput().tap(
        [=](auto event)
        {
            ASSERT_NO_THROW(tracerFn1("test"));
            ASSERT_NO_THROW(tracerFn2("test"));
        },
        [](auto) {},
        []() {})));
    ASSERT_NO_THROW(controller.getOutput().subscribe());

    ASSERT_NO_THROW(controller.ingestEvent(std::shared_ptr(event)));
    for (auto check : checksAll)
    {
        ASSERT_FALSE(*check);
    }
    for (auto check : checksSpecific)
    {
        ASSERT_TRUE(*check);
    }
    csAll.unsubscribe();
    for (auto check : checksAll)
    {
        check.reset();
    }
    ASSERT_NO_THROW(controller.ingestEvent(std::shared_ptr(event)));
    for (auto check : checksSpecific)
    {
        ASSERT_FALSE(*check);
    }
    csSpecific.unsubscribe();
    ASSERT_NO_THROW(controller.ingestEvent(std::shared_ptr(event)));
    for (auto check : checksSpecific)
    {
        ASSERT_FALSE(*check);
    }

    ASSERT_NO_THROW(controller.complete());
}

/****************************************************************************************/
// Factory tests
/****************************************************************************************/
TEST(rxbkFactoryTest, rxFactoryOneTermWithTrace)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));
    auto trace = "test trace";
    auto traceEvent = "[test] test trace";

    Controller controller;
    base::Expression expr = base::Term<base::EngineOp>::create(
        "test", [=](base::Event e) { return base::result::makeSuccess(e, trace); });
    rx::subjects::subject<RxEvent> inputSubj;

    Observable output;
    ASSERT_NO_THROW(
        output = rxFactory(inputSubj.get_observable(), {"test"}, expr, controller));
    controller.listenOnTrace(
        "test",
        rx::make_subscriber<std::string>([=](const std::string& message)
                                         { ASSERT_EQ(message, traceEvent); }));
    output.subscribe(
        [=](RxEvent e)
        {
            ASSERT_TRUE(e->success());
            ASSERT_EQ(e->payload(), event);
            ASSERT_EQ(e->trace(), trace);
        });

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

TEST(rxbkFactoryTest, rxFactoryAndOfTerms)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));

    auto termSuccess = base::Term<base::EngineOp>::create(
        "testSucces", [](base::Event e) { return base::result::makeSuccess(e); });
    auto termFailure = base::Term<base::EngineOp>::create(
        "testFailure", [](base::Event e) { return base::result::makeFailure(e); });
    // This term shoul not be executed
    auto termError = base::Term<base::EngineOp>::create(
        "testError",
        [](base::Event e) -> base::result::Result<base::Event>
        {
            throw std::runtime_error("Executed term "
                                     "that should not "
                                     "be executed");
        });

    Controller controller;
    rx::subjects::subject<RxEvent> inputSubj;
    std::unordered_set<std::string> names;

    // All success
    auto output1 =
        rxFactory(inputSubj.get_observable(),
                  names,
                  base::And::create("And1", {termSuccess, termSuccess, termSuccess}),
                  controller,
                  [](auto s) {});
    output1.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Failure last
    auto output2 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::And::create("And2", {termSuccess, termSuccess, termFailure}),
                  controller,
                  [](auto s) {});
    output2.subscribe([](auto e) { ASSERT_TRUE(e->failure()); });

    // Failure middle
    auto output3 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::And::create("And3", {termSuccess, termFailure, termError}),
                  controller,
                  [](auto s) {});
    output3.subscribe(
        [](auto e) { ASSERT_TRUE(e->failure()); }, [](auto) { FAIL(); }, []() {});

    // Failure first
    auto output4 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::And::create("And4", {termFailure, termError, termError}),
                  controller,
                  [](auto s) {});
    output4.subscribe(
        [](auto e) { ASSERT_TRUE(e->failure()); }, [](auto) { FAIL(); }, []() {});

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

TEST(rxbkFactoryTest, rxFactoryOrOfTerms)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));

    auto termSuccess = base::Term<base::EngineOp>::create(
        "testSucces", [](base::Event e) { return base::result::makeSuccess(e); });
    auto termFailure = base::Term<base::EngineOp>::create(
        "testFailure", [](base::Event e) { return base::result::makeFailure(e); });
    // This term shoul not be executed
    auto termError = base::Term<base::EngineOp>::create(
        "testError",
        [](base::Event e) -> base::result::Result<base::Event>
        {
            throw std::runtime_error("Executed term "
                                     "that should not "
                                     "be executed");
        });

    Controller controller;
    rx::subjects::subject<RxEvent> inputSubj;
    std::unordered_set<std::string> names;

    // All failure
    auto output1 =
        rxFactory(inputSubj.get_observable(),
                  names,
                  base::Or::create("Or1", {termFailure, termFailure, termFailure}),
                  controller,
                  [](auto s) {});
    output1.subscribe([](auto e) { ASSERT_TRUE(e->failure()); });

    // Success last
    auto output2 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Or::create("Or2", {termFailure, termFailure, termSuccess}),
                  controller,
                  [](auto s) {});
    output2.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Success middle
    auto output3 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Or::create("Or3", {termFailure, termSuccess, termError}),
                  controller,
                  [](auto s) {});
    output3.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Success first
    auto output4 = rxFactory(inputSubj.get_observable(),
                             {},
                             base::Or::create("Or4", {termSuccess, termError, termError}),
                             controller,
                             [](auto s) {});
    output4.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

TEST(rxbkFactoryTest, rxFactoryChainOfTerms)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));

    auto termSuccess = base::Term<base::EngineOp>::create(
        "testSucces", [](base::Event e) { return base::result::makeSuccess(e); });
    auto termFailure = base::Term<base::EngineOp>::create(
        "testFailure", [](base::Event e) { return base::result::makeFailure(e); });
    // This term shoul not be executed
    auto termError = base::Term<base::EngineOp>::create(
        "testError",
        [](base::Event e) -> base::result::Result<base::Event>
        {
            throw std::runtime_error("Executed term "
                                     "that should not "
                                     "be executed");
        });

    Controller controller;
    rx::subjects::subject<RxEvent> inputSubj;
    std::unordered_set<std::string> names;

    // All success
    auto output1 =
        rxFactory(inputSubj.get_observable(),
                  names,
                  base::Chain::create("Chain1", {termSuccess, termSuccess, termSuccess}),
                  controller,
                  [](auto s) {});
    output1.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Failure last
    auto output2 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Chain::create("Chain2", {termSuccess, termSuccess, termFailure}),
                  controller,
                  [](auto s) {});
    output2.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Failure middle
    auto output3 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Chain::create("Chain3", {termSuccess, termFailure, termFailure}),
                  controller,
                  [](auto s) {});
    output3.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // All failure
    auto output4 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Chain::create("Chain4", {termFailure, termFailure, termFailure}),
                  controller,
                  [](auto s) {});
    output4.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

// TODO: Broadcast should not care about order, rightnow is the same as Chain
TEST(rxbkFactoryTest, rxFactoryBroadcastOfTerms)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));

    auto termSuccess = base::Term<base::EngineOp>::create(
        "testSucces", [](base::Event e) { return base::result::makeSuccess(e); });
    auto termFailure = base::Term<base::EngineOp>::create(
        "testFailure", [](base::Event e) { return base::result::makeFailure(e); });
    // This term shoul not be executed
    auto termError = base::Term<base::EngineOp>::create(
        "testError",
        [](base::Event e) -> base::result::Result<base::Event>
        {
            throw std::runtime_error("Executed term "
                                     "that should not "
                                     "be executed");
        });

    Controller controller;
    rx::subjects::subject<RxEvent> inputSubj;
    std::unordered_set<std::string> names;

    // All success
    auto output1 = rxFactory(
        inputSubj.get_observable(),
        names,
        base::Broadcast::create("Broadcast1", {termSuccess, termSuccess, termSuccess}),
        controller,
        [](auto s) {});
    output1.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Failure last
    auto output2 = rxFactory(
        inputSubj.get_observable(),
        {},
        base::Broadcast::create("Broadcast2", {termSuccess, termSuccess, termFailure}),
        controller,
        [](auto s) {});
    output2.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Failure middle
    auto output3 = rxFactory(
        inputSubj.get_observable(),
        {},
        base::Broadcast::create("Broadcast3", {termSuccess, termFailure, termFailure}),
        controller,
        [](auto s) {});
    output3.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // All failure
    auto output4 = rxFactory(
        inputSubj.get_observable(),
        {},
        base::Broadcast::create("Broadcast4", {termFailure, termFailure, termFailure}),
        controller,
        [](auto s) {});
    output4.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

TEST(rxbkFactoryTest, rxFactoryImplicationOfTerms)
{
    auto event = std::make_shared<json::Json>(R"({"field": "value"})");
    auto rxEvent = std::make_shared<base::result::Result<base::Event>>(
        base::result::makeSuccess<base::Event>(event));

    auto termSuccess = base::Term<base::EngineOp>::create(
        "testSucces", [](base::Event e) { return base::result::makeSuccess(e); });
    auto termFailure = base::Term<base::EngineOp>::create(
        "testFailure", [](base::Event e) { return base::result::makeFailure(e); });
    // This term shoul not be executed
    auto termError = base::Term<base::EngineOp>::create(
        "testError",
        [](base::Event e) -> base::result::Result<base::Event>
        {
            throw std::runtime_error("Executed term "
                                     "that should not "
                                     "be executed");
        });

    Controller controller;
    rx::subjects::subject<RxEvent> inputSubj;
    std::unordered_set<std::string> names;

    // Condition success, consequence success
    auto output1 =
        rxFactory(inputSubj.get_observable(),
                  names,
                  base::Implication::create("Implication1", termSuccess, termSuccess),
                  controller,
                  [](auto s) {});
    output1.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Condition success, consequence failure
    auto output2 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Implication::create("Implication2", termSuccess, termFailure),
                  controller,
                  [](auto s) {});
    output2.subscribe([](auto e) { ASSERT_TRUE(e->success()); });

    // Condition failure
    auto output3 =
        rxFactory(inputSubj.get_observable(),
                  {},
                  base::Implication::create("Implication3", termFailure, termError),
                  controller,
                  [](auto s) {});
    output3.subscribe([](auto e) { ASSERT_TRUE(e->failure()); });

    inputSubj.get_subscriber().on_next(std::move(rxEvent));
    inputSubj.get_subscriber().on_completed();
}

TEST(rxbkFactoryTest, rxFactoryUseCase)
{
    // TODO: implement with a complex expression graph
    GTEST_SKIP();
}

TEST(rxbkFactoryTest, BuildRxPipelineUseCase)
{
    // TODO: implement with a realistic environment
    GTEST_SKIP();
}
