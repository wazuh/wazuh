#include <gtest/gtest.h>

#include <bk/mockController.hpp>

#include "environment.hpp"

using namespace router;

class EnvironmentTest : public testing::Test
{
protected:
    void SetUp() override
    {
        mockController = std::make_shared<bk::mocks::MockController>();
    }

    std::shared_ptr<bk::mocks::MockController> mockController;
};

TEST_F(EnvironmentTest, ConstructorThrowsOnInvalidController)
{
    EXPECT_THROW(Environment(nullptr, nullptr), std::runtime_error);
}

TEST_F(EnvironmentTest, IsAcceptedReturns)
{
    // Arrange
    auto filterId {1};
    auto filterPath {"/dummyPath"};
    auto event = std::make_shared<json::Json>();
    event->setInt(filterId, filterPath);

    json::Json value {std::to_string(filterId).c_str()};
    auto expression =
        base::Term<base::EngineOp>::create("dummy",
                                            [value, filterPath](const base::Event& event) -> base::result::Result<base::Event>
                                            {
                                                if (event->equals(filterPath, value))
                                                {
                                                    return base::result::makeSuccess(event);
                                                }
                                                return base::result::makeFailure(event);
                                            });

    Environment environment(expression, mockController);

    EXPECT_CALL(*mockController, stop()).Times(1);
    EXPECT_TRUE(environment.isAccepted(event));
}

TEST_F(EnvironmentTest, IngestCallsController)
{
    base::Event event;
    Environment environment(base::Expression{}, mockController);

    EXPECT_CALL(*mockController, ingest(testing::_)).Times(1);
    EXPECT_CALL(*mockController, stop()).Times(1);

    environment.ingest(std::move(event));
}

TEST_F(EnvironmentTest, IngestGetCallsController)
{
    Environment environment(base::Expression{}, mockController);

    auto event = std::make_shared<json::Json>(R"({"key": "value"})");

    EXPECT_CALL(*mockController, ingestGet(testing::_)).WillOnce(testing::Return(event));
    EXPECT_CALL(*mockController, stop()).Times(1);

    EXPECT_STREQ(event->str().c_str(), environment.ingestGet(std::move(event))->str().c_str());
}

/*
using TraceFn = std::function<void(const std::string&, const std::string&, bool)>;
TEST_F(EnvironmentTest, SubscribeTracesController)
{
    // Create an instance of Opt and pass the output function, trace level, and environment ID
    router::test::OutputFn outputCallback = [](router::test::Output&& result) {
        // Do something with the result
        std::cout << "Output received\n";
        // ...
    };

    router::test::Opt opt(outputCallback, router::test::TraceLevel::ALL, "EnvironmentDebug");

    // Get the output function from Opt
    auto resultCallback = opt.getOutputFn();

    // Create a trace function that will call the output function
    TraceFn traceCallback = [&](const std::string& asset, const std::string& traceContent, bool result) {
        // You can perform any additional logic here before calling the output function
        std::cout << "Trace received\n";
        router::test::TraceStorage traceStorage;
        traceStorage.ingest(asset, traceContent, result);
        resultCallback(router::test::Output{std::make_shared<json::Json>(R"({"key": "value"})"), traceStorage}); // Example call to the output function
        // ...
    };

    // Create a list of assets for subscription
    std::vector<std::string> assetsToSubscribe = {"Asset1", "Asset2"};

    // Call the subscribeTrace function
    Environment environment(base::Expression{}, mockController);

    base::RespOrError<size_t> respOrError = size_t(1);
    EXPECT_CALL(*mockController, subscribe(testing::_, testing::_)).WillRepeatedly(testing::Return(respOrError));
    EXPECT_CALL(*mockController, stop()).Times(1);

    auto res = environment.subscribeTrace(traceCallback, assetsToSubscribe);
    EXPECT_FALSE(res.has_value());
}
*/
