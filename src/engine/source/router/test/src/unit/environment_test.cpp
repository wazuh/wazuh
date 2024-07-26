#include <gtest/gtest.h>

#include <bk/mockController.hpp>

#include "environment.hpp"

using namespace router;

base::Expression getDummyTerm(bool result)
{
    return base::Term<base::EngineOp>::create("dummy",
                                              [result](const base::Event& event) -> base::result::Result<base::Event> {
                                                  return result ? base::result::makeSuccess(event)
                                                                : base::result::makeFailure(event);
                                              });
}

auto getMockController()
{
    auto controller = std::make_shared<bk::mocks::MockController>();
    EXPECT_CALL(*controller, stop()).WillOnce(testing::Return());
    return controller;
}


TEST(EnvironmentTest, ConstructorThrowsOnInvalidController)
{
    EXPECT_THROW(Environment(getDummyTerm(true), nullptr, std::string("-")), std::runtime_error);
}

TEST(EnvironmentTest, StopOnDestroy)
{
    Environment environment(base::Expression{}, getMockController(), std::string("-"));
}

TEST(EnvironmentTest, isAccepted)
{
    auto controllerTrue = getMockController();
    auto controllerFalse = getMockController();
    Environment environmentTrue(getDummyTerm(true), controllerTrue, std::string("-"));
    Environment environmentFalse(getDummyTerm(false), controllerFalse, std::string("-"));
}

TEST(EnvironmentTest, Ingest)
{
    auto controller = getMockController();
    base::Event event {};
    EXPECT_CALL(*controller, ingest(base::Event(event))).WillOnce(testing::Return());

    auto environment = Environment(getDummyTerm(true), controller, std::string("-"));
    environment.ingest(std::move(event));
}

TEST(EnvironmentTest, IngestGet)
{
    auto controller = getMockController();
    base::Event event = std::make_shared<json::Json>(R"({"test": "test"})");
    base::Event eventExpected = std::make_shared<json::Json>(R"({"test": "test"})");
    EXPECT_CALL(*controller, ingestGet(base::Event(event))).WillOnce(testing::Return(event));

    auto environment = Environment(getDummyTerm(true), controller, std::string("-"));
    auto res = environment.ingestGet(std::move(event));
    EXPECT_EQ(*res, *eventExpected);
}

