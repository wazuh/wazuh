#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <bk/mockController.hpp>

#include "environment.hpp"

using namespace router;

class EnvironmentTestFixture : public ::testing::Test
{
protected:
    const std::string testHash {"abc123def456"};
    const std::string emptyHash {""};

    std::shared_ptr<bk::mocks::MockController> getMockController()
    {
        auto controller = std::make_shared<bk::mocks::MockController>();
        return controller;
    }
};

TEST_F(EnvironmentTestFixture, ConstructorThrowsOnInvalidController)
{
    EXPECT_THROW(Environment(nullptr, std::string(testHash)), std::runtime_error);
}

TEST_F(EnvironmentTestFixture, ConstructorSucceedsWithValidController)
{
    auto controller = getMockController();
    EXPECT_NO_THROW(Environment(std::move(controller), std::string(testHash)));
}

TEST_F(EnvironmentTestFixture, StopOnDestroy)
{
    auto controller = getMockController();
    EXPECT_CALL(*controller, stop()).Times(1);
    {
        Environment environment(std::move(controller), std::string(testHash));
    }
}

TEST_F(EnvironmentTestFixture, HashStoredCorrectly)
{
    auto controller = getMockController();
    Environment environment(std::move(controller), std::string(testHash));
    EXPECT_EQ(environment.hash(), testHash);
}

TEST_F(EnvironmentTestFixture, Ingest)
{
    auto controller = getMockController();
    base::Event event = std::make_shared<json::Json>(R"({"test": "data"})");
    EXPECT_CALL(*controller, ingest(::testing::_)).Times(1);

    Environment environment(std::move(controller), std::string(testHash));
    environment.ingest(std::move(event));
}

TEST_F(EnvironmentTestFixture, IngestGet)
{
    auto controller = getMockController();
    base::Event event = std::make_shared<json::Json>(R"({"test": "test"})");
    base::Event eventExpected = std::make_shared<json::Json>(R"({"test": "test"})");

    EXPECT_CALL(*controller, ingestGet(::testing::_)).WillOnce(::testing::Return(event));

    Environment environment(std::move(controller), std::string(testHash));
    auto res = environment.ingestGet(std::move(event));
    EXPECT_EQ(*res, *eventExpected);
}

TEST_F(EnvironmentTestFixture, SetControllerThrowsOnNull)
{
    auto controller = getMockController();
    Environment environment(std::move(controller), std::string(testHash));

    EXPECT_THROW(environment.setController(nullptr), std::runtime_error);
}

TEST_F(EnvironmentTestFixture, MultipleIngestCalls)
{
    auto controller = getMockController();
    EXPECT_CALL(*controller, ingest(::testing::_)).Times(3);

    Environment environment(std::move(controller), std::string(testHash));

    base::Event event1 = std::make_shared<json::Json>(R"({"id": "1"})");
    base::Event event2 = std::make_shared<json::Json>(R"({"id": "2"})");
    base::Event event3 = std::make_shared<json::Json>(R"({"id": "3"})");

    environment.ingest(std::move(event1));
    environment.ingest(std::move(event2));
    environment.ingest(std::move(event3));
}
