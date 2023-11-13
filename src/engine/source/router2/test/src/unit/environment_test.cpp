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

TEST_F(EnvironmentTest, IsAcceptedReturnsTrueForAcceptedEvent) {
    // Arrange
    auto filterId {1};
    auto filterPath {"/dummyPath"};
    auto event = std::make_shared<json::Json>();
    event->setString("1", filterPath);

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

TEST_F(EnvironmentTest, IngestGetCallsControllerIngestGet) {
    base::Event event;
    Environment environment(base::Expression{}, mockController);

    EXPECT_CALL(*mockController, ingest(testing::_)).Times(1);
    EXPECT_CALL(*mockController, stop()).Times(1);

    environment.ingest(std::move(event));
}
