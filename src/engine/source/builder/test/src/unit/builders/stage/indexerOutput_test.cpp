#include <memory>

#include "builders/baseBuilders_test.hpp"
#include "builders/stage/indexerOutput.hpp"

#include <wiconnector/mockswindexerconnector.hpp>

using namespace builder::builders;

namespace stagebuildtest
{
std::shared_ptr<wiconnector::IWIndexerConnector> getMockIndexerConnector()
{
    // Static thread
    static thread_local std::shared_ptr<wiconnector::mocks::MockWIndexerConnector> mock =
        std::make_shared<wiconnector::mocks::MockWIndexerConnector>();
    return mock;
}

std::shared_ptr<wiconnector::IWIndexerConnector> getNullIndexerConnector()
{
    return nullptr;
}

INSTANTIATE_TEST_SUITE_P(
    Builders,
    StageBuilderTest,
    testing::Values(
        // Null Indexer connector
        StageT(R"([])", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"("notObject")", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"(1)", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"(null)", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"(true)", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"key": "val", "key2": "val2"})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        // -- Index name is not string
        StageT(R"({"index": 1})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": true})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": null})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": [{"index": "non-alerts"}]})",
               getIndexerOutputBuilder(getNullIndexerConnector()),
               FAILURE()),
        StageT(R"({"index": "alerts"})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        // non-null Indexer connector
        StageT(R"([])", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"("notObject")", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(1)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(null)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(true)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"key": "val", "key2": "val2"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        // -- Index name is not string
        StageT(R"({"index": 1})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": true})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": null})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": [{"index": "non-alerts"}]})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               FAILURE()),
        // Invalid string
        StageT(R"({"index": "alerts"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": "wazuh-Alerts"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": "wazuh-alerts-#"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": "wazuh-events-v5-#Someth/ng"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": "wazuh-events-v5-some-${}"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": "wazuh-events-v5-${}${"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        // Valid string
        StageT(R"({"index": "wazuh-events-v5-applications"})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, runState());
                       return base::Term<base::EngineOp>::create(
                           "write.output(wazuh-indexer/wazuh-events-v5-applications)", {});
                   }))
        // End
        ),
    testNameFormatter<StageBuilderTest>("IndexerOutput"));
} // namespace stagebuildtest

namespace indexeroutputtest
{
const std::string messageStr {R"({
    "event": {
        "original": "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"
    },
    "wazuh": {
        "agent": {
            "id": "001",
            "name": "agentSim",
            "version": "PoC"
        },
        "integration": {
            "category": "Applications",
            "name": "nginx"
        },
        "a": "value A",
        "b": "VALUE B",
        "c": "vAlUe c",
        "event": {
            "format": "text",
            "id": "9aa69e7b-e1b0-530e-a710-49108e86019b",
            "ingested": "2021-10-26T16:50:34.348945Z",
            "kind": "event"
        }
    }
})"};

class IndexerOutputOperationTest : public BaseBuilderTest
{
protected:
    wiconnector::mocks::MockWIndexerConnector mockConnector;

    void SetUp() override
    {
        // Call super
        BaseBuilderTest::SetUp();
        // Reset the mock
        ::testing::Mock::VerifyAndClearExpectations(&mockConnector);
    }

    void TearDown() override
    {
        // Reset the mock
        ::testing::Mock::VerifyAndClearExpectations(&mockConnector);
    }
};

// The indexer connector never fails.
TEST_F(IndexerOutputOperationTest, output_success)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());
    auto definition = json::Json(R"({"index": "wazuh-events-v5-applications"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/wazuh-events-v5-applications)");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-applications", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, output_several_references)
{
    // Use the actual mockConnector instance as a shared_ptr
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.a}${wazuh.b}${wazuh.c}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.a}${wazuh.b}${wazuh.c})");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-value-avalue-bvalue-c", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, output_several_references_separators)
{
    // Use the actual mockConnector instance as a shared_ptr
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.a}---somecrazystring--${wazuh.c}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.a}---somecrazystring--${wazuh.c})");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-value-a---somecrazystring--value-c", ::testing::_));
    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, output_success_with_complex_category_reference)
{
    // Use the actual mockConnector instance as a shared_ptr
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"Cloud Services","name":"AWS"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name})");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-cloud-services-aws", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

} // namespace indexeroutputtest
