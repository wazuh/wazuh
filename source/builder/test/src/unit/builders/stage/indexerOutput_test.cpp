#include <memory>

#include "builders/baseBuilders_test.hpp"
#include "builders/stage/indexerOutput.hpp"

#include <indexerConnector/mockiconnector.hpp>

using namespace builder::builders;

namespace stagebuildtest
{
std::shared_ptr<IIndexerConnector> getMockIndexerConnector()
{
    return std::make_shared<indexerconnector::mocks::MockIConnector>();
}

std::shared_ptr<IIndexerConnector> getNullIndexerConnector()
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
        // -- Index name is not 'alerts' string
        StageT(R"({"index": 1})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": true})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": null})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        StageT(R"({"index": [{"index": "non-alerts"}]})",
               getIndexerOutputBuilder(getNullIndexerConnector()),
               FAILURE()),
        StageT(R"({"index": "non-alerts"})", getIndexerOutputBuilder(getNullIndexerConnector()), FAILURE()),
        // -- Index name is 'alerts'
        StageT(R"({"index": "alerts"})",
               getIndexerOutputBuilder(getNullIndexerConnector()),
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, runState());
                       return base::Term<base::EngineOp>::create("write.output(wazuh-indexer/alerts)", {});
                   })),
        // non-null Indexer connector
        StageT(R"([])", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"("notObject")", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(1)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(null)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"(true)", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"key": "val", "key2": "val2"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        // -- Index name is not 'alerts' string
        StageT(R"({"index": 1})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": true})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": null})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        StageT(R"({"index": [{"index": "non-alerts"}]})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               FAILURE()),
        StageT(R"({"index": "non-alerts"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        // -- Index name is 'alerts'
        StageT(R"({"index": "alerts"})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, runState());
                       return base::Term<base::EngineOp>::create("write.output(wazuh-indexer/alerts)", {});
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
    indexerconnector::mocks::MockIConnector mockConnector;
    json::Json definition;

    void SetUp() override
    {
        // Call super
        BaseBuilderTest::SetUp();
        // Reset the mock
        ::testing::Mock::VerifyAndClearExpectations(&mockConnector);
        // Set success definition for builder creation
        definition = json::Json(R"({"index": "alerts"})");
    }

    void TearDown() override
    {
        // Reset the mock
        ::testing::Mock::VerifyAndClearExpectations(&mockConnector);
    }
};

// Custom matcher to check the event starts with a prefix
MATCHER_P(StartsWith, prefix, "")
{
    return arg.find(prefix) == 0;
}

TEST_F(IndexerOutputOperationTest, output_success)
{
    auto iConnector = std::make_shared<indexerconnector::mocks::MockIConnector>();
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/alerts)");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior
    EXPECT_CALL(*iConnector, publish(StartsWith(R"({"operation": "ADD", "data": {)")));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, output_fail)
{
    std::shared_ptr<indexerconnector::mocks::MockIConnector> iConnector {nullptr};
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), runState());
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/alerts)");

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.failure());
    ASSERT_EQ(*result.payload(), *event);
}

} // namespace indexeroutputtest
