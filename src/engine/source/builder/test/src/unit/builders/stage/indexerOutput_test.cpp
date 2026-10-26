// SPDX-License-Identifier: AGPL-3.0-or-later
#include <memory>
#include <string>

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
        StageT(R"({"index": "wazuh-events-v5-#Someth/ng"})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               FAILURE()),
        StageT(R"({"index": "wazuh-events-v5-some-${}"})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               FAILURE()),
        StageT(R"({"index": "wazuh-events-v5-${}${"})", getIndexerOutputBuilder(getMockIndexerConnector()), FAILURE()),
        // Valid string
        StageT(R"({"index": "wazuh-events-v5-applications"})",
               getIndexerOutputBuilder(getMockIndexerConnector()),
               SUCCESS(
                   [](const BuildersMocks& mocks)
                   {
                       EXPECT_CALL(*mocks.ctx, isTestMode());
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
            "category": "applications",
            "name": "nginx"
        },
        "a": "value-a",
        "b": "value-b",
        "c": "value-c",
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
        BaseBuilderTest::TearDown();
    }
};

// The indexer connector never fails.
TEST_F(IndexerOutputOperationTest, output_success)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());
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

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.a}${wazuh.b}${wazuh.c}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.a}${wazuh.b}${wazuh.c})");

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

// 1M characters overflowed the stack with std::regex_match
TEST_F(IndexerOutputOperationTest, long_index_name_validation_is_linear)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    json::Json validName;
    validName.setString("wazuh-events-v5-" + std::string(1'000'000, 'a'), "/index");
    EXPECT_CALL(*(mocks->ctx), isTestMode());
    EXPECT_NO_THROW(builder(validName, this->mocks->ctx));

    json::Json validPlaceholder;
    validPlaceholder.setString("wazuh-events-v5-${" + std::string(1'000'000, 'a') + "}", "/index");
    EXPECT_CALL(*(mocks->ctx), isTestMode());
    EXPECT_NO_THROW(builder(validPlaceholder, this->mocks->ctx));

    json::Json invalidName;
    invalidName.setString("wazuh-events-v5-" + std::string(1'000'000, 'a') + "#", "/index");
    EXPECT_THROW(builder(invalidName, this->mocks->ctx), std::runtime_error);

    json::Json unclosedPlaceholder;
    unclosedPlaceholder.setString("wazuh-events-v5-${" + std::string(1'000'000, 'a'), "/index");
    EXPECT_THROW(builder(unclosedPlaceholder, this->mocks->ctx), std::runtime_error);
}

TEST_F(IndexerOutputOperationTest, output_several_references_separators)
{
    // Use the actual mockConnector instance as a shared_ptr
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.a}---somecrazystring--${wazuh.c}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(), "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.a}---somecrazystring--${wazuh.c})");

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

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition =
        json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"cloud-services","name":"aws"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();
    ASSERT_EQ(term->getName(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name})");

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

TEST_F(IndexerOutputOperationTest, validate_applications_category)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"applications","name":"nginx"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect sanitized category in index name
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-applications", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_system_activity_category)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"system-activity","name":"auditd"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect sanitized category in index name
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-system-activity", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_network_activity_category)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"network-activity","name":"suricata"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect sanitized category in index name
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-network-activity", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_azure_cloud_integration)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition =
        json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"cloud-services","name":"azure-ad"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect cloud-services-azure index
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-cloud-services-azure-ad", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_gcp_cloud_integration)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition =
        json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}-${wazuh.integration.name}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"cloud-services","name":"gcp-pubsub"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect cloud-services-gcp-pubsub index
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-cloud-services-gcp-pubsub", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_security_category)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"security","name":"ossec"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect sanitized category in index name
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-security", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

TEST_F(IndexerOutputOperationTest, validate_access_management_category)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode());

    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})");
    auto expression = builder(definition, this->mocks->ctx);

    const std::string messageStr {R"({"wazuh":{"integration":{"category":"access-management","name":"okta"}}})"};
    auto event = std::make_shared<json::Json>(messageStr.c_str());

    // Check the expression
    ASSERT_TRUE(expression->isTerm());
    auto term = expression->getPtr<base::Term<base::EngineOp>>();

    // Check the operation
    auto operation = term->getFn();
    ASSERT_TRUE(operation);

    // Configure the behavior - expect sanitized category in index name
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-access-management", ::testing::_));

    // Run the operation
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
}

// I183: in test mode the event is not indexed, and the trace says so
TEST_F(IndexerOutputOperationTest, TestModeDoesNotIndex)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto expression = builder(json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})"), mocks->ctx);
    auto operation = expression->getPtr<base::Term<base::EngineOp>>()->getFn();

    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);
    auto event = std::make_shared<json::Json>(messageStr.c_str());
    auto result = operation(event);
    ASSERT_TRUE(result.success());
    ASSERT_EQ(*result.payload(), *event);
    EXPECT_EQ(result.trace(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.integration.category}) -> Success (skipped in test "
              "mode)");
}

// The index name checks keep running in test mode: a missing placeholder field or an oversized name still fails
TEST_F(IndexerOutputOperationTest, TestModeStillValidates)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);
    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto missing = builder(json::Json(R"({"index": "wazuh-events-v5-${wazuh.missing}"})"), mocks->ctx);
    auto result =
        missing->getPtr<base::Term<base::EngineOp>>()->getFn()(std::make_shared<json::Json>(messageStr.c_str()));
    ASSERT_FALSE(result.success());
    EXPECT_EQ(result.trace(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.missing}) -> Couldn't get field ${wazuh.missing} "
              "from event");

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto oversized = builder(json::Json(R"({"index": "wazuh-events-v5-${wazuh.long}"})"), mocks->ctx);
    auto event = std::make_shared<json::Json>(messageStr.c_str());
    event->setString(std::string(256, 'a'), "/wazuh/long");
    result = oversized->getPtr<base::Term<base::EngineOp>>()->getFn()(event);
    ASSERT_FALSE(result.success());
    EXPECT_THAT(result.trace(), ::testing::HasSubstr("exceeds 255 characters limit"));
}

// I189: with event processing off there is no connector, and the tester must still build the stage
TEST_F(IndexerOutputOperationTest, TestModeWithoutConnectorBuilds)
{
    auto builder = getIndexerOutputBuilder(std::shared_ptr<wiconnector::IWIndexerConnector> {});

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    base::Expression expression;
    ASSERT_NO_THROW(expression = builder(json::Json(R"({"index": "wazuh-events-v5-applications"})"), mocks->ctx));

    auto event = std::make_shared<json::Json>(messageStr.c_str());
    auto result = expression->getPtr<base::Term<base::EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result.success());
    EXPECT_THAT(result.trace(), ::testing::HasSubstr("skipped in test mode"));
}

// Outside test mode a missing connector is still a build error
TEST_F(IndexerOutputOperationTest, NoConnectorOutsideTestModeThrows)
{
    auto builder = getIndexerOutputBuilder(std::shared_ptr<wiconnector::IWIndexerConnector> {});

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(false));
    EXPECT_THROW(builder(json::Json(R"({"index": "wazuh-events-v5-applications"})"), mocks->ctx), std::runtime_error);
}

// Outside test mode the resolved index and the serialized event reach the connector, with no trace
TEST_F(IndexerOutputOperationTest, IndexesOutsideTestMode)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(false));
    auto expression = builder(json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})"), mocks->ctx);

    auto event = std::make_shared<json::Json>(messageStr.c_str());
    EXPECT_CALL(mockConnector, index(std::string("wazuh-events-v5-applications"), event->str()));
    auto result = expression->getPtr<base::Term<base::EngineOp>>()->getFn()(event);
    ASSERT_TRUE(result.success());
    EXPECT_FALSE(result.hasTrace());
}

namespace
{
/// Hand-written connector: records the capacity of the index name it receives, which a gmock action cannot show.
class RecordingConnector final : public wiconnector::IWIndexerConnector
{
public:
    std::string lastIndex;
    std::size_t lastIndexCapacity {0};

    void index(std::string index, std::string) override
    {
        lastIndexCapacity = index.capacity();
        lastIndex = std::move(index);
    }
    json::Json getEngineRemoteConfig() override { return json::Json {}; }
    uint64_t getQueueSize() override { return 0; }
    uint64_t getDroppedEvents() override { return 0; }
    double getQueueUsagePercent() override { return 0.0; }
};
} // namespace

// The resolved index name is moved into the connector: it keeps the buffer of the template it was built in, which is
// larger than the name (a copy would get a buffer of the name's size)
TEST_F(IndexerOutputOperationTest, ResolvedIndexNameIsMoved)
{
    auto connector = std::make_shared<RecordingConnector>();
    auto builder = getIndexerOutputBuilder(connector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(false));
    auto expression = builder(json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}"})"), mocks->ctx);

    auto event = std::make_shared<json::Json>(messageStr.c_str());
    ASSERT_TRUE(expression->getPtr<base::Term<base::EngineOp>>()->getFn()(event).success());
    EXPECT_EQ(connector->lastIndex, "wazuh-events-v5-applications");
    EXPECT_GE(connector->lastIndexCapacity, std::string("wazuh-events-v5-${wazuh.integration.category}").size());
}

} // namespace indexeroutputtest
