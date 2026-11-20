// SPDX-License-Identifier: AGPL-3.0-or-later
#include <chrono>
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

// A placeholder whose field is missing (or not a string) fails the operation with the documented trace; the index
// name is never used as a format string (a '${field}' in it used to throw "argument not found").
TEST_F(IndexerOutputOperationTest, missing_field_fails_with_trace)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.integration.category}-${wazuh.missing}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto operation = expression->getPtr<base::Term<base::EngineOp>>()->getFn();

    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);

    for (const auto* messageStr : {R"({"wazuh":{"integration":{"category":"applications"}}})",
                                   R"({"wazuh":{"integration":{"category":"applications"},"missing":1}})"})
    {
        auto event = std::make_shared<json::Json>(messageStr);
        base::result::Result<base::Event> result;
        ASSERT_NO_THROW(result = operation(event));
        EXPECT_FALSE(result.success());
        EXPECT_EQ(result.trace(),
                  "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.integration.category}-${wazuh.missing}) -> "
                  "Couldn't get field ${wazuh.missing} from event");
    }
}

// A field value becomes part of the index name the connector writes into a bulk action line: one holding anything
// but index-name characters is refused, never indexed under a name it shaped
TEST_F(IndexerOutputOperationTest, field_value_with_invalid_characters_fails_with_trace)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.name}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto operation = expression->getPtr<base::Term<base::EngineOp>>()->getFn();

    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);
    for (const std::string value : {"x\",\"_id\":\"y", "a/b", "a b", "Upper", "a\nb", "a*", "a,b"})
    {
        auto event = std::make_shared<json::Json>("{}");
        event->setString(value, "/wazuh/name");
        base::result::Result<base::Event> result;
        ASSERT_NO_THROW(result = operation(event));
        EXPECT_FALSE(result.success()) << value;
        EXPECT_EQ(result.trace(),
                  "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.name}) -> Field ${wazuh.name} holds characters "
                  "not allowed in an index name");
    }
    ::testing::Mock::VerifyAndClearExpectations(&mockConnector);

    auto event = std::make_shared<json::Json>("{}");
    event->setString("aws_cloud.trail-1", "/wazuh/name");
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-aws_cloud.trail-1", ::testing::_));
    EXPECT_TRUE(operation(event).success());
}

TEST_F(IndexerOutputOperationTest, too_long_index_name_fails_with_trace)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(true));
    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.name}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto operation = expression->getPtr<base::Term<base::EngineOp>>()->getFn();

    // 16 (prefix) + 239 = 255 characters: indexed
    const std::string longest(239, 'a');
    auto event = std::make_shared<json::Json>("{}");
    event->setString(longest, "/wazuh/name");
    EXPECT_CALL(mockConnector, index("wazuh-events-v5-" + longest, ::testing::_));
    EXPECT_TRUE(operation(event).success());

    // 256 characters: not indexed
    const std::string tooLongName = "wazuh-events-v5-" + longest + "b";
    event->setString(longest + "b", "/wazuh/name");
    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);
    base::result::Result<base::Event> result;
    ASSERT_NO_THROW(result = operation(event));
    EXPECT_FALSE(result.success());
    EXPECT_EQ(result.trace(),
              "write.output(wazuh-indexer/wazuh-events-v5-${wazuh.name}) -> Index name '" + tooLongName
                  + "' exceeds 255 characters limit");
}

// Outside test mode the failure carries no trace and nothing throws, however many events fail
TEST_F(IndexerOutputOperationTest, missing_field_fails_without_trace_outside_test_mode)
{
    auto iConnector = std::shared_ptr<wiconnector::IWIndexerConnector>(&mockConnector, [](auto*) {});
    auto builder = getIndexerOutputBuilder(iConnector);

    EXPECT_CALL(*(mocks->ctx), isTestMode()).WillOnce(::testing::Return(false));
    auto definition = json::Json(R"({"index": "wazuh-events-v5-${wazuh.missing}"})");
    auto expression = builder(definition, this->mocks->ctx);
    auto operation = expression->getPtr<base::Term<base::EngineOp>>()->getFn();

    EXPECT_CALL(mockConnector, index(::testing::_, ::testing::_)).Times(0);
    for (int i = 0; i < 3; ++i)
    {
        auto event = std::make_shared<json::Json>(messageStr.c_str());
        base::result::Result<base::Event> result;
        ASSERT_NO_THROW(result = operation(event));
        EXPECT_FALSE(result.success());
        EXPECT_TRUE(result.trace().empty());
    }
}

// The warning of one output: the first failure is reported, the following ones only once per window, and each
// report carries how many were suppressed since the previous one.
TEST(NotIndexedLogThrottleTest, reports_first_then_once_per_window_with_suppressed_count)
{
    NotIndexedLogThrottle throttle;
    const auto start = NotIndexedLogThrottle::Clock::now();
    const auto window = NotIndexedLogThrottle::WINDOW;

    // First occurrence: reported, nothing suppressed before it
    auto reported = throttle.record(start);
    ASSERT_TRUE(reported.has_value());
    EXPECT_EQ(*reported, 0U);

    // Inside the window: suppressed, up to its last instant
    EXPECT_FALSE(throttle.record(start).has_value());
    EXPECT_FALSE(throttle.record(start + std::chrono::seconds(1)).has_value());
    EXPECT_FALSE(throttle.record(start + window - std::chrono::milliseconds(1)).has_value());

    // Window elapsed: reported with the three suppressed ones
    reported = throttle.record(start + window);
    ASSERT_TRUE(reported.has_value());
    EXPECT_EQ(*reported, 3U);

    // The count restarts, and the window is measured from the last report
    EXPECT_FALSE(throttle.record(start + window + std::chrono::seconds(1)).has_value());
    reported = throttle.record(start + window + window);
    ASSERT_TRUE(reported.has_value());
    EXPECT_EQ(*reported, 1U);

    // A quiet window reports no suppressed events
    reported = throttle.record(start + window * 4);
    ASSERT_TRUE(reported.has_value());
    EXPECT_EQ(*reported, 0U);
}

// Failures suppressed after the last report are not lost when no further failure comes: pending() hands them
// over once the window is over, and only once
TEST(NotIndexedLogThrottleTest, pending_reports_the_tail_after_the_window)
{
    NotIndexedLogThrottle throttle;
    const auto start = NotIndexedLogThrottle::Clock::now();
    const auto window = NotIndexedLogThrottle::WINDOW;

    // Nothing recorded, or nothing suppressed: nothing pending
    EXPECT_FALSE(throttle.pending(start).has_value());
    ASSERT_TRUE(throttle.record(start).has_value());
    EXPECT_FALSE(throttle.pending(start + window).has_value());

    // Two suppressed failures stay pending while the window since the last report lasts
    EXPECT_FALSE(throttle.record(start + std::chrono::seconds(1)).has_value());
    EXPECT_FALSE(throttle.record(start + std::chrono::seconds(2)).has_value());
    EXPECT_FALSE(throttle.pending(start + std::chrono::seconds(3)).has_value());

    // Window over: handed over once
    const auto pending = throttle.pending(start + window);
    ASSERT_TRUE(pending.has_value());
    EXPECT_EQ(*pending, 2U);
    EXPECT_FALSE(throttle.pending(start + window * 2).has_value());

    // That report starts a new window for record() too
    EXPECT_FALSE(throttle.record(start + window + std::chrono::seconds(1)).has_value());
}

// Each output has its own throttle: one being silenced does not silence another
TEST(NotIndexedLogThrottleTest, instances_are_independent)
{
    NotIndexedLogThrottle first;
    NotIndexedLogThrottle second;
    const auto now = NotIndexedLogThrottle::Clock::now();

    EXPECT_TRUE(first.record(now).has_value());
    EXPECT_FALSE(first.record(now).has_value());
    EXPECT_TRUE(second.record(now).has_value());
}

// Every build of one output (one per router worker) shares its throttle; another output has its own
TEST(NotIndexedLogThrottleTest, builds_of_the_same_output_share_one_throttle)
{
    const auto first = notIndexedLogThrottleFor("write.output(wazuh-indexer/shared-a)");
    const auto second = notIndexedLogThrottleFor("write.output(wazuh-indexer/shared-a)");
    const auto other = notIndexedLogThrottleFor("write.output(wazuh-indexer/shared-b)");
    const auto now = NotIndexedLogThrottle::Clock::now();

    EXPECT_EQ(first, second);
    EXPECT_NE(first, other);

    // One report for the output, whichever build hits the failure
    EXPECT_TRUE(first->record(now).has_value());
    EXPECT_FALSE(second->record(now).has_value());
    EXPECT_TRUE(other->record(now).has_value());
}

// A throttle lives while a build holds it: an output built again later starts from a clean one
TEST(NotIndexedLogThrottleTest, a_released_output_gets_a_new_throttle)
{
    const auto name = "write.output(wazuh-indexer/released)";
    const auto now = NotIndexedLogThrottle::Clock::now();

    auto throttle = notIndexedLogThrottleFor(name);
    EXPECT_TRUE(throttle->record(now).has_value());
    EXPECT_FALSE(throttle->record(now).has_value());
    throttle.reset();

    throttle = notIndexedLogThrottleFor(name);
    const auto reported = throttle->record(now);
    ASSERT_TRUE(reported.has_value());
    EXPECT_EQ(*reported, 0U);
}

} // namespace indexeroutputtest
