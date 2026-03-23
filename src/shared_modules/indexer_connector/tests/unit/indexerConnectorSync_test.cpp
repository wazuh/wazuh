#include "indexerConnectorSyncImpl.hpp"
#include "mocks/MockHTTPRequest.hpp"
#include "mocks/MockServerSelector.hpp"
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.hpp>
#include <memory>
#include <sstream>
#include <thread>

using ::testing::_;
using ::testing::AtLeast;
using ::testing::DoAll;
using ::testing::HasSubstr;
using ::testing::Invoke;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::SaveArg;
using ::testing::StrictMock;

// Define different connector types with GMock
using IndexerConnectorSyncImplTest = IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest>;
using IndexerConnectorSyncImplSmallBulk = IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 1024, 0>; // 1KB
using IndexerConnectorSyncImplNoFlushInterval =
    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 1024, 0, 0>; // 1KB

// Test fixture using GMock
class IndexerConnectorSyncTest : public ::testing::Test
{
protected:
    nlohmann::json config;
    NiceMock<MockHTTPRequest> mockHttpRequest;
    NiceMock<MockServerSelector> mockServerSelector;

    // Helper to track calls and simulate responses
    int callCount = 0;
    std::vector<std::string> receivedData;

    void SetUp() override
    {
        config["hosts"] = nlohmann::json::array({"localhost:9200"});
        callCount = 0;
        receivedData.clear();

        // Default behavior for server selector - suppress warnings for internal calls
        ON_CALL(mockServerSelector, getNext()).WillByDefault(Return("mockserver:9200"));

        // Default behavior for HTTP request - success (using NiceMock suppresses warnings)
        ON_CALL(mockHttpRequest, post(_, _, _))
            .WillByDefault(Invoke([this](auto requestParams, const auto& postParams, auto configParams)
                                  { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));
    }

    void TearDown() override
    {
        // Clean up any test files
        std::filesystem::remove("/tmp/ca_test.pem");
        std::filesystem::remove("/tmp/cert_test.pem");
        std::filesystem::remove("/tmp/key_test.pem");
        std::filesystem::remove("/tmp/ca1_test.pem");
        std::filesystem::remove("/tmp/ca2_test.pem");
        std::filesystem::remove("/tmp/ca3_test.pem");
    }

    void simulateSuccessfulPost(RequestParamsVariant requestParams,
                                PostRequestParametersVariant postParams,
                                ConfigurationParameters /*configParams*/)
    {
        callCount++;

        // Extract data from variant
        std::string data;
        if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
        {
            data = std::get<TRequestParameters<std::string>>(requestParams).data;
        }
        else
        {
            data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
        }
        receivedData.push_back(data);

        // Simulate successful response
        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
        {
            std::get<TPostRequestParameters<const std::string&>>(postParams)
                .onSuccess(R"({"took":1,"errors":false,"items":[]})");
        }
        else
        {
            std::get<TPostRequestParameters<std::string&&>>(postParams)
                .onSuccess(R"({"took":1,"errors":false,"items":[]})");
        }
    }
};

// Basic constructor and destructor tests
TEST_F(IndexerConnectorSyncTest, ConstructorWithValidConfig)
{
    EXPECT_NO_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorSyncTest, DestructorStopsThread)
{
    auto connector = std::make_unique<IndexerConnectorSyncImplTest>(config, nullptr, &mockHttpRequest);
    connector.reset();
    SUCCEED();
}

// Basic operations tests
TEST_F(IndexerConnectorSyncTest, BulkIndexAddsToBuffer)
{
    // Pass our mock selector to the constructor
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("id2", "index2", R"({"field":"value"})");
    SUCCEED();
}

TEST_F(IndexerConnectorSyncTest, BulkDeleteAddsToBuffer)
{
    // Pass our mock selector to the constructor
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkDelete("id1", "index1");
    SUCCEED();
}

TEST_F(IndexerConnectorSyncTest, BulkDeleteEscapesIdInPayload)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkDelete("id-\"001\"", "index1");
    connector.flush();

    ASSERT_FALSE(receivedData.empty());
    EXPECT_THAT(receivedData.front(), HasSubstr(R"("_id":"id-\"001\"")"));
}

TEST_F(IndexerConnectorSyncTest, AppendEscapedIdWithoutSpecialCharacters)
{
    std::string bulkData;
    const std::string id {"agent-001"};

    appendEscapedId(bulkData, id);

    EXPECT_EQ(bulkData, id);
}

TEST_F(IndexerConnectorSyncTest, AppendEscapedIdWithSpecialCharacters)
{
    std::string bulkData;
    const std::string id {"agent-\"001\""};

    appendEscapedId(bulkData, id);

    EXPECT_EQ(bulkData, R"(agent-\"001\")");
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryAddsToMap)
{
    // DeleteByQuery typically doesn't trigger immediate HTTP calls
    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest);
    connector.deleteByQuery("index3", "agent1");
    SUCCEED();
}

// HTTP error handling tests using GMock
TEST_F(IndexerConnectorSyncTest, HandleError413PayloadTooLarge)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(0)) // May or may not be called depending on size validation
        .WillRepeatedly(Invoke(
            [this](auto requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }
                this->receivedData.push_back(data);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest);

    // Add data to force sending
    std::string id = "id1";
    std::string dataValue(2048, 'a');
    EXPECT_ANY_THROW({ connector.bulkIndex(id, "index1", dataValue); });
}

TEST_F(IndexerConnectorSyncTest, HandleError409VersionConflict)
{
    int errorCallCount = 0;

    // Create and configure mock selector
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(2))
        .WillRepeatedly(Invoke(
            [this, &errorCallCount](auto requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }
                this->receivedData.push_back(data);

                if (errorCallCount == 0)
                {
                    errorCallCount++;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Version Conflict", 409, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Version Conflict", 409, "");
                    }
                }
                else
                {
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to force sending (using small bulk size)
    EXPECT_NO_THROW({
        for (int i = 0; i < 20; ++i)
        {
            std::string id = "id" + std::to_string(i);
            std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
            connector.bulkIndex(id, "index1", data);
        }
    });

    // Verify that at least 2 calls were made (1 error + 1 success)
    EXPECT_GE(callCount, 2);
}

TEST_F(IndexerConnectorSyncTest, HandleError429TooManyRequests)
{
    int errorCallCount = 0;

    // Create and configure mock selector
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(2))
        .WillRepeatedly(Invoke(
            [this, &errorCallCount](auto requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }
                this->receivedData.push_back(data);

                if (errorCallCount == 0)
                {
                    errorCallCount++;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 429, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Too Many Requests", 429, "");
                    }
                }
                else
                {
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to force sending (using small bulk size)
    EXPECT_NO_THROW({
        for (int i = 0; i < 20; ++i)
        {
            std::string id = "id" + std::to_string(i);
            std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
            connector.bulkIndex(id, "index1", data);
        }
    });

    // Verify that at least 2 calls were made (1 error + 1 success)
    EXPECT_GE(callCount, 2);
}

TEST_F(IndexerConnectorSyncTest, HandleError500InternalServerError)
{
    // Create and configure mock selector
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this](auto requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }
                this->receivedData.push_back(data);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to force sending (using small bulk size)
    EXPECT_ANY_THROW({
        for (int i = 0; i < 20; ++i)
        {
            std::string id = "id" + std::to_string(i);
            std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
            connector.bulkIndex(id, "index1", data);
        }
    });

    // Verify that HTTP request was called
    EXPECT_GT(callCount, 0);
}

TEST_F(IndexerConnectorSyncTest, VerifyDataSentToHttpRequest)
{
    // Create and configure mock selector
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([this](auto requestParams, auto postParams, const ConfigurationParameters& configParams)
                               { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add specific data
    connector.bulkIndex("test_id_1", "test_index", R"({"test":"data1"})");
    connector.bulkIndex("test_id_2", "test_index", R"({"test":"data2"})");

    // Force sending by adding more data
    for (int i = 0; i < 15; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Verify that data was sent
    EXPECT_GT(callCount, 0);
    EXPECT_GT(receivedData.size(), 0);
}

TEST_F(IndexerConnectorSyncTest, TestSuccessfulBulkOperation)
{
    // Create and configure mock selector
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke([this](auto requestParams, auto postParams, const ConfigurationParameters& configParams)
                               { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to force sending
    for (int i = 0; i < 20; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Verify that it was sent successfully
    EXPECT_GT(callCount, 0);
}

// Configuration tests
TEST_F(IndexerConnectorSyncTest, ConstructorWithMultipleHosts)
{
    config["hosts"] = nlohmann::json::array({"localhost:9200", "localhost:9201", "localhost:9202"});
    EXPECT_NO_THROW({
        IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest);
        SUCCEED();
    });
}

TEST_F(IndexerConnectorSyncTest, ConstructorWithEmptyHostsThrows)
{
    config["hosts"] = nlohmann::json::array();
    EXPECT_ANY_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorSyncTest, ConstructorWithMissingHostsThrows)
{
    config.erase("hosts");
    EXPECT_ANY_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorSyncTest, ConstructorWithInvalidJSONThrows)
{
    nlohmann::json invalidConfig = "invalid";
    EXPECT_ANY_THROW({ IndexerConnectorSyncImplTest connector(invalidConfig, nullptr, &mockHttpRequest); });
}

// Additional SSL Configuration Tests
TEST_F(IndexerConnectorSyncTest, ConstructorWithSSLConfigurationValid)
{
    std::string caFile = "/tmp/ca_test.pem";
    std::string certFile = "/tmp/cert_test.pem";
    std::string keyFile = "/tmp/key_test.pem";

    // Create test SSL files
    std::ofstream(caFile) << "-----BEGIN CERTIFICATE-----\ntest ca cert\n-----END CERTIFICATE-----";
    std::ofstream(certFile) << "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----";
    std::ofstream(keyFile) << "-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----";

    config["ssl"]["certificate_authorities"] = nlohmann::json::array({caFile});
    config["ssl"]["certificate"] = certFile;
    config["ssl"]["key"] = keyFile;

    EXPECT_NO_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });

    // Cleanup
    std::filesystem::remove(caFile);
    std::filesystem::remove(certFile);
    std::filesystem::remove(keyFile);
}

TEST_F(IndexerConnectorSyncTest, ConstructorWithInvalidSSLPathsThrows)
{
    config["ssl"]["certificate_authorities"] = nlohmann::json::array({"/nonexistent/ca.pem"});
    config["ssl"]["certificate"] = "/nonexistent/cert.pem";
    config["ssl"]["key"] = "/nonexistent/key.pem";

    EXPECT_ANY_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

// Authentication Tests
TEST_F(IndexerConnectorSyncTest, ConstructorWithUsernamePasswordAuth)
{
    config["username"] = "test_user";
    config["password"] = "test_password";

    EXPECT_NO_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorSyncTest, ConstructorWithUsernameOnlyAuth)
{
    config["username"] = "test_user";
    // No password should still work

    EXPECT_NO_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

// Bulk Size Configuration Tests
TEST_F(IndexerConnectorSyncTest, SmallBulkSizeTriggersFrequentSending)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1)) // At least one call should be made
        .WillRepeatedly(Invoke([this](auto requestParams, auto postParams, const ConfigurationParameters& configParams)
                               { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add many small operations to force multiple bulk sends
    for (int i = 0; i < 30; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"operation":)" + std::to_string(i) + R"(})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Allow some time for background thread to process
    // std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_GT(callCount, 0); // Should have made at least one call
}

// Mixed Operations Test
TEST_F(IndexerConnectorSyncTest, MixedBulkAndDeleteOperations)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Use a simple mock to avoid JSON parsing in the actual implementation
    EXPECT_CALL(mockHttpRequest, post(_, _, _)).Times(0); // Don't expect any calls to avoid triggering JSON processing

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Mix different operations - these should be buffered
    connector.bulkIndex("index_id_1", "test_index", R"({"simple":"data"})");
    connector.bulkDelete("delete_id_1", "test_index");
    connector.bulkIndex("index_id_2", "test_index", R"({"simple":"data"})");

    // Test passes if no exceptions are thrown
    SUCCEED();
}

// Background flush Test
TEST_F(IndexerConnectorSyncTest, BackgroundFlushTest)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Use a promise/future to wait for the post call
    std::promise<void> postCalledPromise;
    std::future<void> postCalledFuture = postCalledPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1) // One call should be made
        .WillOnce(DoAll(
            Invoke(
                [this](RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
                { this->simulateSuccessfulPost(requestParams, postParams, configParams); }),
            Invoke([&postCalledPromise](auto, auto, auto) { postCalledPromise.set_value(); })));

    IndexerConnectorSyncImplNoFlushInterval connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to force sending
    std::string id = "id1";
    std::string data = R"({"field":"value1"})";
    connector.bulkIndex(id, "index1", data);

    // Force flush to process the data
    connector.flush();

    // Wait for the post call with timeout (5 seconds)
    auto status = postCalledFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for post call";
}

// Test Error 413 handling with data splitting validation
TEST_F(IndexerConnectorSyncTest, HandleError413WithDataSplittingValidation)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track the sequence of calls and their data
    std::vector<std::string> callSequenceData;
    std::vector<bool> callSequenceIsError;
    std::promise<void> allCallsCompletedPromise;
    std::future<void> allCallsCompletedFuture = allCallsCompletedPromise.get_future();

    int callCounter = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(3) // Should be called 3 times: 1 initial failure + 2 successful chunks
        .WillOnce(Invoke(
            [&callSequenceData, &callSequenceIsError, &callCounter](
                auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }

                callSequenceData.push_back(data);
                callSequenceIsError.push_back(true);

                // First call should fail with 413
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
                }
            }))
        .WillOnce(Invoke(
            [&callSequenceData, &callSequenceIsError, &callCounter](
                auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }

                callSequenceData.push_back(data);
                callSequenceIsError.push_back(false);

                // Second call (first chunk) should succeed
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
            }))
        .WillOnce(Invoke(
            [&callSequenceData, &callSequenceIsError, &callCounter, &allCallsCompletedPromise](
                auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;

                // Extract data from variant
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }

                callSequenceData.push_back(data);
                callSequenceIsError.push_back(false);

                // Third call (second chunk) should succeed
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }

                // Signal that all calls are completed
                allCallsCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add multiple documents to create a bulk operation that will be split
    std::vector<std::string> testDocuments;
    for (int i = 0; i < 4; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        testDocuments.push_back(data);
        connector.bulkIndex(id, "test_index", data);
    }

    // Force flush to trigger the processing
    connector.flush();

    // Wait for all calls to complete with timeout
    auto status = allCallsCompletedFuture.wait_for(std::chrono::seconds(10));
    ASSERT_EQ(status, std::future_status::ready) << "Timeout waiting for all HTTP calls to complete";

    // Validate the call sequence
    ASSERT_EQ(callSequenceData.size(), 3) << "Expected exactly 3 HTTP calls";
    ASSERT_EQ(callSequenceIsError.size(), 3) << "Expected 3 call results";

    // Validate first call failed
    EXPECT_TRUE(callSequenceIsError[0]) << "First call should have failed with 413";

    // Validate second and third calls succeeded
    EXPECT_FALSE(callSequenceIsError[1]) << "Second call should have succeeded";
    EXPECT_FALSE(callSequenceIsError[2]) << "Third call should have succeeded";

    // Validate data splitting: the original data should be split into two chunks
    const std::string& originalData = callSequenceData[0];
    const std::string& firstChunk = callSequenceData[1];
    const std::string& secondChunk = callSequenceData[2];

    // Both chunks should be smaller than the original
    EXPECT_LT(firstChunk.size(), originalData.size()) << "First chunk should be smaller than original data";
    EXPECT_LT(secondChunk.size(), originalData.size()) << "Second chunk should be smaller than original data";

    // Both chunks should be non-empty
    EXPECT_FALSE(firstChunk.empty()) << "First chunk should not be empty";
    EXPECT_FALSE(secondChunk.empty()) << "Second chunk should not be empty";

    // Count the number of operations in each chunk by counting newlines
    auto countOperations = [](const std::string& data) -> int
    {
        return static_cast<int>(std::count(data.begin(), data.end(), '\n')) / 2; // Each operation has 2 lines
    };

    int originalOps = countOperations(originalData);
    int firstChunkOps = countOperations(firstChunk);
    int secondChunkOps = countOperations(secondChunk);

    // The sum of operations in both chunks should equal the original
    EXPECT_EQ(firstChunkOps + secondChunkOps, originalOps)
        << "Sum of operations in chunks should equal original operations";

    // Each chunk should have about half the operations (±1 due to rounding)
    EXPECT_TRUE(std::abs(firstChunkOps - secondChunkOps) <= 1)
        << "Chunks should have approximately equal number of operations";

    // Validate that each chunk contains valid bulk operations
    auto validateBulkFormat = [](const std::string& data) -> int
    {
        std::istringstream stream(data);
        std::string line;
        int lineCount = 0;
        while (std::getline(stream, line))
        {
            if (!line.empty())
            {
                lineCount++;
                if (lineCount % 2 == 1)
                {
                    // Odd lines should be index operations
                    EXPECT_TRUE(line.find(R"({"index":)") != std::string::npos)
                        << "Odd lines should contain index operations: " << line;
                }
                else
                {
                    // Even lines should be document data (JSON)
                    try
                    {
                        auto result = nlohmann::json::parse(line);
                        (void)result; // Suppress unused variable warning
                    }
                    catch (const std::exception&)
                    {
                        ADD_FAILURE() << "Even lines should be valid JSON: " << line;
                    }
                }
            }
        }
        return lineCount;
    };

    EXPECT_GT(validateBulkFormat(firstChunk), 0) << "First chunk should contain valid bulk operations";
    EXPECT_GT(validateBulkFormat(secondChunk), 0) << "Second chunk should contain valid bulk operations";
}

// Test processBulkChunk error handling - 413 with successful recursive splitting
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError413RecursiveSplittingSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::vector<std::string> callSequenceData;
    std::vector<int> callSequenceStatusCodes;
    std::atomic<bool> allCallsCompleted {false};
    std::atomic<int> callCounter {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(2)) // At least initial bulk + some splits
        .WillOnce(Invoke(
            [&callSequenceData, &callSequenceStatusCodes, &callCounter](
                auto requestParams, auto /*postParams*/, const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
                }
                else
                {
                    data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
                }
                callSequenceData.push_back(data);
                callSequenceStatusCodes.push_back(413);
            }))
        .WillRepeatedly(Invoke(
            [&callSequenceData, &callSequenceStatusCodes, &callCounter, &allCallsCompleted](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;
                std::string data;
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    data = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                callSequenceData.push_back(data);
                callSequenceStatusCodes.push_back(200);
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                if (callCounter >= 2) // Complete after at least 2 calls
                {
                    allCallsCompleted = true;
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add multiple documents to trigger splitting when 413 error occurs
    for (int i = 0; i < 4; ++i)
    {
        std::string id = "large_doc_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(200, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    connector.flush();

    // Wait for completion with timeout
    auto startTime = std::chrono::steady_clock::now();
    while (!allCallsCompleted && std::chrono::steady_clock::now() - startTime < std::chrono::seconds(15))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_TRUE(allCallsCompleted) << "Timeout waiting for recursive splitting to complete";
    EXPECT_GE(callCounter.load(), 2) << "Should have made at least 2 calls (1 initial + 1+ splits)";
    EXPECT_EQ(callSequenceStatusCodes[0], 413); // Initial bulk fails
    // Subsequent calls should succeed
    for (size_t i = 1; i < callSequenceStatusCodes.size(); ++i)
    {
        EXPECT_EQ(callSequenceStatusCodes[i], 200) << "Split " << i << " should succeed";
    }
}

// Test processBulkChunk error handling - 413 with single operation too large
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError413SingleOperationTooLarge)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1) // Should be called once and fail
        .WillOnce(Invoke(
            [](RequestParamsVariant /*requestParams*/, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Single operation exceeds server limits", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Single operation exceeds server limits", 413, "");
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add a document that will trigger processing when flush is called
    std::string id = "huge_doc";
    std::string data = R"({"field":"value","huge_data":")" + std::string(800, 'x') + R"("})";

    // This should trigger an exception during flush
    EXPECT_THROW(
        {
            connector.bulkIndex(id, "test_index", data);
            connector.flush();
        },
        IndexerConnectorException);
}

// Test processBulkChunk error handling - 409 Version Conflict with retry
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError409VersionConflictWithRetry)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> retryCompletedPromise;
    std::future<void> retryCompletedFuture = retryCompletedPromise.get_future();

    int callCount = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2) // Should retry once after 409 error
        .WillOnce(Invoke(
            [&callCount](RequestParamsVariant /*requestParams*/,
                         auto postParams,
                         const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Document version conflict", 409, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Document version conflict", 409, "");
                }
            }))
        .WillOnce(Invoke(
            [&callCount, &retryCompletedPromise](RequestParamsVariant /*requestParams*/,
                                                 auto postParams,
                                                 const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                retryCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplNoFlushInterval connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("test_id", "test_index", R"({"field":"value"})");
    connector.flush();

    auto status = retryCompletedFuture.wait_for(std::chrono::seconds(10));
    ASSERT_EQ(status, std::future_status::ready) << "Timeout waiting for version conflict retry";

    EXPECT_EQ(callCount, 2) << "Should have made exactly 2 calls (1 initial + 1 retry)";
}

// Test processBulkChunk error handling - 429 Too Many Requests with retry
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError429TooManyRequestsWithRetry)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> retryCompletedPromise;
    std::future<void> retryCompletedFuture = retryCompletedPromise.get_future();

    int callCount = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2) // Should retry once after 429 error
        .WillOnce(Invoke(
            [&callCount](RequestParamsVariant /*requestParams*/,
                         auto postParams,
                         const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Too many requests", 429, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too many requests", 429, "");
                }
            }))
        .WillOnce(Invoke(
            [&callCount, &retryCompletedPromise](RequestParamsVariant /*requestParams*/,
                                                 auto postParams,
                                                 const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                retryCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplNoFlushInterval connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("test_id", "test_index", R"({"field":"value"})");
    connector.flush();

    auto status = retryCompletedFuture.wait_for(std::chrono::seconds(10));
    ASSERT_EQ(status, std::future_status::ready) << "Timeout waiting for too many requests retry";

    EXPECT_EQ(callCount, 2) << "Should have made exactly 2 calls (1 initial + 1 retry)";
}

// Test processBulkChunk error handling - Generic server error should throw exception
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkGenericServerErrorThrowsException)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [](RequestParamsVariant /*requestParams*/, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("test_id", "test_index", R"({"field":"value"})");

    EXPECT_THROW({ connector.flush(); }, IndexerConnectorException);
}

// Test processBulkChunk error handling - Stopping during chunk processing
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkStoppingDuringProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::atomic<bool> processingStarted {false};
    std::atomic<int> callCount {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [&processingStarted, &callCount](RequestParamsVariant /*requestParams*/,
                                             auto postParams,
                                             const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                processingStarted = true;
                // Simulate a shorter delay
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
            }));

    auto connector = std::make_unique<IndexerConnectorSyncImplNoFlushInterval>(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector->bulkIndex("test_id", "test_index", R"({"field":"value"})");
    connector->flush();

    // Wait for processing to start with shorter timeout
    auto startTime = std::chrono::steady_clock::now();
    while (!processingStarted && std::chrono::steady_clock::now() - startTime < std::chrono::seconds(2))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    ASSERT_TRUE(processingStarted) << "Processing should have started";

    // Stop the connector (destructor should handle stopping gracefully)
    connector.reset();

    SUCCEED(); // If we reach here without hanging, the stop mechanism worked
}

// Simple tests for DeleteByQuery callback behavior
TEST_F(IndexerConnectorSyncTest, DeleteByQuerySuccessCallback)
{
    bool callbackCalled = false;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&callbackCalled](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                callbackCalled = true;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":5,"deleted":10})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(R"({"took":5,"deleted":10})");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("test-index", "agent-123");
    connector.flush();

    EXPECT_TRUE(callbackCalled);
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryError409DoesNotThrow)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Document version conflict", 409, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Document version conflict", 409, "");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("test-index", "agent-123");

    // HTTP 409 should not cause exception in deleteByQuery callback
    EXPECT_NO_THROW(connector.flush());
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryError429DoesNotThrow)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Too many requests", 429, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too many requests", 429, "");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("test-index", "agent-123");

    // HTTP 429 should not cause exception in deleteByQuery callback
    EXPECT_NO_THROW(connector.flush());
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryGenericErrorThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal server error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal server error", 500, "");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("test-index", "agent-123");

    // Generic HTTP errors should cause exception
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryWithoutBulkDataTriggersNotify)
{
    // This test verifies the fix for DataClean: when there's only deleteByQuery (no bulk data),
    // the notify callbacks should still be triggered after flush
    bool notifyCalled = false;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                // Simulate successful deleteByQuery response
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":5,"deleted":10})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(R"({"took":5,"deleted":10})");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Register notify callback
    connector.registerNotify([&notifyCalled]() { notifyCalled = true; });

    // Call deleteByQuery (no bulk data)
    connector.deleteByQuery("test-index", "agent-123");

    // Flush should process deleteByQuery and trigger notify callback even without bulk data
    connector.flush();

    EXPECT_TRUE(notifyCalled);
}

TEST_F(IndexerConnectorSyncTest, DeleteByQueryWithBulkDataTriggersNotifyOnce)
{
    // Verify that notify is only called once when there's both deleteByQuery and bulk data
    int notifyCallCount = 0;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":5,"deleted":10})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(R"({"took":5,"deleted":10})");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Register notify callback
    connector.registerNotify([&notifyCallCount]() { notifyCallCount++; });

    // Add both bulk data and deleteByQuery
    connector.bulkIndex("id1", "test-index", R"({"field":"value"})");
    connector.deleteByQuery("test-index", "agent-123");

    // Flush should process both and trigger notify callback only once (from bulk onSuccess)
    connector.flush();

    EXPECT_EQ(notifyCallCount, 1);
}

// Test to specifically trigger processBulkChunk execution
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkDirectExecution)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track if processBulkChunk was called
    std::atomic<bool> processBulkChunkCalled {false};
    std::atomic<int> callCount {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(3)) // Initial bulk + 2 chunks from split
        .WillOnce(Invoke(
            [&callCount](RequestParamsVariant /*requestParams*/,
                         auto postParams,
                         const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                // First call fails with 413 to trigger splitAndProcessBulk
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
                }
            }))
        .WillRepeatedly(Invoke(
            [&callCount, &processBulkChunkCalled](RequestParamsVariant /*requestParams*/,
                                                  auto postParams,
                                                  const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                processBulkChunkCalled = true;
                // Subsequent calls succeed
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                }
            }));

    // Use a larger bulk size to ensure we have enough data to trigger splitting
    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 2048, 0> connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add multiple documents to create a bulk operation that will be split
    for (int i = 0; i < 10; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Force flush to trigger processing
    connector.flush();

    // Wait a bit for processing to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Verify that processBulkChunk was called
    EXPECT_TRUE(processBulkChunkCalled.load()) << "processBulkChunk should have been called";
    EXPECT_GE(callCount.load(), 3) << "Should have made at least 3 calls (1 initial + 2 chunks)";
}

// Test to specifically trigger processBulkChunk onError execution
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkOnErrorExecution)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track calls to processBulkChunk
    std::atomic<int> callCount {0};
    std::atomic<bool> onErrorCalled {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2) // Initial bulk + 1 chunk (the flow is interrupted by exception)
        .WillOnce(Invoke(
            [&callCount](RequestParamsVariant /*requestParams*/,
                         auto postParams,
                         const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                // First call fails with 413 to trigger splitAndProcessBulk
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
                }
            }))
        .WillOnce(Invoke(
            [&callCount, &onErrorCalled](RequestParamsVariant /*requestParams*/,
                                         auto postParams,
                                         const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                // Second call (first chunk) fails with 500 to trigger onError without retry
                onErrorCalled = true;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
            }));

    // Use a larger bulk size to ensure we have enough data to trigger splitting
    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 2048, 0> connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add multiple documents to create a bulk operation that will be split
    for (int i = 0; i < 10; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Force flush to trigger processing - this should throw due to 500 error
    EXPECT_THROW(connector.flush(), IndexerConnectorException);

    // Verify that onError was called
    EXPECT_TRUE(onErrorCalled.load()) << "processBulkChunk onError should have been called";
    EXPECT_GE(callCount.load(), 2) << "Should have made at least 2 calls (1 initial + 1 chunk)";
}

// Test to simulate 413 -> 429 -> 409 -> 200 success flow
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError413Then429ThenSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track calls and error states
    std::atomic<int> callCount {0};
    std::atomic<bool> error413Called {false};
    std::atomic<bool> error429Called {false};
    std::atomic<bool> error409Called {false};
    std::atomic<bool> successCalled {false};
    std::atomic<bool> finished {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&callCount, &error413Called, &error429Called, &error409Called, &successCalled, &finished](
                RequestParamsVariant /*requestParams*/,
                auto postParams,
                const ConfigurationParameters& /*configParams*/)
            {
                ++callCount;
                if (callCount == 1)
                {
                    error413Called = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                }
                else if (callCount == 2)
                {
                    error429Called = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 429, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Too Many Requests", 429, "");
                    }
                }
                else if (callCount == 3)
                {
                    error409Called = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Document version conflict", 409, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Document version conflict", 409, "");
                    }
                }
                else
                {
                    successCalled = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    finished = true;
                }
            }));

    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 2048, 0> connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < 10; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    connector.flush();

    EXPECT_TRUE(error413Called.load()) << "Error 413 should have been called";
    EXPECT_TRUE(error429Called.load()) << "Error 429 should have been called";
    EXPECT_TRUE(error409Called.load()) << "Error 409 should have been called";
    EXPECT_TRUE(successCalled.load()) << "Success should have been called";
    EXPECT_GE(callCount.load(), 4) << "Should have made at least 4 calls";
    EXPECT_TRUE(finished.load()) << "Test did not finish in time (possible infinite retry)";
}

// Test to simulate 413 -> 413 -> 200 success flow
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError413Then413ThenSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track calls and error states
    std::atomic<int> callCount {0};
    std::atomic<bool> error413CalledFirst {false};
    std::atomic<bool> error413CalledSecond {false};
    std::atomic<bool> successCalled {false};
    std::atomic<bool> finished {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&callCount, &error413CalledFirst, &error413CalledSecond, &successCalled, &finished](
                RequestParamsVariant /*requestParams*/,
                auto postParams,
                const ConfigurationParameters& /*configParams*/)
            {
                ++callCount;
                if (callCount == 1)
                {
                    error413CalledFirst = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                }
                else if (callCount == 2)
                {
                    error413CalledSecond = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Too Many Requests", 413, "");
                    }
                }
                else
                {
                    successCalled = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    finished = true;
                }
            }));

    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 2048, 0> connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < 10; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    connector.flush();

    EXPECT_TRUE(error413CalledFirst.load()) << "Error 413 should have been called";
    EXPECT_TRUE(error413CalledSecond.load()) << "Error 413 should have been called";
    EXPECT_TRUE(successCalled.load()) << "Success should have been called";
    EXPECT_GE(callCount.load(), 3) << "Should have made at least 3 calls";
    EXPECT_TRUE(finished.load()) << "Test did not finish in time (possible infinite retry)";
}

// Test to simulate 413 -> 413 -> exception flow
TEST_F(IndexerConnectorSyncTest, ProcessBulkChunkError413Then413ThenException)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Track calls and error states
    std::atomic<int> callCount {0};
    std::atomic<bool> error413CalledFirst {false};
    std::atomic<bool> error413CalledSecond {false};
    std::atomic<bool> successCalled {false};
    std::atomic<bool> finished {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&callCount, &error413CalledFirst, &error413CalledSecond, &successCalled, &finished](
                RequestParamsVariant /*requestParams*/,
                auto postParams,
                const ConfigurationParameters& /*configParams*/)
            {
                ++callCount;
                if (callCount == 1)
                {
                    error413CalledFirst = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
                    }
                }
                else if (callCount == 2)
                {
                    error413CalledSecond = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Too Many Requests", 413, "");
                    }
                }
                else
                {
                    successCalled = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(R"({"took":1,"errors":false,"items":[]})");
                    }
                    finished = true;
                }
            }));

    IndexerConnectorSyncImpl<MockServerSelector, MockHTTPRequest, 2048, 0> connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < 2; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(100, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    EXPECT_THROW(connector.flush(), IndexerConnectorException);

    EXPECT_TRUE(error413CalledFirst.load()) << "Error 413 should have been called";
    EXPECT_TRUE(error413CalledSecond.load()) << "Error 413 should have been called";
    EXPECT_FALSE(successCalled.load()) << "Success should not have been called";
    EXPECT_GE(callCount.load(), 2) << "Should have made at least 3 calls";
    EXPECT_FALSE(finished.load()) << "Test should have thrown an exception";
}

// Test version handling in bulk index operations for sync connector
TEST_F(IndexerConnectorSyncTest, BulkIndexWithVersionHandling)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBulkData, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                std::visit([&capturedBulkData](auto&& request) { capturedBulkData = request.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test with version
    connector.bulkIndex("doc1", "index1", R"({"field":"value1"})", "12345");
    // Test without version
    connector.bulkIndex("doc2", "index1", R"({"field":"value2"})");

    connector.flush();

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for version test processing";

    // Verify version is included in the bulk data for doc1
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("version":"12345")"));
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("version_type":"external_gte")"));

    // Verify doc2 does not have version information
    std::size_t doc2_pos = capturedBulkData.find("doc2");
    EXPECT_NE(doc2_pos, std::string::npos);
    std::size_t doc2_end = capturedBulkData.find('\n', doc2_pos);
    std::string doc2_metadata = capturedBulkData.substr(doc2_pos, doc2_end - doc2_pos);
    EXPECT_THAT(doc2_metadata, ::testing::Not(::testing::HasSubstr("version")));
}

// Test escaping special characters in document IDs for bulkIndex
TEST_F(IndexerConnectorSyncTest, BulkIndexEscapesSpecialCharactersInId)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBulkData, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                std::visit([&capturedBulkData](auto&& request) { capturedBulkData = request.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test various special characters that need escaping
    connector.bulkIndex("001_dum\\amy", "test_index", R"({"group":"dum\\amy"})");
    connector.bulkIndex("002_tab\tchar", "test_index", R"({"name":"tab\tchar"})");
    connector.bulkIndex("003_quote\"char", "test_index", R"({"name":"quote\"char"})");
    connector.bulkIndex("004_newline\nchar", "test_index", R"({"name":"newline\nchar"})");

    connector.flush();

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for escape test processing";

    // Verify backslash is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"001_dum\\amy")"));

    // Verify tab is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"002_tab\tchar")"));

    // Verify quote is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"003_quote\"char")"));

    // Verify newline is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"004_newline\nchar")"));

    // Verify the bulk data is valid (no JSON parse errors would occur)
    EXPECT_FALSE(capturedBulkData.empty());
}

// Test escaping special characters in document IDs for bulkDelete
TEST_F(IndexerConnectorSyncTest, BulkDeleteEscapesSpecialCharactersInId)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBulkData, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                std::visit([&capturedBulkData](auto&& request) { capturedBulkData = request.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test special characters in delete operations
    connector.bulkDelete("001_dum\\amy", "test_index");
    connector.bulkDelete("002_tab\tchar", "test_index");

    connector.flush();

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for delete escape test processing";

    // Verify backslash is properly escaped in delete ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"001_dum\\amy")"));

    // Verify tab is properly escaped in delete ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"002_tab\tchar")"));
}

// Test that IDs without special characters are not unnecessarily escaped
TEST_F(IndexerConnectorSyncTest, BulkIndexDoesNotEscapeNormalIds)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBulkData, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                std::visit([&capturedBulkData](auto&& request) { capturedBulkData = request.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test normal IDs that don't need escaping
    connector.bulkIndex("001_normal_id", "test_index", R"({"field":"value"})");
    connector.bulkIndex("002-another-normal-id_123", "test_index", R"({"field":"value"})");

    connector.flush();

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for normal ID test processing";

    // Verify normal IDs are passed through unchanged
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"001_normal_id")"));
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"002-another-normal-id_123")"));
}

// Test error handling for invalid input with version in sync connector
TEST_F(IndexerConnectorSyncTest, ErrorHandlingForInvalidInputWithVersion)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test with empty index - should throw exception
    EXPECT_THROW(connector.bulkIndex("doc1", "", R"({"field":"value"})", "123"), IndexerConnectorException);

    // Test with version provided but empty id - should throw exception
    EXPECT_THROW(connector.bulkIndex("", "index1", R"({"field":"value"})", "456"), IndexerConnectorException);

    // Test with empty data - should not throw but log warning
    EXPECT_NO_THROW(connector.bulkIndex("doc2", "index1", "", "789"));
}

// Tests for executeUpdateByQuery - generic update by query operation
TEST_F(IndexerConnectorSyncTest, ExecuteUpdateByQuerySuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::vector<std::string> indices = {"wazuh-states-fim-files", "wazuh-states-sca"};
    bool notifyCalled = false;

    // Setup expectations
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke([this](auto requestParams, const auto& postParams, auto configParams)
                         { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));

    connector.registerNotify([&notifyCalled]() { notifyCalled = true; });

    // Build a sample update query (simulating what inventory_sync would build)
    nlohmann::json updateQuery;
    updateQuery["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"] = "agent-001";
    updateQuery["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"] = "state.document_version";
    updateQuery["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"] = 12345;
    updateQuery["query"]["bool"]["minimum_should_match"] = 1;
    updateQuery["script"]["source"] = "ctx._source.field = params.value";
    updateQuery["script"]["lang"] = "painless";
    updateQuery["script"]["params"]["value"] = "test-value";

    // Call the generic function
    EXPECT_NO_THROW(connector.executeUpdateByQuery(indices, updateQuery));

    // Verify the request was made
    EXPECT_EQ(callCount, 1);
    EXPECT_TRUE(notifyCalled) << "Notify callback should have been called";

    // Verify the request contained the correct data
    auto requestData = nlohmann::json::parse(receivedData[0]);
    EXPECT_EQ(requestData["query"]["bool"]["must"][0]["term"]["wazuh.agent.id"], "agent-001");
    EXPECT_EQ(requestData["query"]["bool"]["should"][0]["bool"]["must_not"]["exists"]["field"],
              "state.document_version");
    EXPECT_EQ(requestData["query"]["bool"]["should"][1]["range"]["state.document_version"]["lte"], 12345);
    EXPECT_EQ(requestData["query"]["bool"]["minimum_should_match"], 1);
    EXPECT_TRUE(requestData.contains("script"));
    EXPECT_EQ(requestData["script"]["source"], "ctx._source.field = params.value");
    EXPECT_EQ(requestData["script"]["params"]["value"], "test-value");
}

TEST_F(IndexerConnectorSyncTest, ExecuteUpdateByQueryError)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::vector<std::string> indices = {"wazuh-states-fim-files"};
    bool notifyCalled = false;

    // Setup error expectation
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::string url;
                    std::visit([&url](const auto& params) { url = params.url.url(); }, requestParams);
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError(url, 500, "Internal server error");
                }
            }));

    connector.registerNotify([&notifyCalled]() { notifyCalled = true; });

    // Build a sample update query
    nlohmann::json updateQuery;
    updateQuery["query"]["term"]["field"] = "value";
    updateQuery["script"]["source"] = "ctx._source.field = params.value";
    updateQuery["script"]["params"]["value"] = "new-value";

    // Call should throw exception on fatal error
    EXPECT_THROW(connector.executeUpdateByQuery(indices, updateQuery), IndexerConnectorException);

    EXPECT_FALSE(notifyCalled) << "Notify callback should not have been called on error";
}

// Test with version conflict retry
TEST_F(IndexerConnectorSyncTest, ExecuteUpdateByQueryWithRetry)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::vector<std::string> indices = {"wazuh-states-sca"};
    bool notifyCalled = false;
    int attempts = 0;

    // First call fails with version conflict, second succeeds
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2)
        .WillOnce(Invoke(
            [&attempts](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                attempts++;
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::string url;
                    std::visit([&url](const auto& params) { url = params.url.url(); }, requestParams);
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError(url, 409, "Version conflict");
                }
            }))
        .WillOnce(Invoke(
            [this, &attempts](auto requestParams, const auto& postParams, auto configParams)
            {
                attempts++;
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
            }));

    connector.registerNotify([&notifyCalled]() { notifyCalled = true; });

    // Build a sample update query
    nlohmann::json updateQuery;
    updateQuery["query"]["term"]["wazuh.agent.id"] = "agent-003";
    updateQuery["script"]["source"] = "ctx._source.groups = params.groups";
    updateQuery["script"]["params"]["groups"] = std::vector<std::string> {"default"};

    // Call should succeed after retry
    EXPECT_NO_THROW(connector.executeUpdateByQuery(indices, updateQuery));

    EXPECT_EQ(attempts, 2) << "Should have retried once";
    EXPECT_TRUE(notifyCalled) << "Notify callback should have been called after successful retry";
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQuerySuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::string requestData;
    std::string requestUrl;

    // Setup expectations for successful search
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&requestData, &requestUrl](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                std::visit([&requestUrl](const auto& params) { requestUrl = params.url.url(); }, requestParams);
                std::visit([&requestData](const auto& params) { requestData = params.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    nlohmann::json response;
                    response["hits"]["total"]["value"] = 2;
                    response["hits"]["hits"] = nlohmann::json::array();

                    nlohmann::json hit1;
                    hit1["_id"] = "doc1";
                    hit1["_source"]["checksum"]["hash"]["sha1"] = "abc123";
                    hit1["_source"]["wazuh"]["agent"]["id"] = "001";
                    hit1["sort"] = nlohmann::json::array({"doc1"});
                    response["hits"]["hits"].push_back(hit1);

                    nlohmann::json hit2;
                    hit2["_id"] = "doc2";
                    hit2["_source"]["checksum"]["hash"]["sha1"] = "def456";
                    hit2["_source"]["wazuh"]["agent"]["id"] = "001";
                    hit2["sort"] = nlohmann::json::array({"doc2"});
                    response["hits"]["hits"].push_back(hit2);

                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
            }));

    nlohmann::json searchQuery;
    searchQuery["query"]["term"]["wazuh.agent.id"] = "001";
    searchQuery["_source"] = nlohmann::json::array({"checksum.hash.sha1"});
    searchQuery["sort"] = nlohmann::json::array({nlohmann::json::object({{"checksum.hash.sha1", "asc"}})});
    searchQuery["size"] = 1000;

    nlohmann::json result = connector.executeSearchQuery("wazuh-states-vulnerabilities", searchQuery);

    // Verify URL is correct
    EXPECT_EQ(requestUrl, "mockserver:9200/wazuh-states-vulnerabilities/_search");

    // Verify request data contains the query
    nlohmann::json parsedRequest = nlohmann::json::parse(requestData);
    EXPECT_EQ(parsedRequest["query"]["term"]["wazuh.agent.id"], "001");
    EXPECT_EQ(parsedRequest["size"], 1000);

    // Verify response structure
    EXPECT_TRUE(result.contains("hits"));
    EXPECT_EQ(result["hits"]["total"]["value"], 2);
    EXPECT_EQ(result["hits"]["hits"].size(), 2);
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithSearchAfter)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::string requestData;

    // Setup expectations for search with search_after
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&requestData](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                std::visit([&requestData](const auto& params) { requestData = params.data; }, requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    nlohmann::json response;
                    response["hits"]["hits"] = nlohmann::json::array();
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
            }));

    nlohmann::json searchQuery;
    searchQuery["query"]["term"]["wazuh.agent.id"] = "001";
    searchQuery["_source"] = nlohmann::json::array({"checksum.hash.sha1"});
    searchQuery["sort"] = nlohmann::json::array({nlohmann::json::object({{"checksum.hash.sha1", "asc"}})});
    searchQuery["search_after"] = nlohmann::json::array({"previous_doc_id"});
    searchQuery["size"] = 1000;

    nlohmann::json result = connector.executeSearchQuery("wazuh-states-vulnerabilities", searchQuery);

    // Verify request data contains search_after
    nlohmann::json parsedRequest = nlohmann::json::parse(requestData);
    EXPECT_TRUE(parsedRequest.contains("search_after"));
    EXPECT_EQ(parsedRequest["search_after"][0], "previous_doc_id");
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryError)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Setup error expectation
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto requestParams, const auto& postParams, auto /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::string url;
                    std::visit([&url](const auto& params) { url = params.url.url(); }, requestParams);
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError(url, 500, "Internal server error");
                }
            }));

    nlohmann::json searchQuery;
    searchQuery["query"]["term"]["wazuh.agent.id"] = "001";

    // Call should throw exception on error
    EXPECT_THROW(connector.executeSearchQuery("wazuh-states-vulnerabilities", searchQuery), IndexerConnectorException);
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryEmptyResults)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Setup expectations for empty search results
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, auto /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    nlohmann::json response;
                    response["hits"]["total"]["value"] = 0;
                    response["hits"]["hits"] = nlohmann::json::array();
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response.dump());
                }
            }));

    nlohmann::json searchQuery;
    searchQuery["query"]["term"]["wazuh.agent.id"] = "999";

    nlohmann::json result = connector.executeSearchQuery("wazuh-states-vulnerabilities", searchQuery);

    // Verify response structure with no results
    EXPECT_TRUE(result.contains("hits"));
    EXPECT_EQ(result["hits"]["total"]["value"], 0);
    EXPECT_EQ(result["hits"]["hits"].size(), 0);
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithPaginationEmptyResults)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto, const auto& postParams, auto)
            {
                std::string mockResponse = R"({"took":1,"hits":{"total":{"value":0}}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(mockResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(mockResponse));
                }
            }));

    nlohmann::json query;
    query["size"] = 1000;
    query["query"]["term"]["package.name"] = "test-package";

    // Execute with callback (required by new signature)
    EXPECT_NO_THROW(connector.executeSearchQueryWithPagination("test-index", query, [](const nlohmann::json&) {}));
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithPaginationWithCallbackTwoPages)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    int callbackCount = 0;
    int postCallCount = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2)
        .WillOnce(Invoke(
            [&postCallCount](auto, const auto& postParams, auto)
            {
                postCallCount++;
                // First page with data, hits has an ID and sort field for pagination
                // NOTE: Returns 1 hit.
                std::string mockResponse =
                    R"({"took":1,"hits":{"total":{"value":2},"hits":[{"_id":"1","sort":["1"]}]}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(mockResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(mockResponse));
                }
            }))
        .WillOnce(Invoke(
            [&postCallCount](auto, const auto& postParams, auto)
            {
                postCallCount++;
                // Second page empty, hits is empty
                std::string mockResponse = R"({"took":1,"hits":{"total":{"value":0},"hits":[]}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(mockResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(mockResponse));
                }
            }));

    nlohmann::json query;
    query["size"] = 1;
    query["query"]["term"]["package.name"] = "test-package";
    query["sort"][0]["_id"] = "asc";

    auto callback = [&callbackCount](const nlohmann::json& response)
    {
        callbackCount++;
    };

    EXPECT_NO_THROW(connector.executeSearchQueryWithPagination("test-index", query, callback));

    EXPECT_EQ(postCallCount, 2) << "Should have made 2 POST requests (2 pages)";
    EXPECT_EQ(callbackCount, 2) << "Callback should have been invoked 2 times (first page + empty page)";
}

// ==================== Document-Level Bulk Response Validation Tests ====================

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationAllSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate successful bulk response with no errors
                std::string successResponse = R"({
                    "took": 10,
                    "errors": false,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {"_id": "2", "status": 201}},
                        {"delete": {"_id": "3", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(successResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(successResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"field":"value2"})");
    connector.bulkDelete("3", "test-index");

    EXPECT_NO_THROW(connector.flush());
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationVersionConflictAccepted)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate bulk response with version conflict (same version already indexed)
                std::string versionConflictResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {
                            "_id": "2",
                            "status": 409,
                            "error": {
                                "type": "version_conflict_engine_exception",
                                "reason": "[2]: version conflict, current version [5] is higher or equal to the one provided [5]"
                            }
                        }},
                        {"index": {"_id": "3", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(versionConflictResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(versionConflictResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})", "5");
    connector.bulkIndex("2", "test-index", R"({"field":"value2"})", "5");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})", "5");

    // Should not throw - version conflicts are acceptable
    EXPECT_NO_THROW(connector.flush());
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationRealFailure)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate bulk response with real indexing failure (e.g., 400 bad request)
                std::string failureResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {
                            "_id": "2",
                            "status": 400,
                            "error": {
                                "type": "mapper_parsing_exception",
                                "reason": "failed to parse field [timestamp] of type [date]"
                            }
                        }},
                        {"index": {"_id": "3", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(failureResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(failureResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"timestamp":"invalid"})");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})");

    // Should throw - real indexing failure
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationMixedOperations)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate bulk response with mixed operations and version conflicts
                std::string mixedResponse = R"({
                    "took": 15,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 201}},
                        {"delete": {"_id": "2", "status": 200}},
                        {"index": {
                            "_id": "3",
                            "status": 409,
                            "error": {
                                "type": "version_conflict_engine_exception",
                                "reason": "[3]: version conflict, current version [3] is higher or equal to the one provided [3]"
                            }
                        }},
                        {"index": {"_id": "4", "status": 200}},
                        {"delete": {
                            "_id": "5",
                            "status": 409,
                            "error": {
                                "type": "version_conflict_engine_exception",
                                "reason": "version conflict on delete"
                            }
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(mixedResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(mixedResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})", "1");
    connector.bulkDelete("2", "test-index");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})", "3");
    connector.bulkIndex("4", "test-index", R"({"field":"value4"})", "4");
    connector.bulkDelete("5", "test-index");

    // Should not throw - all are either success or acceptable version conflicts
    EXPECT_NO_THROW(connector.flush());
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationVersionConflictWithoutErrorType)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate version conflict without proper error details - should be treated as failure
                std::string badConflictResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {
                            "_id": "2",
                            "status": 409,
                            "error": "Some generic error string"
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(badConflictResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(badConflictResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"field":"value2"})");

    // Should throw - version conflict without proper error type
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationMultipleRealFailures)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Simulate multiple real failures
                std::string multiFailureResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {
                            "_id": "2",
                            "status": 400,
                            "error": {
                                "type": "mapper_parsing_exception",
                                "reason": "failed to parse"
                            }
                        }},
                        {"index": {
                            "_id": "3",
                            "status": 500,
                            "error": {
                                "type": "internal_error",
                                "reason": "internal server error"
                            }
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(multiFailureResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(multiFailureResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"bad":"data"})");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})");

    // Should throw - multiple real failures
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationMissingErrorsField)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Response without 'errors' field - should be treated as success
                std::string noErrorsFieldResponse = R"({
                    "took": 10,
                    "items": [
                        {"index": {"_id": "1", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(noErrorsFieldResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(noErrorsFieldResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should not throw - missing 'errors' field treated as success
    EXPECT_NO_THROW(connector.flush());
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationErrorsTrueButMissingItems)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // errors=true but no 'items' array - should fail
                std::string missingItemsResponse = R"({
                    "took": 10,
                    "errors": true
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(missingItemsResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(missingItemsResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should throw - errors=true but items array missing
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationEmptyItem)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Empty item in items array
                std::string emptyItemResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {},
                        {"index": {"_id": "3", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(emptyItemResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(emptyItemResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"field":"value2"})");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})");

    // Should throw - empty item counts as failure
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationItemMissingStatus)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Item missing 'status' field
                std::string missingStatusResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {"_id": "1", "status": 200}},
                        {"index": {"_id": "2"}},
                        {"index": {"_id": "3", "status": 200}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(missingStatusResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(missingStatusResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.bulkIndex("2", "test-index", R"({"field":"value2"})");
    connector.bulkIndex("3", "test-index", R"({"field":"value3"})");

    // Should throw - item missing status field
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationInvalidJSON)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Invalid JSON - should trigger parse exception
                std::string invalidJSON = R"({"took": 10, "errors": false, invalid json})";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(invalidJSON);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(invalidJSON));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should throw - invalid JSON triggers parse exception
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationErrorAsString)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Error as simple string instead of object
                std::string errorStringResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {
                            "_id": "1",
                            "status": 500,
                            "error": "Internal server error"
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorStringResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(errorStringResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should throw - error as string still counts as failure
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

// ==================== Additional Tests for Coverage Improvement ====================

// Tests for scopeLock()
TEST_F(IndexerConnectorSyncTest, ScopeLockCanBeLocked)
{
    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest);

    // Test that we can acquire a scope lock
    {
        auto lock = connector.scopeLock();
        EXPECT_TRUE(lock.owns_lock());
    }

    // Test that we can acquire it again after releasing
    {
        auto lock = connector.scopeLock();
        EXPECT_TRUE(lock.owns_lock());
    }
}

TEST_F(IndexerConnectorSyncTest, ScopeLockPreventsRaceConditions)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    std::atomic<int> counter {0};

    auto incrementWithLock = [&connector, &counter]()
    {
        for (int i = 0; i < 100; ++i)
        {
            auto lock = connector.scopeLock();
            counter++;
        }
    };

    std::thread t1(incrementWithLock);
    std::thread t2(incrementWithLock);

    t1.join();
    t2.join();

    EXPECT_EQ(counter, 200);
}

// Tests for isAvailable()
TEST_F(IndexerConnectorSyncTest, IsAvailableReturnsTrueWhenSelectorAvailable)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, isAvailable()).WillOnce(Return(true));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    EXPECT_TRUE(connector.isAvailable());
}

TEST_F(IndexerConnectorSyncTest, IsAvailableReturnsFalseWhenSelectorUnavailable)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, isAvailable()).WillOnce(Return(false));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    EXPECT_FALSE(connector.isAvailable());
}

// Tests for Multiple CA Certificates
TEST_F(IndexerConnectorSyncTest, ConstructorWithSingleCACertificate)
{
    std::string caFile = "/tmp/ca1_test.pem";

    // Create test SSL file
    std::ofstream(caFile) << "-----BEGIN CERTIFICATE-----\ntest ca cert\n-----END CERTIFICATE-----";

    config["ssl"]["certificate_authorities"] = nlohmann::json::array({caFile});

    EXPECT_NO_THROW({ IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest); });

    // Cleanup
    std::filesystem::remove(caFile);
}

// Tests for bulkIndex edge cases
TEST_F(IndexerConnectorSyncTest, BulkIndexWithEmptyIndex)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Empty index should throw
    EXPECT_THROW(connector.bulkIndex("id1", "", R"({"field":"value"})"), IndexerConnectorException);
}

TEST_F(IndexerConnectorSyncTest, BulkIndexWithEmptyData)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Empty data should not throw but should log a warning
    EXPECT_NO_THROW(connector.bulkIndex("id1", "test-index", ""));
}

TEST_F(IndexerConnectorSyncTest, BulkIndexWithVersionButNoId)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Version without ID should throw
    EXPECT_THROW(connector.bulkIndex("", "test-index", R"({"field":"value"})", "1"), IndexerConnectorException);
}

TEST_F(IndexerConnectorSyncTest, BulkIndexWithEmptyIdButNoVersion)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Empty ID without version should be allowed (auto-generated ID)
    EXPECT_NO_THROW(connector.bulkIndex("", "test-index", R"({"field":"value"})"));
}

// Tests for executeSearchQueryWithPagination edge cases
TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithPaginationNoSortField)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    int callCount = 0;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&callCount](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                // Response without sort field - should stop pagination
                std::string response = R"({
                    "hits": {
                        "total": {"value": 1},
                        "hits": [
                            {"_id": "1", "_source": {"field": "value1"}}
                        ]
                    }
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    nlohmann::json query = {{"size", 10}, {"query", {{"match_all", {}}}}};

    int responseCount = 0;
    connector.executeSearchQueryWithPagination(
        "test-index", query, [&responseCount](const nlohmann::json& response) { responseCount++; });

    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(responseCount, 1);
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithPaginationSortNotString)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    int callCount = 0;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&callCount](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                // Response with sort field that is not a string - should stop pagination
                std::string response = R"({
                    "hits": {
                        "total": {"value": 1},
                        "hits": [
                            {"_id": "1", "_source": {"field": "value1"}, "sort": [123]}
                        ]
                    }
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    nlohmann::json query = {{"size", 10}, {"query", {{"match_all", {}}}}};

    int responseCount = 0;
    connector.executeSearchQueryWithPagination(
        "test-index", query, [&responseCount](const nlohmann::json& response) { responseCount++; });

    EXPECT_EQ(callCount, 1);
    EXPECT_EQ(responseCount, 1);
}

TEST_F(IndexerConnectorSyncTest, ExecuteSearchQueryWithPaginationNoSizeInQuery)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    int callCount = 0;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2)
        .WillOnce(Invoke(
            [&callCount](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                std::string response = R"({
                    "hits": {
                        "total": {"value": 2},
                        "hits": [
                            {"_id": "1", "_source": {"field": "value1"}, "sort": ["sort1"]}
                        ]
                    }
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }))
        .WillOnce(Invoke(
            [&callCount](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                callCount++;
                std::string response = R"({
                    "hits": {
                        "total": {"value": 2},
                        "hits": []
                    }
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Query without size field
    nlohmann::json query = {{"query", {{"match_all", {}}}}};

    int responseCount = 0;
    connector.executeSearchQueryWithPagination(
        "test-index", query, [&responseCount](const nlohmann::json& response) { responseCount++; });

    EXPECT_EQ(callCount, 2);
    EXPECT_EQ(responseCount, 2);
}

// Tests for flush() edge cases
TEST_F(IndexerConnectorSyncTest, FlushWithNoData)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Should not call HTTP post if there's no data
    EXPECT_CALL(mockHttpRequest, post(_, _, _)).Times(0);

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Flush without adding any data should not throw
    EXPECT_NO_THROW(connector.flush());
}

// Tests for validateBulkResponse edge cases
TEST_F(IndexerConnectorSyncTest, BulkResponseValidationErrorObjectWithoutReason)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Error as object without reason field
                std::string errorObjectResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {
                            "_id": "1",
                            "status": 500,
                            "error": {
                                "type": "some_error_type"
                            }
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorObjectResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(errorObjectResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should throw - error without reason is still a failure
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

TEST_F(IndexerConnectorSyncTest, BulkResponseValidationVersionConflictWithDifferentType)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;
                // Version conflict with a different error type (not version_conflict_engine_exception)
                std::string versionConflictResponse = R"({
                    "took": 10,
                    "errors": true,
                    "items": [
                        {"index": {
                            "_id": "1",
                            "status": 409,
                            "error": {
                                "type": "some_other_conflict_type",
                                "reason": "Different kind of conflict"
                            }
                        }}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(versionConflictResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onSuccess(std::move(versionConflictResponse));
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");

    // Should throw - version conflict without version_conflict_engine_exception is a failure
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
    EXPECT_TRUE(postCalled);
}

// Tests for deleteByQuery with 404 response
TEST_F(IndexerConnectorSyncTest, DeleteByQueryWith404Response)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    bool postCalled = false;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&postCalled](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                postCalled = true;

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Index not found", 404, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Index not found", 404, "");
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("nonexistent-index", "agent1");

    // Should not throw - 404 is acceptable for deleteByQuery
    EXPECT_NO_THROW(connector.flush());
    EXPECT_TRUE(postCalled);
}

// Tests for registerNotify
TEST_F(IndexerConnectorSyncTest, RegisterNotifyMultipleCallbacks)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    int callback1Count = 0;
    int callback2Count = 0;
    int callback3Count = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke([this](auto requestParams, auto postParams, const ConfigurationParameters& configParams)
                         { this->simulateSuccessfulPost(requestParams, postParams, configParams); }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Register multiple callbacks
    connector.registerNotify([&callback1Count]() { callback1Count++; });
    connector.registerNotify([&callback2Count]() { callback2Count++; });
    connector.registerNotify([&callback3Count]() { callback3Count++; });

    // Trigger bulk operation
    connector.bulkIndex("1", "test-index", R"({"field":"value1"})");
    connector.flush();

    // All callbacks should be called once
    EXPECT_EQ(callback1Count, 1);
    EXPECT_EQ(callback2Count, 1);
    EXPECT_EQ(callback3Count, 1);
}

TEST_F(IndexerConnectorSyncTest, RegisterNotifyCallbacksNotCalledOnError)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    int callbackCount = 0;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [](auto requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Internal Server Error", 500, "");
                }
            }));

    IndexerConnectorSyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Register callback
    connector.registerNotify([&callbackCount]() { callbackCount++; });

    // Trigger bulk operation that will fail - this will throw when buffer fills
    EXPECT_ANY_THROW({
        for (int i = 0; i < 20; ++i)
        {
            std::string id = "id" + std::to_string(i);
            std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
            connector.bulkIndex(id, "test-index", data);
        }
    });

    // Callback should not be called on error
    EXPECT_EQ(callbackCount, 0);
}
