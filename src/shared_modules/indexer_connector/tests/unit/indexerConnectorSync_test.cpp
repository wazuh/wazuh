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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Payload Too Large", 413);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
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
                            .onError("Version Conflict", 409);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Version Conflict", 409);
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
                            .onError("Too Many Requests", 429);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too Many Requests", 429);
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
                        .onError("Internal Server Error", 500);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Internal Server Error", 500);
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Payload Too Large", 413);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
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
                        .onError("Single operation exceeds server limits", 413);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Single operation exceeds server limits", 413);
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
                        .onError("Document version conflict", 409);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Document version conflict", 409);
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Too many requests", 429);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too many requests", 429);
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
                        .onError("Internal Server Error", 500);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Internal Server Error", 500);
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
                        .onError("Document version conflict", 409);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams)
                        .onError("Document version conflict", 409);
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Too many requests", 429);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too many requests", 429);
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
                        .onError("Internal server error", 500);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Internal server error", 500);
                }
            }));

    IndexerConnectorSyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.deleteByQuery("test-index", "agent-123");

    // Generic HTTP errors should cause exception
    EXPECT_THROW(connector.flush(), IndexerConnectorException);
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Payload Too Large", 413);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Payload Too Large", 413);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
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
                        .onError("Internal Server Error", 500);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Internal Server Error", 500);
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
                            .onError("Payload Too Large", 413);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
                    }
                }
                else if (callCount == 2)
                {
                    error429Called = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 429);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too Many Requests", 429);
                    }
                }
                else if (callCount == 3)
                {
                    error409Called = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Document version conflict", 409);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Document version conflict", 409);
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
                            .onError("Payload Too Large", 413);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
                    }
                }
                else if (callCount == 2)
                {
                    error413CalledSecond = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 413);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too Many Requests", 413);
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
                            .onError("Payload Too Large", 413);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413);
                    }
                }
                else if (callCount == 2)
                {
                    error413CalledSecond = true;
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Too Many Requests", 413);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Too Many Requests", 413);
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
