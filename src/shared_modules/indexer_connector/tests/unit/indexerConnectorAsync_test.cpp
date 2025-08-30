#include "indexerConnectorAsyncImpl.hpp"
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

// Define different connector types with GMock for async testing
using IndexerConnectorAsyncImplTest = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest>;
using IndexerConnectorAsyncImplSmallBulk = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 5, 5, 0>;
using IndexerConnectorAsyncImplSmallBulkPair = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 2, 5, 0>;
using IndexerConnectorAsyncImplSmallBulkNoFlushInterval =
    IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 5, 0, 0>;

// Test fixture using GMock for async implementation
class IndexerConnectorAsyncTest : public ::testing::Test
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

        // Clean up any queue files
        std::filesystem::remove_all("queue/indexer/");
    }

    void simulateSuccessfulPost(RequestParamsVariant requestParams,
                                const PostRequestParametersVariant& postParams,
                                ConfigurationParameters /*configParams*/)
    {
        callCount++;

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

    void simulateSuccessfulWithErrorsPost(RequestParamsVariant requestParams,
                                          const PostRequestParametersVariant& postParams,
                                          ConfigurationParameters /*configParams*/)
    {
        callCount++;

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
        receivedData.push_back(data);

        // Simulate successful response
        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
        {
            std::get<TPostRequestParameters<const std::string&>>(postParams)
                .onSuccess(
                    R"({"took":1,"errors":true,"items":[{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}}]})");
        }
        else
        {
            std::get<TPostRequestParameters<std::string&&>>(postParams)
                .onSuccess(
                    R"({"took":1,"errors":true,"items":[{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}},{"index":{"error":{"reason":"test error","type":"test type"}}}]})");
        }
    }
};

// Basic constructor and destructor tests
TEST_F(IndexerConnectorAsyncTest, ConstructorWithValidConfig)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));
    EXPECT_NO_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorAsyncTest, DestructorStopsThreadDispatcher)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));
    auto connector = std::make_unique<IndexerConnectorAsyncImplTest>(config, nullptr, &mockHttpRequest);
    connector.reset();
    SUCCEED();
}

// Basic operations tests
TEST_F(IndexerConnectorAsyncTest, BulkIndexAddsToQueue)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndex("id2", "index2", R"({"field":"value"})");

    // Give some time for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    SUCCEED();
}

// Configuration tests
TEST_F(IndexerConnectorAsyncTest, ConstructorWithMultipleHosts)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));
    config["hosts"] = nlohmann::json::array({"localhost:9200", "localhost:9201", "localhost:9202"});
    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest);
        SUCCEED();
    });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithEmptyHostsThrows)
{
    config["hosts"] = nlohmann::json::array();
    EXPECT_ANY_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithMissingHostsThrows)
{
    config.erase("hosts");
    EXPECT_ANY_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithInvalidJSONThrows)
{
    nlohmann::json invalidConfig = "invalid";
    EXPECT_ANY_THROW({ IndexerConnectorAsyncImplTest connector(invalidConfig, nullptr, &mockHttpRequest); });
}

// SSL Configuration Tests
TEST_F(IndexerConnectorAsyncTest, ConstructorWithSSLConfigurationValid)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));
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

    EXPECT_NO_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });

    // Cleanup
    std::filesystem::remove(caFile);
    std::filesystem::remove(certFile);
    std::filesystem::remove(keyFile);
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithInvalidSSLPathsThrows)
{
    config["ssl"]["certificate_authorities"] = nlohmann::json::array({"/nonexistent/ca.pem"});
    config["ssl"]["certificate"] = "/nonexistent/cert.pem";
    config["ssl"]["key"] = "/nonexistent/key.pem";

    EXPECT_ANY_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

// HTTP error handling tests for async implementation
TEST_F(IndexerConnectorAsyncTest, HandleError413PayloadTooLarge)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorProcessedPromise;
    std::future<void> errorProcessedFuture = errorProcessedPromise.get_future();
    std::atomic<int> callCounter {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &errorProcessedPromise, &callCounter](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                callCounter++;
                this->callCount++;

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
                this->receivedData.push_back(data);

                if (callCounter == 1)
                {
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
                    if (callCounter == 3)
                    {
                        errorProcessedPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkPair connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add large data to force bulk processing
    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(200, 'a');
        connector.bulkIndex(id, "index1", dataValue);
    }

    // Wait for async processing to complete
    auto status = errorProcessedFuture.wait_for(std::chrono::seconds(15));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for error 413 handling";
    EXPECT_EQ(callCount, 3);
}

// HTTP error handling tests for async implementation
TEST_F(IndexerConnectorAsyncTest, HandleError413PayloadTooLargeDouble)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorProcessedPromise;
    std::future<void> errorProcessedFuture = errorProcessedPromise.get_future();
    std::atomic<int> callCounter {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &errorProcessedPromise, &callCounter](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                callCounter++;
                this->callCount++;

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
                this->receivedData.push_back(data);

                if (callCounter < 3)
                {
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
                    if (callCounter == 4)
                    {
                        errorProcessedPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkPair connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add large data to force bulk processing
    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(200, 'a');
        connector.bulkIndex(id, "index1", dataValue);
    }

    // Wait for async processing to complete
    auto status = errorProcessedFuture.wait_for(std::chrono::seconds(15));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for error 413 handling";
    EXPECT_EQ(callCount, 4);
}

// HTTP error handling tests for async implementation
TEST_F(IndexerConnectorAsyncTest, HandleError413PayloadTooLargeResetAfterSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorProcessedPromise;
    std::future<void> errorProcessedFuture = errorProcessedPromise.get_future();
    std::atomic<int> callCounter {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &errorProcessedPromise, &callCounter](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                callCounter++;
                this->callCount++;

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
                this->receivedData.push_back(data);

                if (callCounter == 1)
                {
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
                    if (callCounter == 8)
                    {
                        errorProcessedPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkPair connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add large data to force bulk processing
    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(200, 'a');
        connector.bulkIndex(id, "index1", dataValue);
    }

    for (int i = 0; i < 4; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(200, 'a');
        connector.bulkIndex(id, "index1", dataValue);
    }

    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(200, 'a');
        connector.bulkIndex(id, "index1", dataValue);
    }

    // Wait for async processing to complete
    auto status = errorProcessedFuture.wait_for(std::chrono::seconds(15));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for error 413 handling";
    EXPECT_EQ(callCount, 8);
}

TEST_F(IndexerConnectorAsyncTest, HandleError409VersionConflict)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> retryCompletedPromise;
    std::future<void> retryCompletedFuture = retryCompletedPromise.get_future();
    std::atomic<int> errorCallCount {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &retryCompletedPromise, &errorCallCount](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

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
                this->receivedData.push_back(data);

                if (errorCallCount.load() == 0)
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
                    retryCompletedPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to trigger processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for retry to complete
    auto status = retryCompletedFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for version conflict retry";
    EXPECT_GE(callCount, 2);
}

TEST_F(IndexerConnectorAsyncTest, HandleError429TooManyRequests)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> retryCompletedPromise;
    std::future<void> retryCompletedFuture = retryCompletedPromise.get_future();
    std::atomic<int> errorCallCount {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &retryCompletedPromise, &errorCallCount](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

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
                this->receivedData.push_back(data);

                if (errorCallCount.load() == 0)
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
                    retryCompletedPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to trigger processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for retry to complete
    auto status = retryCompletedFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for too many requests retry";
    EXPECT_GE(callCount, 2);
}

TEST_F(IndexerConnectorAsyncTest, HandleError500InternalServerError)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorHandledPromise;
    std::future<void> errorHandledFuture = errorHandledPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &errorHandledPromise](RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

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
                errorHandledPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to trigger processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for error to be handled
    auto status = errorHandledFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for internal server error handling";
    EXPECT_GT(callCount, 0);
}

// Test for generic error handling (non-specific status codes)
TEST_F(IndexerConnectorAsyncTest, HandleGenericError)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorHandledPromise;
    std::future<void> errorHandledFuture = errorHandledPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &errorHandledPromise](RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;

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
                this->receivedData.push_back(data);

                // Test with a generic error status code (502 Bad Gateway)
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Bad Gateway", 502);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Bad Gateway", 502);
                }
                errorHandledPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to trigger processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for error handling to complete
    auto status = errorHandledFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for generic error handling";
    EXPECT_GE(callCount, 1);
}

// Test for recursive splitting with multiple 413 errors
// TEST_F(IndexerConnectorAsyncTest, HandleError413RecursiveSplitting)
// {
//     auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
//     EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

//     std::promise<void> processingCompletedPromise;
//     std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();
//     std::atomic<int> callCounter {0};

//     EXPECT_CALL(mockHttpRequest, post(_, _, _))
//         .WillRepeatedly(Invoke(
//             [this, &processingCompletedPromise, &callCounter](
//                 RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
//             {
//                 callCounter++;
//                 this->callCount++;

//                 // Extract data from variant
//                 std::string data;
//                 if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string>>(requestParams).data;
//                 }
//                 else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
//                 }
//                 else
//                 {
//                     data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
//                 }
//                 this->receivedData.push_back(data);

//                 // Return 413 for first few calls, then success
//                 if (callCounter <= 3)
//                 {
//                     postParams.onError("Payload Too Large", 413);
//                 }
//                 else
//                 {
//                     postParams.onSuccess(R"({"took":1,"errors":false,"items":[]})");
//                     processingCompletedPromise.set_value();
//                 }
//             }));

//     IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

//     // Add multiple documents to create bulk operations that will be split recursively
//     for (int i = 0; i < 8; ++i)
//     {
//         std::string id = "recursive_test_" + std::to_string(i);
//         std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(200, 'x') +
//                            std::to_string(i) + R"("})";
//         connector.bulkIndex(id, "test_index", data);
//     }

//     // Wait for recursive processing to complete
//     auto status = processingCompletedFuture.wait_for(std::chrono::seconds(15));
//     EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for recursive splitting processing";
//     EXPECT_GE(callCounter.load(), 4); // At least 4 calls: initial + recursive splits
// }

// Test for HTTP_VERSION_CONFLICT (409) exception throwing
// TEST_F(IndexerConnectorAsyncTest, HandleError409VersionConflictThrowsException)
// {
//     auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
//     EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

//     std::atomic<int> callCounter {0};

//     EXPECT_CALL(mockHttpRequest, post(_, _, _))
//         .WillRepeatedly(Invoke(
//             [this, &callCounter](
//                 RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
//             {
//                 callCounter++;
//                 this->callCount++;

//                 // Extract data from variant
//                 std::string data;
//                 if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string>>(requestParams).data;
//                 }
//                 else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
//                 }
//                 else
//                 {
//                     data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
//                 }
//                 this->receivedData.push_back(data);

//                 // First call: return 413 to trigger recursive splitting
//                 if (callCounter == 1)
//                 {
//                     postParams.onError("Request Entity Too Large", HTTP_CONTENT_LENGTH);
//                     return;
//                 }

//                 // Second call: return 409 Version Conflict
//                 postParams.onError("Version Conflict", HTTP_VERSION_CONFLICT);
//             }));

//     auto connector = std::make_unique<IndexerConnectorAsyncImplSmallBulk>(
//         config, nullptr, &mockHttpRequest, std::move(mockSelector));

//     std::string testData = "{\"test\": \"data\"}\n{\"test2\": \"data2\"}";

//     // This should trigger recursive splitting on first 413, then process 409
//     connector->bulkIndex("test_id", "test_index", testData);

//     // Wait a bit for async processing
//     std::this_thread::sleep_for(std::chrono::milliseconds(100));

//     // Verify that the mock was called at least twice (413 + 409)
//     EXPECT_GE(callCounter.load(), 2) << "Mock should be called at least twice for 413 + 409 error handling";
// }

// // Test for HTTP_TOO_MANY_REQUESTS (429) exception throwing
// TEST_F(IndexerConnectorAsyncTest, HandleError429TooManyRequestsThrowsException)
// {
//     auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
//     EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

//     std::atomic<int> callCounter {0};

//     EXPECT_CALL(mockHttpRequest, post(_, _, _))
//         .WillRepeatedly(Invoke(
//             [this, &callCounter](
//                 RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
//             {
//                 callCounter++;
//                 this->callCount++;

//                 // Extract data from variant
//                 std::string data;
//                 if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string>>(requestParams).data;
//                 }
//                 else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
//                 {
//                     data = std::get<TRequestParameters<std::string_view>>(requestParams).data;
//                 }
//                 else
//                 {
//                     data = std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
//                 }
//                 this->receivedData.push_back(data);

//                 // First call: return 413 to trigger recursive splitting
//                 if (callCounter == 1)
//                 {
//                     postParams.onError("Request Entity Too Large", HTTP_CONTENT_LENGTH);
//                     return;
//                 }

//                 // Second call: return 429 Too Many Requests
//                 postParams.onError("Too Many Requests", HTTP_TOO_MANY_REQUESTS);
//             }));

//     auto connector = std::make_unique<IndexerConnectorAsyncImplSmallBulk>(
//         config, nullptr, &mockHttpRequest, std::move(mockSelector));

//     std::string testData = "{\"test\": \"data\"}\n{\"test2\": \"data2\"}";

//     // This should trigger recursive splitting on first 413, then process 429
//     connector->bulkIndex("test_id", "test_index", testData);

//     // Wait a bit for async processing
//     std::this_thread::sleep_for(std::chrono::milliseconds(100));

//     // Verify that the mock was called at least twice (413 + 429)
//     EXPECT_GE(callCounter.load(), 2) << "Mock should be called at least twice for 413 + 429 error handling";
// }

// Test async queue processing with small bulk size
TEST_F(IndexerConnectorAsyncTest, SmallBulkSizeTriggersAsyncProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add many small operations to force async bulk processing
    for (int i = 0; i < 30; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"operation":)" + std::to_string(i) + R"(})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Wait for async processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for async processing";
    EXPECT_GT(callCount, 0);
}

// Test async bulk processing validation
TEST_F(IndexerConnectorAsyncTest, VerifyAsyncDataProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add specific test data
    connector.bulkIndex("test_id_1", "test_index", R"({"test":"data1"})");
    connector.bulkIndex("test_id_2", "test_index", R"({"test":"data2"})");

    // Add more data to trigger processing
    for (int i = 0; i < 10; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for data processing";
    EXPECT_GT(callCount, 0);
    EXPECT_GT(receivedData.size(), 0);
}

// Test splitAndProcessBulk functionality for async implementation
TEST_F(IndexerConnectorAsyncTest, SplitAndProcessBulkWithAsyncDispatcher)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::vector<std::string> callSequenceData;
    std::promise<void> allProcessingCompletedPromise;
    std::future<void> allProcessingCompletedFuture = allProcessingCompletedPromise.get_future();
    std::atomic<int> callCounter {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&callSequenceData, &callCounter](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
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
            [&callSequenceData, &callCounter, &allProcessingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
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

                if (callCounter >= 3) // Initial + 2 splits
                {
                    allProcessingCompletedPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add multiple documents to create a bulk operation that will be split
    for (int i = 0; i < 8; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(150, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Wait for async processing to complete
    auto status = allProcessingCompletedFuture.wait_for(std::chrono::seconds(15));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for split and process bulk";
    EXPECT_GE(callCounter.load(), 3);
    EXPECT_GE(callSequenceData.size(), 3);
}

// Test processBulkChunk with recursive splitting for async implementation
TEST_F(IndexerConnectorAsyncTest, ProcessBulkChunkRecursiveSplittingAsync)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::atomic<int> callCounter {0};
    std::promise<void> recursiveProcessingCompletedPromise;
    std::future<void> recursiveProcessingCompletedFuture = recursiveProcessingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&callCounter](RequestParamsVariant /*requestParams*/,
                           auto postParams,
                           const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;
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
            [&callCounter, &recursiveProcessingCompletedPromise](RequestParamsVariant /*requestParams*/,
                                                                 auto postParams,
                                                                 const ConfigurationParameters& /*configParams*/)
            {
                callCounter++;
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
                if (callCounter >= 3)
                {
                    recursiveProcessingCompletedPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add documents that will trigger recursive splitting
    for (int i = 0; i < 6; ++i)
    {
        std::string id = "large_doc_" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"(","large_data":")" + std::string(200, 'x') +
                           std::to_string(i) + R"("})";
        connector.bulkIndex(id, "test_index", data);
    }

    // Wait for recursive processing to complete
    auto status = recursiveProcessingCompletedFuture.wait_for(std::chrono::seconds(15));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for recursive processing";
    EXPECT_GE(callCounter.load(), 3);
}

// Test stopping during async processing
TEST_F(IndexerConnectorAsyncTest, StoppingDuringAsyncProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::atomic<bool> processingStarted {false};
    std::atomic<bool> stoppedGracefully {true};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&processingStarted, &stoppedGracefully](RequestParamsVariant /*requestParams*/,
                                                     auto postParams,
                                                     const ConfigurationParameters& /*configParams*/)
            {
                processingStarted = true;
                try
                {
                    // Simulate processing time
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
                catch (const std::exception&)
                {
                    stoppedGracefully = false;
                }
            }));

    auto connector = std::make_unique<IndexerConnectorAsyncImplSmallBulk>(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add data to trigger async processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "test_id_" + std::to_string(i);
        connector->bulkIndex(id, "test_index", R"({"field":"value"})");
    }

    // Give time for processing to start
    auto startTime = std::chrono::steady_clock::now();
    while (!processingStarted && std::chrono::steady_clock::now() - startTime < std::chrono::seconds(5))
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Stop the connector (destructor should handle stopping gracefully)
    connector.reset();

    EXPECT_TRUE(stoppedGracefully) << "Connector should stop gracefully";
    SUCCEED();
}

// Test with custom queue ID
TEST_F(IndexerConnectorAsyncTest, ConstructorWithCustomQueueId)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string customQueueId = "test_queue_123";

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(
            config, nullptr, &mockHttpRequest, std::move(mockSelector), customQueueId);
        SUCCEED();
    });
}

// Test bulk data formatting in async processing
TEST_F(IndexerConnectorAsyncTest, AsyncBulkDataFormatValidation)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> formatValidationPromise;
    std::future<void> formatValidationFuture = formatValidationPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&capturedBulkData, &formatValidationPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& /*configParams*/)
            {
                // Extract data from variant
                if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
                {
                    capturedBulkData = std::get<TRequestParameters<std::string>>(requestParams).data;
                }
                else if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
                {
                    capturedBulkData = std::get<TRequestParameters<std::string_view>>(requestParams).data;
                }

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
                formatValidationPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulkNoFlushInterval connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add test documents
    connector.bulkIndex("doc1", "test_index", R"({"name":"document1"})");

    // Wait for async processing
    auto status = formatValidationFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for bulk format validation";

    // Validate bulk format
    EXPECT_FALSE(capturedBulkData.empty());

    // Check for proper index operations format
    EXPECT_TRUE(capturedBulkData.find(R"({"index":{"_index":"test_index","_id":"doc1"}})") != std::string::npos);

    // Check for document data
    EXPECT_TRUE(capturedBulkData.find(R"({"name":"document1"})") != std::string::npos);
}

// Test async processing with mixed operations
TEST_F(IndexerConnectorAsyncTest, AsyncMixedOperations)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> mixedProcessingPromise;
    std::future<void> mixedProcessingFuture = mixedProcessingPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &mixedProcessingPromise](RequestParamsVariant requestParams,
                                            const PostRequestParametersVariant& postParams,
                                            const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                mixedProcessingPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Mix different types of index operations
    connector.bulkIndex("index_id_1", "test_index", R"({"type":"index","data":"value1"})");
    connector.bulkIndex("index_id_2", "test_index", R"({"type":"index","data":"value2"})");
    connector.bulkIndex("", "test_index", R"({"type":"index","data":"no_id"})");

    // Add enough data to trigger processing
    for (int i = 0; i < 5; ++i)
    {
        std::string id = "bulk_" + std::to_string(i);
        std::string data = R"({"bulk_operation":)" + std::to_string(i) + R"(})";
        connector.bulkIndex(id, "bulk_index", data);
    }

    // Wait for async processing
    auto status = mixedProcessingFuture.wait_for(std::chrono::seconds(10));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for mixed operations processing";
    EXPECT_GT(callCount, 0);
}

// Test ThreadEventDispatcher queue persistence for async implementation
TEST_F(IndexerConnectorAsyncTest, AsyncQueuePersistence)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string customQueueId = "persistence_test_queue";

    // First connector instance - add some data
    {
        IndexerConnectorAsyncImplTest connector(
            config, nullptr, &mockHttpRequest, std::move(mockSelector), customQueueId);

        for (int i = 0; i < 3; ++i)
        {
            std::string id = "persistent_doc_" + std::to_string(i);
            std::string data = R"({"persistent":"data)" + std::to_string(i) + R"("})";
            connector.bulkIndex(id, "persistent_index", data);
        }

        // Give some time for queue operations
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    } // Connector destroyed here

    // Test passes if no exceptions during setup/teardown
    SUCCEED();
}

// Test async bulk processing validation
TEST_F(IndexerConnectorAsyncTest, VerifyAsyncDataWithErrorProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulWithErrorsPost(requestParams, postParams, configParams);
                processingCompletedPromise.set_value();
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < 5; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for data processing";
    EXPECT_GT(callCount, 0);
    EXPECT_GT(receivedData.size(), 0);
}
