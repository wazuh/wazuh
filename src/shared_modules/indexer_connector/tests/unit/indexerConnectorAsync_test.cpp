// SPDX-License-Identifier: GPL-2.0-only OR AGPL-3.0-or-later
#include "indexerConnectorAsyncImpl.hpp"
#include "mocks/MockHTTPRequest.hpp"
#include "mocks/MockServerSelector.hpp"
#include "scopedLogCapture.hpp"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <gmock/gmock.h>
#include <gtest/gtest.h>
#include <json.hpp>
#include <memory>
#include <mutex>
#include <sstream>
#include <string_view>
#include <thread>
#include <tuple>
#include <vector>

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
using IndexerConnectorAsyncImplSmallBulk = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 5, 5, 1>;
using IndexerConnectorAsyncImplRetryableBulk =
    IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 350, 1, 1>;
using IndexerConnectorAsyncImplSmallBulkPair = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 2, 5, 1>;
using IndexerConnectorAsyncImplSmallBulkNoFlushInterval =
    IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 5, 0, 1>;
// Large template bulk (25000) with a 5-second flush timer and a minimal (1s) retry delay.
using IndexerConnectorAsyncImplLargeBulk = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 25000, 5, 1>;
// One item per batch, and a batch is discarded after 2 consecutive HTTP 503 answers.
using IndexerConnectorAsyncImplSmallBulkTwoUnavailable =
    IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 5, 5, 1, 5, 15, 2>;
// Bulk threshold far above a few small documents and a 1-second flush timer: documents pushed back
// to back go out together in a single batch when the timer fires.
using IndexerConnectorAsyncImplMultiItemBulk =
    IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 100000, 1, 1>;
// 8192-byte bulk threshold (a 413 halves it to the 4096-byte minimum) and a 1-second flush timer.
using IndexerConnectorAsyncImplSplitBulk = IndexerConnectorAsyncImpl<MockServerSelector, MockHTTPRequest, 8192, 1, 1>;

namespace
{
    // Body of a mocked POST.
    std::string postedData(const RequestParamsVariant& requestParams)
    {
        if (std::holds_alternative<TRequestParameters<std::string>>(requestParams))
        {
            return std::get<TRequestParameters<std::string>>(requestParams).data;
        }
        if (std::holds_alternative<TRequestParameters<std::string_view>>(requestParams))
        {
            return std::string(std::get<TRequestParameters<std::string_view>>(requestParams).data);
        }
        return std::get<TRequestParameters<nlohmann::json>>(requestParams).data.dump();
    }

    // Answers a mocked POST with an HTTP error.
    void answerError(const PostRequestParametersVariant& postParams, const std::string& error, long statusCode)
    {
        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
        {
            std::get<TPostRequestParameters<const std::string&>>(postParams).onError(error, statusCode, "");
        }
        else
        {
            std::get<TPostRequestParameters<std::string&&>>(postParams).onError(error, statusCode, "");
        }
    }

    // Answers a mocked POST with a clean bulk response.
    void answerSuccess(const PostRequestParametersVariant& postParams)
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

    // Number of posted bodies containing `needle`.
    size_t countPostsWith(const std::vector<std::string>& posts, std::string_view needle)
    {
        return static_cast<size_t>(std::count_if(posts.begin(),
                                                 posts.end(),
                                                 [needle](const std::string& post)
                                                 { return post.find(needle) != std::string::npos; }));
    }

    // Answers a mocked POST with HTTP 200 and the given bulk response body.
    void answerSuccessWith(const PostRequestParametersVariant& postParams, const std::string& body)
    {
        if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
        {
            std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(body);
        }
        else
        {
            std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::string(body));
        }
    }

    // The WARN a bulk answer with documents an earlier attempt had already applied produces (03-diseno §4).
    constexpr std::string_view DEDUP_WARN_TAIL {"document(s) of a resent bulk (an earlier attempt was applied after a "
                                                "timeout or connection loss); they were not indexed twice."};

    std::string dedupWarn(size_t count)
    {
        return "Indexer already had " + std::to_string(count) + " " + std::string(DEDUP_WARN_TAIL);
    }

    // One item of a bulk response: `op` answered with `status`, failed with `errorType` unless it is empty.
    std::string bulkItem(std::string_view op, int status, std::string_view errorType = {})
    {
        std::string item =
            R"({")" + std::string(op) + R"(":{"_index":".ds-ds-000001","status":)" + std::to_string(status);
        if (!errorType.empty())
        {
            item += R"(,"error":{"type":")" + std::string(errorType) + R"(","reason":"reason of )" +
                    std::string(errorType) + R"("})";
        }
        item += "}}";
        return item;
    }

    // A create answered 409 version_conflict_engine_exception: the document was already indexed.
    std::string appliedConflictItem()
    {
        return bulkItem("create", 409, "version_conflict_engine_exception");
    }

    // An HTTP 200 bulk response reporting errors, with the given items.
    std::string bulkResponse(const std::vector<std::string>& items)
    {
        std::string response = R"({"took":1,"errors":true,"items":[)";
        for (size_t i = 0; i < items.size(); ++i)
        {
            response += (i == 0 ? "" : ",") + items[i];
        }
        response += "]}";
        return response;
    }

    constexpr auto CLEAN_BULK_RESPONSE {R"({"took":1,"errors":false,"items":[]})"};

    // NDJSON entry queued for a data-stream document with a caller-supplied id (`escapedId` already JSON-escaped).
    std::string dataStreamEntry(std::string_view index, std::string_view escapedId, std::string_view data)
    {
        return R"({"create":{"_index":")" + std::string(index) + R"(","_id":")" + std::string(escapedId) + R"("}})" +
               "\n" + std::string(data) + "\n";
    }

    // Records every mocked POST (body and URL, in arrival order) and how many were answered without throwing.
    class PostLog
    {
    public:
        size_t record(const RequestParamsVariant& requestParams)
        {
            std::string url;
            std::visit([&url](auto&& request) { url = request.url.url(); }, requestParams);
            size_t index = 0;
            {
                std::scoped_lock lock(m_mutex);
                m_bodies.push_back(postedData(requestParams));
                m_urls.push_back(std::move(url));
                index = m_bodies.size() - 1;
            }
            m_cv.notify_all();
            return index;
        }

        void markAnswered()
        {
            {
                std::scoped_lock lock(m_mutex);
                ++m_answered;
            }
            m_cv.notify_all();
        }

        // Waits (10 s at most) until `count` POSTs returned from their callback without throwing.
        bool waitAnswered(size_t count)
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, std::chrono::seconds(10), [this, count]() { return m_answered >= count; });
        }

        // Waits (10 s at most) until `predicate` holds for the bodies posted so far.
        bool waitUntil(const std::function<bool(const std::vector<std::string>&)>& predicate)
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, std::chrono::seconds(10), [this, &predicate]() { return predicate(m_bodies); });
        }

        std::vector<std::string> bodies() const
        {
            std::scoped_lock lock(m_mutex);
            return m_bodies;
        }

        std::vector<std::string> urls() const
        {
            std::scoped_lock lock(m_mutex);
            return m_urls;
        }

        size_t posts() const
        {
            std::scoped_lock lock(m_mutex);
            return m_bodies.size();
        }

    private:
        mutable std::mutex m_mutex;
        std::condition_variable m_cv;
        std::vector<std::string> m_bodies;
        std::vector<std::string> m_urls;
        size_t m_answered {0};
    };

    // Answers POST number `index` (0-based); may throw, as the connector's error callback does.
    using PostResponder = std::function<void(size_t index, const PostRequestParametersVariant& postParams)>;

    // Routes every POST of `mock` through `log` and `respond`. The body is recorded before the answer,
    // which may throw (retryable errors); the POST counts as answered only when the answer returns.
    void recordPosts(MockHTTPRequest& mock, PostLog& log, PostResponder respond)
    {
        EXPECT_CALL(mock, post(_, _, _))
            .WillRepeatedly(Invoke(
                [&log, respond = std::move(respond)](RequestParamsVariant requestParams,
                                                     PostRequestParametersVariant postParams,
                                                     ConfigurationParameters)
                {
                    const auto index = log.record(requestParams);
                    respond(index, postParams);
                    log.markAnswered();
                }));
    }

    // Records the pauses IndexerBulkQueue requests (PauseObserver hook).
    class PauseLog
    {
    public:
        IndexerBulkQueue::PauseObserver observer()
        {
            return [this](std::chrono::milliseconds, bool externalRequest)
            {
                {
                    std::scoped_lock lock(m_mutex);
                    m_external = m_external || externalRequest;
                }
                m_cv.notify_all();
            };
        }

        // Waits (10 s at most) for a pause requested through requestBackoff().
        bool waitExternal()
        {
            std::unique_lock lock(m_mutex);
            return m_cv.wait_for(lock, std::chrono::seconds(10), [this]() { return m_external; });
        }

    private:
        std::mutex m_mutex;
        std::condition_variable m_cv;
        bool m_external {false};
    };

    // Waits (10 s at most) until `logs` holds at least `count` WARNING lines containing `needle`. The
    // error logger runs on its own thread and has no completion hook, hence the bounded polling.
    bool waitForWarnings(const ScopedLogCapture& logs, std::string_view needle, size_t count)
    {
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (logs.countAtLevel(Log::LOGLEVEL_WARNING, needle) < count)
        {
            if (std::chrono::steady_clock::now() >= deadline)
            {
                return false;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return true;
    }
} // namespace

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

/*
 * THE property bulkDelete() exists for: a delete queued after an index of the SAME document is
 * applied after it, so the document ends up gone.
 *
 * Its caller is a whole-agent deletion that has to remove a document whose own index() may still be
 * sitting in this queue. Nothing else can give it that ordering: a delete through another connector
 * races this queue, and a `_delete_by_query` cannot see a document that has not been refreshed yet.
 *
 * The assertion runs over the concatenation of every payload sent, in send order, so it holds
 * whether the two actions share one bulk or land in consecutive ones.
 */
TEST_F(IndexerConnectorAsyncTest, BulkDeleteIsAppliedAfterAnIndexOfTheSameDocument)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    static constexpr auto INDEX_ACTION {R"({"index":{"_index":"wazuh-agent-config","_id":"007"}})"};
    static constexpr auto DELETE_ACTION {R"({"delete":{"_index":"wazuh-agent-config","_id":"007"}})"};

    std::promise<void> deleteSentPromise;
    auto deleteSentFuture = deleteSentPromise.get_future();
    std::atomic<bool> signalled {false};

    // Signalling from INSIDE the mock is what synchronizes the read of receivedData below: the
    // future's wait is the happens-after edge with the connector's own bulk thread.
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &deleteSentPromise, &signalled](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                if (!this->receivedData.empty() && this->receivedData.back().find(DELETE_ACTION) != std::string::npos &&
                    !signalled.exchange(true))
                {
                    deleteSentPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplRetryableBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("007", "wazuh-agent-config", R"({"field":"value"})");
    connector.bulkDelete("007", "wazuh-agent-config");

    ASSERT_EQ(deleteSentFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "the queued delete was never sent";

    std::string sent;
    for (const auto& payload : receivedData)
    {
        sent += payload;
    }

    const auto indexAt = sent.find(INDEX_ACTION);
    const auto deleteAt = sent.find(DELETE_ACTION);
    ASSERT_NE(indexAt, std::string::npos) << sent;
    ASSERT_NE(deleteAt, std::string::npos) << sent;
    EXPECT_LT(indexAt, deleteAt) << "the delete must reach the indexer AFTER the index it removes: " << sent;
}

/// An action without an `_id`, or without an index, would be a malformed bulk item that fails the
/// whole request -- so it is refused at the call site instead. There is no by-query form here.
TEST_F(IndexerConnectorAsyncTest, BulkDeleteRejectsAnEmptyIdOrIndex)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    EXPECT_THROW(connector.bulkDelete("", "wazuh-agent-config"), IndexerConnectorException);
    EXPECT_THROW(connector.bulkDelete("007", ""), IndexerConnectorException);
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

// Queue path configuration tests
TEST_F(IndexerConnectorAsyncTest, ConstructorWithCallerName)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_NO_THROW(
        { IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, nullptr, "test-instance"); });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithValidConfigNoDbPath)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_NO_THROW({ IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest); });
}

TEST_F(IndexerConnectorAsyncTest, MultipleInstances)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector1(config, nullptr, &mockHttpRequest);
        IndexerConnectorAsyncImplTest connector2(config, nullptr, &mockHttpRequest);
    });
}

// Queue size limit tests
TEST_F(IndexerConnectorAsyncTest, ConstructorWithMaxQueueSizeConfig)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    config["max_queue_bytes"] = 10000;

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest);
        EXPECT_EQ(connector.getQueueSize(), 0); // Initially empty
    });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithUnlimitedQueueSizeDefault)
{
    EXPECT_CALL(mockServerSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // No max_queue_bytes specified, should default to unlimited (0)
    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest);
        EXPECT_EQ(connector.getQueueSize(), 0); // Initially empty
    });
}

TEST_F(IndexerConnectorAsyncTest, QueueSizeLimitEnforcedWithSlowProcessing)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Set a small max queue size
    config["max_queue_bytes"] = 100;

    std::atomic<int> callCounter {0};
    std::promise<void> firstCallPromise;
    std::atomic<bool> firstCallDone {false};

    // Make HTTP requests process very slowly
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &callCounter, &firstCallPromise, &firstCallDone](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                callCounter++;

                // First call - wait a bit to let queue fill up
                if (callCounter == 1 && !firstCallDone.exchange(true))
                {
                    // Wait to allow queue to fill
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                    firstCallPromise.set_value();
                }

                this->simulateSuccessfulPost(requestParams, postParams, ConfigurationParameters {});
            }));

    // Use the small bulk implementation to trigger more frequent processing
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Push many documents quickly (more than max_queue_bytes)
    for (int i = 0; i < 20; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value"})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait a bit for the queue to process
    auto status = firstCallPromise.get_future().wait_for(std::chrono::seconds(3));
    EXPECT_EQ(status, std::future_status::ready);

    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // The queue should respect the limit while processing
    // Note: We can't check exact queue size due to timing, but we verify no crash
    SUCCEED();
}

TEST_F(IndexerConnectorAsyncTest, UnlimitedQueueSizeAllowsAllEvents)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Set unlimited queue size (0 or not specified)
    config["max_queue_bytes"] = 0;

    std::atomic<int> callCounter {0};
    std::promise<void> allProcessedPromise;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &callCounter, &allProcessedPromise](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                callCounter++;
                this->simulateSuccessfulPost(requestParams, postParams, ConfigurationParameters {});

                // After receiving multiple calls, signal completion
                if (callCounter >= 2)
                {
                    try
                    {
                        allProcessedPromise.set_value();
                    }
                    catch (...)
                    {
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Push many documents
    for (int i = 0; i < 15; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string data = R"({"field":"value"})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for processing
    auto status = allProcessedPromise.get_future().wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready);

    // Verify multiple batches were processed
    EXPECT_GE(callCounter, 2);
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
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
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

    // BulkMaxBytes counts bytes, not documents: size it so both docs (~10086 bytes) combine
    // into one POST, and the halved threshold (>= 4096) still splits them for the retry.
    config["bulk_max_bytes"] = 9000;
    IndexerConnectorAsyncImplSmallBulkPair connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add large data to force bulk processing
    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(5000, 'a');
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
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
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

    // BulkMaxBytes counts bytes, not documents: size it so both docs (~10086 bytes) combine
    // into one POST, and two 413-halvings still stay retry-worthy (>= 4096) before splitting.
    config["bulk_max_bytes"] = 18400;
    IndexerConnectorAsyncImplSmallBulkPair connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Add large data to force bulk processing
    for (int i = 0; i < 2; ++i)
    {
        std::string id = "id" + std::to_string(i);
        std::string dataValue(5000, 'a');
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
                            .onError("Payload Too Large", 413, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onError("Payload Too Large", 413, "");
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

// cluster_block_exception arrives as HTTP 200 with a per-item error: the bulk send itself succeeded,
// so IndexerBulkQueue has nothing to retry - the blocked item is discarded (logged + counted) and
// only a future send is paused via requestBackoff(). Unlike a retried failure (429, 503, transport),
// the blocked batch's data must never reappear in a later send.
TEST_F(IndexerConnectorAsyncTest, ClusterBlockExceptionItemsAreDiscardedNotRetried)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> firstCallPromise;
    std::future<void> firstCallFuture = firstCallPromise.get_future();
    std::promise<void> secondCallPromise;
    std::future<void> secondCallFuture = secondCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &firstCallPromise, &secondCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;

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

                if (currentCall == 1)
                {
                    std::string clusterBlockResponse = R"({
                        "took": 1,
                        "errors": true,
                        "items": [
                            {
                                "create": {
                                    "_index": ".ds-wazuh-events-v5-system-activity-000001",
                                    "status": 403,
                                    "error": {
                                        "type": "cluster_block_exception",
                                        "reason": "index [.ds-wazuh-events-v5-system-activity-000001] blocked by: [FORBIDDEN/8/index write (api)];"
                                    }
                                }
                            },
                            {"create": {"_index": "test-index", "status": 201}},
                            {"create": {"_index": "test-index", "status": 201}},
                            {"create": {"_index": "test-index", "status": 201}},
                            {"create": {"_index": "test-index", "status": 201}}
                        ]
                    })";

                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onSuccess(clusterBlockResponse);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(std::move(clusterBlockResponse));
                    }
                    firstCallPromise.set_value();
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
                    secondCallPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplRetryableBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < 5; ++i)
    {
        const std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndexDataStream("wazuh-events-v5-system-activity", data);
    }

    ASSERT_EQ(firstCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the initial cluster-blocked bulk";

    // Pushed only after the first (blocked) bulk was sent, so the next send is unambiguously a fresh
    // batch, not a race with the first one still being formed.
    connector.bulkIndexDataStream("wazuh-events-v5-system-activity", R"({"field":"value5"})");

    ASSERT_EQ(secondCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the next bulk after a cluster block";

    EXPECT_EQ(callCount, 2);
    ASSERT_GE(receivedData.size(), 2);

    // None of the first bulk's items - including the blocked one - should have been retried/reinserted.
    for (int i = 0; i < 5; ++i)
    {
        EXPECT_EQ(receivedData[1].find("value" + std::to_string(i)), std::string::npos)
            << "value" << i << " should not have been retried after a cluster_block_exception";
    }
    // Only the genuinely new data goes out in the next send.
    EXPECT_NE(receivedData[1].find("value5"), std::string::npos);
}

TEST(IndexerPrintableForLogTest, ControlBytesAreEscapedAndTheEntryTerminatorDropped)
{
    EXPECT_EQ(printableForLog("{\"create\":{}}\n{\"a\":\"b\"}\n"), R"({"create":{}}\n{"a":"b"})");
    EXPECT_EQ(printableForLog("x\r\t\x01\x7fy"), R"(x\r\t\x01\x7fy)");
    EXPECT_EQ(printableForLog(""), "");
}

TEST(IndexerPrintableForLogTest, LongTextIsCappedOnACharacterBoundary)
{
    const std::string text(LOGGED_TEXT_MAX + 100, 'a');
    EXPECT_EQ(printableForLog(text), std::string(LOGGED_TEXT_MAX, 'a') + "... (612 bytes)");

    const std::string exact(LOGGED_TEXT_MAX, 'b');
    EXPECT_EQ(printableForLog(exact), exact) << "nothing cut, nothing appended";

    // A two-byte character straddling the cap is dropped whole, never split.
    const std::string straddling = std::string(3, 'c') + "\xc3\xa9" + "dd";
    EXPECT_EQ(printableForLog(straddling, 4), "ccc... (7 bytes)");
}

// A per-item indexing error quotes the document, which is event content: the WARNING stays one
// escaped, bounded line instead of spilling the raw multi-line NDJSON entry into the log.
TEST_F(IndexerConnectorAsyncTest, ADocumentErrorIsLoggedOnOneBoundedLine)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                std::string response = R"({"took":1,"errors":true,"items":[{"create":{"status":400,"error":{)"
                                       R"("type":"mapper_parsing_exception","reason":"bad\nvalue"}}}]})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorAsyncImplRetryableBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndexDataStream("wazuh-events-v5-test", R"({"field":")" + std::string(2000, 'z') + R"(END"})");

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (!logs.contains("Error indexing document") && std::chrono::steady_clock::now() < deadline)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }

    ASSERT_TRUE(logs.containsAtLevel(
        Log::LOGLEVEL_WARNING, R"(Error indexing document (type mapper_parsing_exception - reason: 'bad\nvalue'))"));
    // WARNING only: the DEBUG2 "Bulk data" line deliberately carries the raw bulk.
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, R"(}\n{"field":"zzz)"), 1u)
        << "the action/document separator is escaped";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "\n"), 0u) << "no raw newline may reach the line";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "zEND"), 0u) << "the document is capped";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, " bytes)"), 1u);
}

// Verifies a cluster_block_exception makes IndexerBulkQueue pause before the next bulk, and that the
// pause is ordered before that next send. With this fixture's limits (RetryDelay = 1s, the default
// MaxRetryDelay = 15s, at least twice the base) nextDelay() is never below baseDelay: a first occurrence is
// uniform in [baseDelay, 1.5 * baseDelay] and later ones start at the previous exponential delay (see
// IndexerExponentialBackoffTest), so the requested delay has a deterministic floor. That the pause really
// sleeps is IndexerBulkQueueTest.ExternalBackoffPausesTheNextSendForTheRequestedDelay.
// The pause is observed through IndexerBulkQueue's PauseObserver hook, not the wall clock. Limit: this
// proves the pause was requested and ordered before the 3rd send, not that the wait_for actually slept.
TEST_F(IndexerConnectorAsyncTest, AppliesBackoffToNextBulkAfterClusterBlockException)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    static constexpr auto clusterBlockResponse = R"({
        "took": 1,
        "errors": true,
        "items": [
            {
                "create": {
                    "_index": ".ds-wazuh-events-v5-system-activity-000001",
                    "status": 403,
                    "error": {
                        "type": "cluster_block_exception",
                        "reason": "index [.ds-wazuh-events-v5-system-activity-000001] blocked by: [FORBIDDEN/8/index write (api)];"
                    }
                }
            }
        ]
    })";
    static constexpr auto cleanResponse = R"({"took":1,"errors":false,"items":[]})";

    // Pause history, written by the dispatcher thread through the observer. Declared before the connector so
    // they outlive its queue (the observer captures them by reference).
    struct PauseRecord
    {
        std::chrono::milliseconds delay;
        bool external;
        int posts;
    };
    std::vector<PauseRecord> pauses;
    std::mutex pausesMutex;
    std::condition_variable pausesCv;

    std::promise<void> firstCallPromise;
    std::future<void> firstCallFuture = firstCallPromise.get_future();
    std::promise<void> secondCallPromise;
    std::future<void> secondCallFuture = secondCallPromise.get_future();
    std::promise<void> thirdCallPromise;
    std::future<void> thirdCallFuture = thirdCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &firstCallPromise, &secondCallPromise, &thirdCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;

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

                const bool blocked = currentCall <= 2;
                const char* response = blocked ? clusterBlockResponse : cleanResponse;

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::string(response));
                }

                if (currentCall == 1)
                {
                    firstCallPromise.set_value();
                }
                else if (currentCall == 2)
                {
                    secondCallPromise.set_value();
                }
                else if (currentCall == 3)
                {
                    thirdCallPromise.set_value();
                }
            }));

    // Records each pause together with the number of posts received so far.
    IndexerBulkQueue::PauseObserver observer =
        [&pauses, &pausesMutex, &pausesCv, &callIndex](std::chrono::milliseconds delay, bool externalRequest)
    {
        {
            std::lock_guard<std::mutex> lock(pausesMutex);
            pauses.push_back({delay, externalRequest, callIndex.load()});
        }
        pausesCv.notify_all();
    };

    IndexerConnectorAsyncImplRetryableBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, observer);

    // 1. Send a first bulk.
    connector.bulkIndexDataStream("wazuh-events-v5-system-activity", R"({"field":"value0"})");

    // 2. It comes back with a cluster_block_exception (handled above).
    ASSERT_EQ(firstCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the first (blocked) bulk";

    // 3. Enqueue new, independent events right away - this becomes the second bulk, also reported as
    // blocked. Whether the first block's pause lands before or after it, an external pause must follow it.
    connector.bulkIndexDataStream("wazuh-events-v5-system-activity", R"({"field":"value1"})");

    ASSERT_EQ(secondCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the second (also blocked) bulk";

    // 4. Wait for the dispatcher to request an external pause after the second post. The block signal
    // arrives through the response logger, so it may only be picked up a dispatcher loop later.
    std::chrono::milliseconds pauseDelay {};
    {
        std::unique_lock<std::mutex> lock(pausesMutex);
        const auto findPause = [&pauses]()
        {
            return std::find_if(pauses.begin(),
                                pauses.end(),
                                [](const PauseRecord& record) { return record.external && record.posts >= 2; });
        };
        ASSERT_TRUE(pausesCv.wait_for(lock, std::chrono::seconds(10), [&]() { return findPause() != pauses.end(); }))
            << "Timeout waiting for the backoff pause after the second blocked bulk";
        pauseDelay = findPause()->delay;
    }

    // 5. The requested pause has the RetryDelay (1s) floor.
    EXPECT_GE(pauseDelay, std::chrono::milliseconds(1000))
        << "The backoff pause after a cluster block should be at least baseDelay (1000ms)";

    // Only now enqueue the third bulk: the pause above was ordered before it is sent.
    connector.bulkIndexDataStream("wazuh-events-v5-system-activity", R"({"field":"value2"})");

    ASSERT_EQ(thirdCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the third bulk";

    // 6. None of the earlier bulks' data was ever resent.
    EXPECT_EQ(callCount, 3);
    ASSERT_GE(receivedData.size(), 3);
    EXPECT_NE(receivedData[0].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[1].find("value0"), std::string::npos);
    EXPECT_NE(receivedData[1].find("value1"), std::string::npos);
    EXPECT_EQ(receivedData[2].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[2].find("value1"), std::string::npos);
    EXPECT_NE(receivedData[2].find("value2"), std::string::npos);
}

// A per-item 429 inside an HTTP 200 bulk response (the indexer shedding load, e.g. its parent circuit
// breaker tripping) backs off the next send and counts the rejected items in getDroppedEvents(), with one
// WARN per batch and no per-document WARN carrying the payload. The items are not resent.
TEST_F(IndexerConnectorAsyncTest, PerItem429BacksOffAndCountsDroppedItems)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    // Two items rejected with 429 (each exception type the indexer uses for it), one indexed.
    static constexpr auto throttledResponse = R"({
        "took": 1,
        "errors": true,
        "items": [
            {
                "create": {
                    "_index": ".ds-wazuh-events-v5-system-activity-000001",
                    "status": 429,
                    "error": {
                        "type": "circuit_breaking_exception",
                        "reason": "[parent] Data too large, data for [indices:data/write/bulk[s]] would be larger than the limit",
                        "bytes_wanted": 3285407922,
                        "bytes_limit": 3278268006,
                        "durability": "TRANSIENT"
                    }
                }
            },
            {
                "create": {
                    "_index": ".ds-wazuh-events-v5-system-activity-000001",
                    "status": 429,
                    "error": {
                        "type": "es_rejected_execution_exception",
                        "reason": "rejected execution of coordinating operation"
                    }
                }
            },
            {"create": {"_index": ".ds-wazuh-events-v5-system-activity-000001", "status": 201}}
        ]
    })";

    struct PauseRecord
    {
        bool external;
        int posts;
    };
    std::vector<PauseRecord> pauses;
    std::mutex pausesMutex;
    std::condition_variable pausesCv;

    std::promise<void> firstCallPromise;
    std::future<void> firstCallFuture = firstCallPromise.get_future();
    std::promise<void> secondCallPromise;
    std::future<void> secondCallFuture = secondCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &firstCallPromise, &secondCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall == 1)
                {
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(throttledResponse);
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams)
                            .onSuccess(std::string(throttledResponse));
                    }
                    firstCallPromise.set_value();
                }
                else
                {
                    answerSuccess(postParams);
                    if (currentCall == 2)
                    {
                        secondCallPromise.set_value();
                    }
                }
            }));

    IndexerBulkQueue::PauseObserver observer =
        [&pauses, &pausesMutex, &pausesCv, &callIndex](std::chrono::milliseconds, bool externalRequest)
    {
        {
            std::lock_guard<std::mutex> lock(pausesMutex);
            pauses.push_back({externalRequest, callIndex.load()});
        }
        pausesCv.notify_all();
    };

    IndexerConnectorAsyncImplMultiItemBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, observer);

    for (int i = 0; i < 3; ++i)
    {
        connector.bulkIndexDataStream("wazuh-events-v5-system-activity",
                                      R"({"field":"value)" + std::to_string(i) + R"("})");
    }

    ASSERT_EQ(firstCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the throttled bulk";
    ASSERT_NE(receivedData[0].find("value2"), std::string::npos) << "the three documents must go out in one bulk";

    // The response is classified on the logger thread: the pause request is the signal it was handled.
    // Nothing else is queued until the pause shows up: a clean answer to a next bulk sent before the
    // dispatcher picks the request up would reset it (reportHealthyResponse()), so the pause would never run.
    {
        std::unique_lock<std::mutex> lock(pausesMutex);
        ASSERT_TRUE(pausesCv.wait_for(lock,
                                      std::chrono::seconds(10),
                                      [&pauses]()
                                      {
                                          return std::any_of(pauses.begin(),
                                                             pauses.end(),
                                                             [](const PauseRecord& record)
                                                             { return record.external && record.posts >= 1; });
                                      }))
            << "Timeout waiting for the backoff pause after the throttled bulk";
    }

    connector.bulkIndexDataStream("wazuh-events-v5-system-activity", R"({"field":"value3"})");
    ASSERT_EQ(secondCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the bulk after the throttled one";

    EXPECT_EQ(connector.getDroppedEvents(), 2u) << "only the two 429 items are dropped";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Indexer rejected 2 document(s) in this batch with HTTP 429"),
              1u);
    EXPECT_FALSE(logs.contains("Error indexing document")) << "no per-document WARN with the payload";

    // The rejected items are not resent: the next bulk carries only the new document.
    ASSERT_GE(receivedData.size(), 2u);
    for (int i = 0; i < 3; ++i)
    {
        EXPECT_EQ(receivedData[1].find("value" + std::to_string(i)), std::string::npos);
    }
    EXPECT_NE(receivedData[1].find("value3"), std::string::npos);
}

// A 500 is not retried: each batch is sent once, discarded and counted.
TEST_F(IndexerConnectorAsyncTest, HandleError500InternalServerError)
{
    constexpr int BATCHES {3};

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastCallPromise;
    std::future<void> lastCallFuture = lastCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &lastCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                answerError(postParams, "Internal Server Error", 500);
                // Fulfilled once, after onError returned (the discard is already counted).
                if (currentCall == BATCHES)
                {
                    lastCallPromise.set_value();
                }
            }));

    // Small bulk threshold: each bulkIndex() below is sent as its own separate batch.
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < BATCHES; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "index1", R"({"field":"value)" + std::to_string(i) + R"("})");
    }

    ASSERT_EQ(lastCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the internal server error handling";

    EXPECT_EQ(callCount, BATCHES);
    for (int i = 0; i < BATCHES; ++i)
    {
        EXPECT_EQ(countPostsWith(receivedData, "value" + std::to_string(i)), 1u)
            << "value" << i << " must be sent exactly once (a 500 is not retried)";
    }
    EXPECT_EQ(connector.getDroppedEvents(), static_cast<uint64_t>(BATCHES));
}

// 502 (like 504) may mean OpenSearch actually processed the bulk but the response never made it
// back - retrying would risk indexing the same documents twice (data streams have no _id to dedupe
// on), so it must NOT be retried: the batch is discarded and counted. 503 (like 429 and connection
// errors) means the request was rejected before processing, so it IS retried (up to a limit).
TEST_F(IndexerConnectorAsyncTest, HandleBadGatewayIsNotRetried)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> secondCallPromise;
    std::future<void> secondCallFuture = secondCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &secondCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;

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

                if (currentCall == 1)
                {
                    if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                    {
                        std::get<TPostRequestParameters<const std::string&>>(postParams)
                            .onError("Bad Gateway", 502, "");
                    }
                    else
                    {
                        std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Bad Gateway", 502, "");
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
                    secondCallPromise.set_value();
                }
            }));

    // Small bulk threshold: each bulkIndex() below is sent as its own separate batch.
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("id0", "index1", R"({"field":"value0"})");
    connector.bulkIndex("id1", "index1", R"({"field":"value1"})");

    ASSERT_EQ(secondCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the second (unrelated) bulk";

    EXPECT_EQ(callCount, 2);
    ASSERT_GE(receivedData.size(), 2);
    EXPECT_NE(receivedData[0].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[1].find("value0"), std::string::npos) << "value0 should not have been retried after a 502";
    EXPECT_NE(receivedData[1].find("value1"), std::string::npos);
    EXPECT_EQ(connector.getDroppedEvents(), 1u) << "the discarded 502 batch must be counted";
}

// 504, like 502, is discarded (and counted), never retried.
TEST_F(IndexerConnectorAsyncTest, GatewayTimeoutIsNotRetried)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> secondCallPromise;
    std::future<void> secondCallFuture = secondCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &secondCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall == 1)
                {
                    answerError(postParams, "Gateway Timeout", 504);
                }
                else
                {
                    answerSuccess(postParams);
                    if (currentCall == 2)
                    {
                        secondCallPromise.set_value();
                    }
                }
            }));

    // Small bulk threshold: each bulkIndex() below is sent as its own separate batch.
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("id0", "index1", R"({"field":"value0"})");
    connector.bulkIndex("id1", "index1", R"({"field":"value1"})");

    ASSERT_EQ(secondCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the second (unrelated) bulk";

    EXPECT_EQ(callCount, 2);
    ASSERT_GE(receivedData.size(), 2);
    EXPECT_NE(receivedData[0].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[1].find("value0"), std::string::npos) << "value0 should not have been retried after a 504";
    EXPECT_NE(receivedData[1].find("value1"), std::string::npos);
    EXPECT_EQ(connector.getDroppedEvents(), 1u) << "the discarded 504 batch must be counted";
}

// A 503 means the indexer rejected the bulk before processing it: the same batch is resent and
// nothing is dropped once the indexer answers 200.
TEST_F(IndexerConnectorAsyncTest, ServiceUnavailableIsRetriedUntilSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> successPromise;
    std::future<void> successFuture = successPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &successPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall == 1)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else
                {
                    answerSuccess(postParams);
                    if (currentCall == 2)
                    {
                        successPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("id0", "index1", R"({"field":"value0"})");

    ASSERT_EQ(successFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the 503 batch to be retried";

    EXPECT_EQ(callCount, 2);
    ASSERT_EQ(receivedData.size(), 2);
    EXPECT_NE(receivedData[0].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[1], receivedData[0]) << "the retry must resend the same body";
    EXPECT_EQ(connector.getDroppedEvents(), 0u);
}

// After MaxUnavailableRetries (2 here) consecutive 503 answers the head batch is discarded and
// counted, and the next batch goes out.
TEST_F(IndexerConnectorAsyncTest, ServiceUnavailableIsDiscardedAfterRetryLimit)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> otherBatchPromise;
    std::future<void> otherBatchFuture = otherBatchPromise.get_future();
    std::atomic<bool> otherBatchSent {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &otherBatchPromise, &otherBatchSent](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const auto data = postedData(requestParams);
                this->receivedData.push_back(data);

                if (data.find("valueA") != std::string::npos)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else
                {
                    answerSuccess(postParams);
                    if (!otherBatchSent.exchange(true))
                    {
                        otherBatchPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("idA", "index1", R"({"field":"valueA"})");
    connector.bulkIndex("idB", "index1", R"({"field":"valueB"})");

    ASSERT_EQ(otherBatchFuture.wait_for(std::chrono::seconds(15)), std::future_status::ready)
        << "Timeout waiting for the batch after the discarded one";

    EXPECT_EQ(callCount, 3);
    EXPECT_EQ(countPostsWith(receivedData, "valueA"), 2u) << "the 503 batch must be sent exactly twice";
    EXPECT_EQ(countPostsWith(receivedData, "valueB"), 1u);
    ASSERT_FALSE(receivedData.empty());
    EXPECT_NE(receivedData.back().find("valueB"), std::string::npos) << "valueA must not be sent after valueB";
    EXPECT_EQ(connector.getDroppedEvents(), 1u);
}

// Any non-503 HTTP outcome resets the consecutive-503 counter: 503, 200, 503, 200 with a limit of 2
// discards nothing.
TEST_F(IndexerConnectorAsyncTest, ServiceUnavailableCounterResetsOnOtherOutcome)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> fourthCallPromise;
    std::future<void> fourthCallFuture = fourthCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &fourthCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall == 1 || currentCall == 3)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else
                {
                    answerSuccess(postParams);
                    if (currentCall == 4)
                    {
                        fourthCallPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("id0", "index1", R"({"field":"value0"})");
    connector.bulkIndex("id1", "index1", R"({"field":"value1"})");

    ASSERT_EQ(fourthCallFuture.wait_for(std::chrono::seconds(15)), std::future_status::ready)
        << "Timeout waiting for the fourth POST (the second batch was discarded?)";

    EXPECT_EQ(callCount, 4);
    ASSERT_EQ(receivedData.size(), 4);
    EXPECT_NE(receivedData[0].find("value0"), std::string::npos);
    EXPECT_EQ(receivedData[1], receivedData[0]);
    EXPECT_NE(receivedData[2].find("value1"), std::string::npos);
    EXPECT_EQ(receivedData[3], receivedData[2]);
    EXPECT_EQ(connector.getDroppedEvents(), 0u);
}

namespace
{
    // Sends 4 one-item batches: the first is answered 503 twice (retries exhausted with the
    // TwoUnavailable alias), the other three are answered 500. Returns once the 5th POST's
    // onError has returned.
    template<typename TConnector>
    void runRepeatedDiscards(TConnector& connector, std::atomic<int>& callIndex, std::future<void>& lastCallFuture)
    {
        for (int i = 0; i < 4; ++i)
        {
            connector.bulkIndex("id" + std::to_string(i), "index1", R"({"field":"value)" + std::to_string(i) + R"("})");
        }

        ASSERT_EQ(lastCallFuture.wait_for(std::chrono::seconds(15)), std::future_status::ready)
            << "Timeout waiting for the fifth POST";
        EXPECT_EQ(callIndex.load(), 5);
    }

    auto repeatedDiscardsPost(std::atomic<int>& callIndex, std::promise<void>& lastCallPromise)
    {
        return [&callIndex, &lastCallPromise](RequestParamsVariant, auto postParams, ConfigurationParameters)
        {
            const int currentCall = ++callIndex;
            if (currentCall <= 2)
            {
                answerError(postParams, "Service Unavailable", 503);
            }
            else
            {
                answerError(postParams, "Internal Server Error", 500);
                if (currentCall == 5)
                {
                    lastCallPromise.set_value();
                }
            }
        };
    }
} // namespace

// Within the summary interval, a run of discards logs a single WARN (the first one); every discard
// is still logged at DEBUG1 and counted.
TEST_F(IndexerConnectorAsyncTest, RepeatedDiscardsLogOneWarning)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastCallPromise;
    std::future<void> lastCallFuture = lastCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(repeatedDiscardsPost(callIndex, lastCallPromise)));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    runRepeatedDiscards(connector, callIndex, lastCallFuture);

    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING,
                                "Discarding 1 event(s): bulk request answered HTTP 503 on 2 consecutive attempts"),
              1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discarding"), 1u) << "no WARN per discarded batch";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue"), 0u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_DEBUG, "Bulk request discarded: HTTP"), 4u);
    EXPECT_EQ(connector.getDroppedEvents(), 4u);
}

// With a 0-second summary interval every discard after the first one is summarized, and the
// per-cause counters restart after each summary.
TEST_F(IndexerConnectorAsyncTest, RepeatedDiscardsSummaryEveryInterval)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastCallPromise;
    std::future<void> lastCallFuture = lastCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(repeatedDiscardsPost(callIndex, lastCallPromise)));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, {}, 0);

    runRepeatedDiscards(connector, callIndex, lastCallFuture);

    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discarding"), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue"), 3u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue: 1 event(s) in 1 batch(es)"), 3u);
    EXPECT_EQ(
        logs.countAtLevel(Log::LOGLEVEL_WARNING, "(HTTP 500: 1, 502: 0, 504: 0, 503 retries exhausted: 0, other: 0)."),
        3u)
        << "each summary (the last one included) must report only the discards since the previous one";
    EXPECT_EQ(connector.getDroppedEvents(), 4u);
}

// A discarded batch counts every event it holds, not one per batch: 4 documents sent in a single
// _bulk answered 500 add 4 to getDroppedEvents() and the WARN reports 4 events.
TEST_F(IndexerConnectorAsyncTest, DiscardCountsEveryEventOfTheBatch)
{
    constexpr int EVENTS {4};

    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> firstCallPromise;
    std::future<void> firstCallFuture = firstCallPromise.get_future();
    std::atomic<int> callIndex {0};
    // Written only by the first POST, read only after its promise: no race even if the flush
    // timer split the documents into a second POST.
    std::string firstPost;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&firstCallPromise, &callIndex, &firstPost](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                const int currentCall = ++callIndex;
                if (currentCall == 1)
                {
                    firstPost = postedData(requestParams);
                }

                answerError(postParams, "Internal Server Error", 500);
                // Fulfilled once, after onError returned (the discard is already counted).
                if (currentCall == 1)
                {
                    firstCallPromise.set_value();
                }
            }));

    IndexerConnectorAsyncImplMultiItemBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (int i = 0; i < EVENTS; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "index1", R"({"field":"value)" + std::to_string(i) + R"("})");
    }

    ASSERT_EQ(firstCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the bulk request";

    for (int i = 0; i < EVENTS; ++i)
    {
        ASSERT_NE(firstPost.find("value" + std::to_string(i)), std::string::npos)
            << "value" << i << " missing from the first POST: the flush timer split the batch, the test "
            << "premise (one POST with all " << EVENTS << " events) does not hold";
    }
    EXPECT_EQ(callIndex.load(), 1) << "all the events must go out in a single POST";
    EXPECT_EQ(connector.getDroppedEvents(), static_cast<uint64_t>(EVENTS));
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discarding 4 event(s): bulk request answered HTTP 500"), 1u);
}

// A successful response after the summary interval with nothing pending closes the discard window:
// the next discard logs a fresh WARN instead of a summary.
TEST_F(IndexerConnectorAsyncTest, DiscardWindowClosesAfterAQuietInterval)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastCallPromise;
    std::future<void> lastCallFuture = lastCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [&lastCallPromise, &callIndex](RequestParamsVariant, auto postParams, ConfigurationParameters)
            {
                const int currentCall = ++callIndex;
                if (currentCall == 2)
                {
                    answerSuccess(postParams);
                }
                else
                {
                    answerError(postParams, "Internal Server Error", 500);
                    // Fulfilled once, after onError returned.
                    if (currentCall == 3)
                    {
                        lastCallPromise.set_value();
                    }
                }
            }));

    // Small bulk threshold (one document per batch) and a 0-second summary interval.
    IndexerConnectorAsyncImplSmallBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, {}, 0);

    for (int i = 0; i < 3; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "index1", R"({"field":"value)" + std::to_string(i) + R"("})");
    }

    ASSERT_EQ(lastCallFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the third POST";

    EXPECT_EQ(callIndex.load(), 3);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discarding"), 2u)
        << "the 200 in between must close the window, so the second 500 opens a new one";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue"), 0u);
    EXPECT_EQ(connector.getDroppedEvents(), 2u);
}

// A 429 (like 409, 413 and transport failures) also resets the consecutive-503 counter: 503, 429,
// 503, 200 with a limit of 2 resends the same batch until the 200 and discards nothing.
TEST_F(IndexerConnectorAsyncTest, ServiceUnavailableCounterResetsOnTooManyRequests)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> fourthCallPromise;
    std::future<void> fourthCallFuture = fourthCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &fourthCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall == 1 || currentCall == 3)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else if (currentCall == 2)
                {
                    answerError(postParams, "Too Many Requests", 429);
                }
                else
                {
                    answerSuccess(postParams);
                    if (currentCall == 4)
                    {
                        fourthCallPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("id0", "index1", R"({"field":"value0"})");

    // Three backoff pauses (1-1.5 s, 1-2 s, 2-4 s) before the fourth POST.
    ASSERT_EQ(fourthCallFuture.wait_for(std::chrono::seconds(20)), std::future_status::ready)
        << "Timeout waiting for the fourth POST (the batch was discarded on the third, the 429 did not reset the "
           "503 counter?)";

    EXPECT_EQ(callCount, 4);
    ASSERT_EQ(receivedData.size(), 4);
    for (size_t i = 0; i < receivedData.size(); ++i)
    {
        EXPECT_NE(receivedData[i].find("value0"), std::string::npos) << "POST " << i + 1;
    }
    EXPECT_EQ(connector.getDroppedEvents(), 0u);
}

// The consecutive-503 counter restarts after a batch is discarded: the next batch that keeps getting
// 503 is sent MaxUnavailableRetries times too, not discarded at its first 503.
TEST_F(IndexerConnectorAsyncTest, ConsecutiveExhaustedBatchesEachGetTheFullRetryLimit)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastBatchPromise;
    std::future<void> lastBatchFuture = lastBatchPromise.get_future();
    std::atomic<bool> lastBatchSent {false};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &lastBatchPromise, &lastBatchSent](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                this->callCount++;
                const auto data = postedData(requestParams);
                this->receivedData.push_back(data);

                if (data.find("valueC") == std::string::npos)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else
                {
                    answerSuccess(postParams);
                    if (!lastBatchSent.exchange(true))
                    {
                        lastBatchPromise.set_value();
                    }
                }
            }));

    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector));

    connector.bulkIndex("idA", "index1", R"({"field":"valueA"})");
    connector.bulkIndex("idB", "index1", R"({"field":"valueB"})");
    connector.bulkIndex("idC", "index1", R"({"field":"valueC"})");

    // Two backoff pauses: 1-1.5 s before A's retry and 2-4 s before B's (the backoff is not reset
    // by A's discard).
    ASSERT_EQ(lastBatchFuture.wait_for(std::chrono::seconds(20)), std::future_status::ready)
        << "Timeout waiting for the batch after the two discarded ones";

    EXPECT_EQ(callCount, 5);
    EXPECT_EQ(countPostsWith(receivedData, "valueA"), 2u) << "A must be sent exactly MaxUnavailableRetries times";
    EXPECT_EQ(countPostsWith(receivedData, "valueB"), 2u)
        << "B must get the full retry limit too, not inherit A's consecutive 503 count";
    EXPECT_EQ(countPostsWith(receivedData, "valueC"), 1u);
    EXPECT_EQ(connector.getDroppedEvents(), 2u);
}

// Each summary attributes the discards since the previous one to their cause: 503 retries
// exhausted, 502, 504 and any other status each land in their own bucket.
TEST_F(IndexerConnectorAsyncTest, DiscardSummaryCountsEachCause)
{
    // POSTs: 1-2 batch 0 (503 x2, exhausted: opens the window), 3-4 batch 1 (503 x2, exhausted),
    // 5 batch 2 (502), 6 batch 3 (504), 7 batch 4 (400), 8 batch 5 (200).
    constexpr int LAST_CALL {8};

    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> lastCallPromise;
    std::future<void> lastCallFuture = lastCallPromise.get_future();
    std::atomic<int> callIndex {0};

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillRepeatedly(Invoke(
            [this, &lastCallPromise, &callIndex](
                RequestParamsVariant requestParams, auto postParams, ConfigurationParameters)
            {
                const int currentCall = ++callIndex;
                this->receivedData.push_back(postedData(requestParams));

                if (currentCall <= 4)
                {
                    answerError(postParams, "Service Unavailable", 503);
                }
                else if (currentCall == 5)
                {
                    answerError(postParams, "Bad Gateway", 502);
                }
                else if (currentCall == 6)
                {
                    answerError(postParams, "Gateway Timeout", 504);
                }
                else if (currentCall == 7)
                {
                    answerError(postParams, "Bad Request", 400);
                }
                else
                {
                    answerSuccess(postParams);
                    // Fulfilled once, after onSuccess returned.
                    if (currentCall == LAST_CALL)
                    {
                        lastCallPromise.set_value();
                    }
                }
            }));

    // One document per batch, 2 consecutive 503 exhaust a batch, 0-second summary interval.
    IndexerConnectorAsyncImplSmallBulkTwoUnavailable connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, {}, 0);

    for (int i = 0; i < 6; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "index1", R"({"field":"value)" + std::to_string(i) + R"("})");
    }

    // Two backoff pauses (1-1.5 s and 2-4 s) before the second batch is discarded.
    ASSERT_EQ(lastCallFuture.wait_for(std::chrono::seconds(20)), std::future_status::ready)
        << "Timeout waiting for the eighth POST";

    EXPECT_EQ(callIndex.load(), LAST_CALL);
    ASSERT_EQ(receivedData.size(), static_cast<size_t>(LAST_CALL));
    EXPECT_EQ(countPostsWith(receivedData, "value0"), 2u);
    EXPECT_EQ(countPostsWith(receivedData, "value1"), 2u);
    for (int i = 2; i < 6; ++i)
    {
        EXPECT_EQ(countPostsWith(receivedData, "value" + std::to_string(i)), 1u) << "value" << i;
    }

    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING,
                                "Discarding 1 event(s): bulk request answered HTTP 503 on 2 consecutive attempts"),
              1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discarding"), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue: 1 event(s) in 1 batch(es)"), 4u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Discards continue"), 4u);
    EXPECT_EQ(
        logs.countAtLevel(Log::LOGLEVEL_WARNING, "(HTTP 500: 0, 502: 0, 504: 0, 503 retries exhausted: 1, other: 0)."),
        1u)
        << "batch 1 (503 retries exhausted)";
    EXPECT_EQ(
        logs.countAtLevel(Log::LOGLEVEL_WARNING, "(HTTP 500: 0, 502: 1, 504: 0, 503 retries exhausted: 0, other: 0)."),
        1u)
        << "batch 2 (502)";
    EXPECT_EQ(
        logs.countAtLevel(Log::LOGLEVEL_WARNING, "(HTTP 500: 0, 502: 0, 504: 1, 503 retries exhausted: 0, other: 0)."),
        1u)
        << "batch 3 (504)";
    EXPECT_EQ(
        logs.countAtLevel(Log::LOGLEVEL_WARNING, "(HTTP 500: 0, 502: 0, 504: 0, 503 retries exhausted: 0, other: 1)."),
        1u)
        << "batch 4 (400)";
    EXPECT_EQ(connector.getDroppedEvents(), 5u);
}

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
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
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
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Payload Too Large", 413, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Payload Too Large", 413, "");
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

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
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

    // First connector instance - add some data
    {
        IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

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

// Test error processing with "create" operation type (data streams)
TEST_F(IndexerConnectorAsyncTest, ErrorProcessingWithCreateOperation)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate response with "create" operation error (1 error + 4 success items)
                std::string errorResponse = R"({
                    "took": 1,
                    "errors": true,
                    "items": [
                        {
                            "create": {
                                "_index": ".ds-wazuh-events-v5-security-000001",
                                "_id": "test_id",
                                "status": 400,
                                "error": {
                                    "type": "mapper_parsing_exception",
                                    "reason": "failed to parse"
                                }
                            }
                        },
                        {"index": {"_index": "test-index", "_id": "filler1", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler2", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler3", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler4", "status": 201}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(errorResponse));
                }
                processingCompletedPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~344 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 300;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Send only 1 document to match the 1 item in response
    connector.bulkIndex("doc0", "test-data-stream", R"({"field":"value0"})");

    // Add fillers to trigger bulk processing (total 5 to reach bulk size)
    for (int i = 1; i < 5; ++i)
    {
        connector.bulkIndex("filler" + std::to_string(i), "test-index", R"({"filler":"data"})");
    }

    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for create operation error processing";
}

// Test error processing with caused_by information
TEST_F(IndexerConnectorAsyncTest, ErrorProcessingWithCausedBy)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate response with caused_by in error (1 error + 4 success items)
                std::string errorResponse = R"({
                    "took": 1,
                    "errors": true,
                    "items": [
                        {
                            "create": {
                                "_index": "test_index",
                                "_id": "test_doc",
                                "status": 400,
                                "error": {
                                    "type": "mapper_parsing_exception",
                                    "reason": "failed to parse",
                                    "caused_by": {
                                        "type": "illegal_argument_exception",
                                        "reason": "documents must contain a single-valued timestamp field '@timestamp' of date type"
                                    }
                                }
                            }
                        },
                        {"index": {"_index": "test-index", "_id": "filler1", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler2", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler3", "status": 201}},
                        {"index": {"_index": "test-index", "_id": "filler4", "status": 201}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(errorResponse));
                }
                processingCompletedPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~342 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 300;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Send only 1 document to match the 1 item in response
    connector.bulkIndex("test_doc", "test_index", R"({"field":"value0"})");

    // Add fillers to trigger bulk processing (total 5 to reach bulk size)
    for (int i = 1; i < 5; ++i)
    {
        connector.bulkIndex("filler" + std::to_string(i), "test-index", R"({"filler":"data"})");
    }

    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for caused_by error processing";
}

// Test error processing with caused_by having only type (no reason)
TEST_F(IndexerConnectorAsyncTest, ErrorProcessingWithCausedByTypeOnly)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate response with caused_by having only type field (1 error + 4 success items)
                std::string errorResponse = R"({
                    "took": 1,
                    "errors": true,
                    "items": [
                        {
                            "index": {
                                "_index": "test_index",
                                "_id": "test_doc",
                                "status": 400,
                                "error": {
                                    "type": "mapper_parsing_exception",
                                    "reason": "failed to parse",
                                    "caused_by": {
                                        "type": "illegal_argument_exception"
                                    }
                                }
                            }
                        },
                        {"index": {"_index": "test_index", "_id": "filler0", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler1", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler2", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler3", "status": 201}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(errorResponse));
                }
                processingCompletedPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~342 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 300;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Send 1 document to match the 1 item in response
    connector.bulkIndex("test_doc", "test_index", R"({"field":"value1"})");

    // Add fillers to trigger bulk processing
    for (int i = 0; i < 4; ++i)
    {
        connector.bulkIndex("filler" + std::to_string(i), "test_index", R"({"filler":"data"})");
    }

    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for caused_by type-only error processing";
}

// Test error processing with caused_by having only reason (no type)
TEST_F(IndexerConnectorAsyncTest, ErrorProcessingWithCausedByReasonOnly)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingCompletedPromise;
    std::future<void> processingCompletedFuture = processingCompletedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [&processingCompletedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate response with caused_by having only reason field (1 error + 4 success items)
                std::string errorResponse = R"({
                    "took": 1,
                    "errors": true,
                    "items": [
                        {
                            "index": {
                                "_index": "test_index",
                                "_id": "test_doc",
                                "status": 400,
                                "error": {
                                    "type": "mapper_parsing_exception",
                                    "reason": "failed to parse",
                                    "caused_by": {
                                        "reason": "missing required field"
                                    }
                                }
                            }
                        },
                        {"index": {"_index": "test_index", "_id": "filler0", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler1", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler2", "status": 201}},
                        {"index": {"_index": "test_index", "_id": "filler3", "status": 201}}
                    ]
                })";

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(errorResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(errorResponse));
                }
                processingCompletedPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~342 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 300;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Send 1 document to match the 1 item in response
    connector.bulkIndex("test_doc", "test_index", R"({"field":"value1"})");

    // Add fillers to trigger bulk processing
    for (int i = 0; i < 4; ++i)
    {
        connector.bulkIndex("filler" + std::to_string(i), "test_index", R"({"filler":"data"})");
    }

    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for caused_by reason-only error processing";
}

// Test version handling in bulk index operations
TEST_F(IndexerConnectorAsyncTest, BulkIndexWithVersionHandling)
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

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~358 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 320;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test with version
    connector.bulkIndex("doc1", "index1", R"({"field":"value1"})", "12345");
    // Test without version
    connector.bulkIndex("doc2", "index1", R"({"field":"value2"})");

    // Add more data to force bulk processing in async connector (stay within bulk size limit of 5)
    for (int i = 0; i < 3; ++i)
    {
        std::string id = "doc" + std::to_string(i + 3);
        std::string data = R"({"field":"value)" + std::to_string(i + 3) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

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

// Test escaping special characters in document IDs for async bulkIndex
TEST_F(IndexerConnectorAsyncTest, BulkIndexEscapesSpecialCharactersInId)
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

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~386 bytes total, incl. escaping) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 350;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test various special characters that need escaping
    connector.bulkIndex("001_dum\\amy", "test_index", R"({"group":"dum\\amy"})");
    connector.bulkIndex("002_tab\tchar", "test_index", R"({"name":"tab\tchar"})");
    connector.bulkIndex("003_quote\"char", "test_index", R"({"name":"quote\"char"})");
    connector.bulkIndex("004_newline\nchar", "test_index", R"({"name":"newline\nchar"})");
    connector.bulkIndex("005_normal", "test_index", R"({"name":"normal"})");

    // Wait for processing to complete
    auto status = processingCompletedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for async escape test processing";

    // Verify backslash is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"001_dum\\amy")"));

    // Verify tab is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"002_tab\tchar")"));

    // Verify quote is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"003_quote\"char")"));

    // Verify newline is properly escaped in ID
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"004_newline\nchar")"));

    // Verify normal ID is passed through unchanged
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"("_id":"005_normal")"));

    // Verify the bulk data is valid (no JSON parse errors would occur)
    EXPECT_FALSE(capturedBulkData.empty());
}

// Test error handling for missing version fields
TEST_F(IndexerConnectorAsyncTest, ErrorHandlingForInvalidInput)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Test with empty index - should throw exception
    EXPECT_THROW(connector.bulkIndex("doc1", "", R"({"field":"value"})", "123"), IndexerConnectorException);

    // Test with empty data - should not throw but log warning
    EXPECT_NO_THROW(connector.bulkIndex("doc2", "index1", "", "456"));
}

// Test version conflict handling
TEST_F(IndexerConnectorAsyncTest, VersionConflictHandling)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> errorProcessedPromise;
    std::future<void> errorProcessedFuture = errorProcessedPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(2) // Initial request + retry
        .WillOnce(Invoke(
            [&errorProcessedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate version conflict (409)
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams)
                        .onError("Version conflict", 409, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Version conflict", 409, "");
                }
            }))
        .WillOnce(Invoke(
            [&errorProcessedPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                // Simulate successful retry
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess("{}");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess("{}");
                }
                errorProcessedPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so all 11 pushed documents below
    // (~747 bytes total) flush together in a single POST, matching the "initial request" the
    // mock expects, and so the whole batch is retried together as the "retry" after the 409.
    config["bulk_max_bytes"] = 720;
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    // Send a document with version that will cause conflict
    connector.bulkIndex("conflict_doc", "index1", R"({"field":"conflicting_value"})", "999");

    // Add more data to force bulk processing
    for (int i = 0; i < 10; ++i)
    {
        std::string id = "doc" + std::to_string(i);
        std::string data = R"({"field":"value)" + std::to_string(i) + R"("})";
        connector.bulkIndex(id, "index1", data);
    }

    // Wait for error processing to complete
    auto status = errorProcessedFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Timeout waiting for version conflict handling";
}

// =============================================================================
// Point In Time (PIT) Tests — Async
// =============================================================================

TEST_F(IndexerConnectorAsyncTest, CreatePointInTimeSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::string pitResponse = R"({
                    "pit_id": "async_pit_123",
                    "creation_time": 1700000000000
                })";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(pitResponse);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(pitResponse));
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-pit-queue");

    auto pit = connector.createPointInTime(std::vector<std::string> {"wazuh-states-*"}, "5m", true);
    EXPECT_EQ(pit.getPitId(), "async_pit_123");
    EXPECT_EQ(pit.getCreationTime(), 1700000000000ULL);
    EXPECT_EQ(pit.getKeepAlive(), "5m");
}

TEST_F(IndexerConnectorAsyncTest, CreatePointInTimeEmptyIndicesThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-pit-empty");

    EXPECT_THROW(connector.createPointInTime(std::vector<std::string> {}, "5m", false), IndexerConnectorException);
}

TEST_F(IndexerConnectorAsyncTest, CreatePointInTimeEmptyKeepAliveThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-pit-ka");

    EXPECT_THROW(connector.createPointInTime(std::vector<std::string> {"index"}, "", false), IndexerConnectorException);
}

TEST_F(IndexerConnectorAsyncTest, CreatePointInTimeServerErrorThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Server error", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Server error", 500, "");
                }
            }));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-pit-err");

    EXPECT_THROW(connector.createPointInTime(std::vector<std::string> {"index"}, "5m", false),
                 IndexerConnectorException);
}

TEST_F(IndexerConnectorAsyncTest, DeletePointInTimeSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, delete_(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedBody](auto&& req)
                    {
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(R"({"succeeded":true})");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(R"({"succeeded":true})");
                }
            }));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-del-pit");
    PointInTime pit("async_pit_to_delete", 100, "5m");

    EXPECT_NO_THROW(connector.deletePointInTime(pit));
    auto bodyJson = nlohmann::json::parse(capturedBody);
    EXPECT_EQ(bodyJson["pit_id"], "async_pit_to_delete");
}

TEST_F(IndexerConnectorAsyncTest, DeletePointInTimeEmptyIdThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-del-empty");

    PointInTime pit("", 0, "5m");
    EXPECT_THROW(connector.deletePointInTime(pit), IndexerConnectorException);
}

TEST_F(IndexerConnectorAsyncTest, DeletePointInTimeServerErrorThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, delete_(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Delete failed", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Delete failed", 500, "");
                }
            }));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-del-err");
    PointInTime pit("valid_pit", 100, "5m");

    EXPECT_THROW(connector.deletePointInTime(pit), IndexerConnectorException);
}

// =============================================================================
// Search Tests — Async (PIT-based)
// =============================================================================

TEST_F(IndexerConnectorAsyncTest, SearchWithPitSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedBody](auto&& req)
                    {
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                std::string response = R"({
                    "hits": {
                        "total": {"value": 1, "relation": "eq"},
                        "hits": [{"_id": "d1", "_source": {"f": "v"}, "sort": [1]}]
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

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-pit");
    PointInTime pit("s_pit", 100, "5m");
    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}});

    auto hits = connector.search(pit, static_cast<std::size_t>(10), query, sort, std::nullopt, std::nullopt);

    auto body = nlohmann::json::parse(capturedBody);
    EXPECT_EQ(body["pit"]["id"], "s_pit");
    EXPECT_TRUE(hits.contains("hits"));
}

TEST_F(IndexerConnectorAsyncTest, SearchWithPitSearchAfterAndSource)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedBody](auto&& req)
                    {
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                std::string response = R"({"hits":{"total":{"value":0},"hits":[]}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-sa");
    PointInTime pit("sa_pit", 100, "5m");
    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}});
    nlohmann::json searchAfter = nlohmann::json::array({5, "last_doc"});
    nlohmann::json source = {{"includes", nlohmann::json::array({"hash"})}};

    connector.search(pit, 10, query, sort, searchAfter, source);

    auto body = nlohmann::json::parse(capturedBody);
    EXPECT_TRUE(body.contains("search_after"));
    EXPECT_FALSE(body.contains("track_total_hits"));
    EXPECT_TRUE(body.contains("_source"));
}

TEST_F(IndexerConnectorAsyncTest, SearchWithPitAndSlice)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedBody](auto&& req)
                    {
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                std::string response = R"({"hits":{"total":{"value":0},"hits":[]}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-slice");
    PointInTime pit("slice_pit", 100, "5m");
    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}});
    nlohmann::json slice = {{"id", 2}, {"max", 8}};

    connector.search(pit, 10, query, sort, std::nullopt, std::nullopt, slice);

    auto body = nlohmann::json::parse(capturedBody);
    EXPECT_TRUE(body.contains("slice"));
    EXPECT_EQ(body["slice"]["id"], 2);
    EXPECT_EQ(body["slice"]["max"], 8);
}

TEST_F(IndexerConnectorAsyncTest, SearchWithPitServerErrorThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Search failed", 500, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Search failed", 500, "");
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-err");
    PointInTime pit("err_pit", 100, "5m");
    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}});

    EXPECT_THROW(connector.search(pit, static_cast<std::size_t>(10), query, sort, std::nullopt, std::nullopt),
                 IndexerConnectorException);
}

// =============================================================================
// Search Tests — Async (index-based, no PIT)
// =============================================================================

TEST_F(IndexerConnectorAsyncTest, SearchByIndexSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedUrl;
    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedUrl,
             &capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedUrl, &capturedBody](auto&& req)
                    {
                        capturedUrl = req.url.url();
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                std::string response = R"({
                    "hits": {
                        "total": {"value": 1},
                        "hits": [{"_id": "doc1", "_source": {"hash": "abc123"}}]
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

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-idx");

    nlohmann::json query = {{"bool", {{"filter", nlohmann::json::array({{{"term", {{"space.name", "free"}}}}})}}}};
    nlohmann::json source = {{"includes", nlohmann::json::array({"hash"})}};

    auto hits = connector.search("wazuh-threatintel-policies", 10, query, source);

    EXPECT_THAT(capturedUrl, ::testing::HasSubstr("/wazuh-threatintel-policies/_search"));
    auto body = nlohmann::json::parse(capturedBody);
    EXPECT_EQ(body["size"], 10);
    EXPECT_TRUE(body.contains("track_total_hits"));
    EXPECT_TRUE(body.contains("_source"));
    EXPECT_TRUE(hits.contains("hits"));
}

TEST_F(IndexerConnectorAsyncTest, SearchByIndexWithoutSource)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::string capturedBody;
    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBody](auto requestParams, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                std::visit(
                    [&capturedBody](auto&& req)
                    {
                        if constexpr (std::is_same_v<std::decay_t<decltype(req.data)>, std::string>)
                        {
                            capturedBody = req.data;
                        }
                    },
                    requestParams);

                std::string response = R"({"hits":{"total":{"value":0},"hits":[]}})";
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onSuccess(response);
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onSuccess(std::move(response));
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-nosrc");

    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    auto hits = connector.search("test-index", 5, query, std::nullopt);

    auto body = nlohmann::json::parse(capturedBody);
    EXPECT_FALSE(body.contains("_source"));
}

TEST_F(IndexerConnectorAsyncTest, SearchByIndexServerErrorThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [](auto /*requestParams*/, const auto& postParams, const ConfigurationParameters& /*configParams*/)
            {
                if (std::holds_alternative<TPostRequestParameters<const std::string&>>(postParams))
                {
                    std::get<TPostRequestParameters<const std::string&>>(postParams).onError("Not found", 404, "");
                }
                else
                {
                    std::get<TPostRequestParameters<std::string&&>>(postParams).onError("Not found", 404, "");
                }
            }));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-search-err2");

    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    try
    {
        connector.search("missing-index", 10, query, std::nullopt);
        FAIL() << "search() returned on a 404";
    }
    catch (const IndexerConnectorException& e)
    {
        EXPECT_EQ(e.statusCode(), 404);
    }
}

TEST_F(IndexerConnectorAsyncTest, PitAndSearchWithEveryNodeDownThrowIndexerConnectorException)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext())
        .WillRepeatedly(Invoke(
            []() -> std::string
            { throw IndexerConnectorException("No available server. Unavailable nodes: mockserver:9200: down"); }));
    EXPECT_CALL(mockHttpRequest, post(_, _, _)).Times(0);

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-no-server");
    PointInTime pit("pit", 100, "5m");
    nlohmann::json query = {{"match_all", nlohmann::json::object()}};
    nlohmann::json sort = nlohmann::json::array({{{"_shard_doc", "asc"}}});

    EXPECT_THROW(connector.createPointInTime(std::vector<std::string> {"index"}, "5m", false),
                 IndexerConnectorException);
    EXPECT_THROW(connector.search(pit, static_cast<std::size_t>(10), query, sort, std::nullopt, std::nullopt),
                 IndexerConnectorException);
    EXPECT_THROW(connector.search("index", 10, query, std::nullopt), IndexerConnectorException);
}

// =============================================================================
// bulkIndexDataStream Tests — Async
// =============================================================================

TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamSuccess)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> processingPromise;
    auto processingFuture = processingPromise.get_future();
    std::string capturedBulkData;

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(1)
        .WillOnce(Invoke(
            [&capturedBulkData, &processingPromise](
                RequestParamsVariant requestParams, const auto& postParams, const ConfigurationParameters&)
            {
                std::visit([&capturedBulkData](auto&& req) { capturedBulkData = req.data; }, requestParams);

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
                processingPromise.set_value();
            }));

    // BulkMaxBytes counts bytes, not documents: size it so the 5 pushed documents below
    // (~465 bytes total) flush together in a single POST instead of one-by-one.
    config["bulk_max_bytes"] = 420;
    IndexerConnectorAsyncImplSmallBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-ds-queue");

    // Push enough items to trigger the bulk (bulk size = 5)
    for (int i = 0; i < 5; ++i)
    {
        std::string data = R"({"@timestamp":"2026-01-01T00:00:00Z","msg":"event)" + std::to_string(i) + R"("})";
        connector.bulkIndexDataStream("wazuh-alerts-ds", data);
    }

    auto status = processingFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready);

    // Verify create action (not index) is used for data streams
    EXPECT_THAT(capturedBulkData, ::testing::HasSubstr(R"({"create":{"_index":"wazuh-alerts-ds"}})"));
    EXPECT_THAT(capturedBulkData, ::testing::Not(::testing::HasSubstr(R"("index")")));
}

TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamEmptyIndexThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    IndexerConnectorAsyncImplSmallBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-ds-empty");

    EXPECT_THROW(connector.bulkIndexDataStream("", R"({"data":"value"})"), IndexerConnectorException);
}

TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamEmptyDataThrows)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    IndexerConnectorAsyncImplSmallBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-ds-nodata");

    EXPECT_THROW(connector.bulkIndexDataStream("wazuh-alerts", ""), IndexerConnectorException);
}

// =============================================================================
// isAvailable & getDroppedEvents Tests — Async
// =============================================================================

TEST_F(IndexerConnectorAsyncTest, IsAvailableReturnsTrue)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, isAvailable()).WillRepeatedly(Return(true));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-avail-true");

    EXPECT_TRUE(connector.isAvailable());
}

TEST_F(IndexerConnectorAsyncTest, IsAvailableReturnsFalse)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, isAvailable()).WillRepeatedly(Return(false));

    IndexerConnectorAsyncImplTest connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-avail-false");

    EXPECT_FALSE(connector.isAvailable());
}

TEST_F(IndexerConnectorAsyncTest, GetDroppedEventsInitiallyZero)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorAsyncImplTest connector(config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-dropped");

    EXPECT_EQ(connector.getDroppedEvents(), 0ULL);
}

// JSON config override tests for bulk_max_bytes and flush_interval_seconds
TEST_F(IndexerConnectorAsyncTest, ElementsPerBulkFromJsonConfigTriggersBulk)
{
    // bulk_max_bytes=5 in JSON overrides the template default of 25000.
    // flush_interval_seconds=60 prevents the periodic timer from firing during the test window.
    // If the JSON value is honoured, pushing exactly 5 elements immediately triggers a bulk send.
    config["bulk_max_bytes"] = 200;
    config["flush_interval_seconds"] = 60;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> bulkSentPromise;
    std::future<void> bulkSentFuture = bulkSentPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &bulkSentPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                try
                {
                    bulkSentPromise.set_value();
                }
                catch (...)
                {
                }
            }));

    IndexerConnectorAsyncImplLargeBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-elements-per-bulk-json");

    for (int i = 0; i < 5; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "test_index", R"({"data":"x"})");
    }

    auto status = bulkSentFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready) << "Bulk not sent after pushing bulk_max_bytes items";
    EXPECT_GT(callCount, 0);
}

TEST_F(IndexerConnectorAsyncTest, ElementsPerBulkMinValueOneFlushesImmediately)
{
    // Extreme low value: bulk_max_bytes=1 means every single element triggers its own bulk send.
    // flush_interval_seconds=60 ensures the count trigger —not the timer— is responsible.
    config["bulk_max_bytes"] = 1;
    config["flush_interval_seconds"] = 60;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> bulkSentPromise;
    std::future<void> bulkSentFuture = bulkSentPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &bulkSentPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                try
                {
                    bulkSentPromise.set_value();
                }
                catch (...)
                {
                }
            }));

    IndexerConnectorAsyncImplLargeBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-min-elements-per-bulk");

    connector.bulkIndex("id0", "test_index", R"({"data":"x"})");

    auto status = bulkSentFuture.wait_for(std::chrono::seconds(5));
    EXPECT_EQ(status, std::future_status::ready)
        << "Single element should trigger immediate bulk with bulk_max_bytes=1";
    EXPECT_GT(callCount, 0);
}

TEST_F(IndexerConnectorAsyncTest, ElementsPerBulkBelowThresholdNoFlush)
{
    // Negative path: pushing a few items whose total bytes remain below bulk_max_bytes must NOT trigger a bulk send.
    config["bulk_max_bytes"] = 4096;
    config["flush_interval_seconds"] = 60;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    IndexerConnectorAsyncImplLargeBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-below-threshold");

    for (int i = 0; i < 4; ++i)
    {
        connector.bulkIndex("id" + std::to_string(i), "test_index", R"({"data":"x"})");
    }

    // Allow the async worker enough time to process any spurious flush.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_EQ(callCount, 0) << "No bulk should be sent when fewer than bulk_max_bytes items are queued";
}

TEST_F(IndexerConnectorAsyncTest, FlushIntervalSecondsFromJsonConfigTimerFires)
{
    // Verify that flush_interval_seconds from JSON config actually drives the periodic flush timer.
    config["flush_interval_seconds"] = 1;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    EXPECT_CALL(*mockSelector, getNext()).WillRepeatedly(Return("mockserver:9200"));

    std::promise<void> timerFiredPromise;
    std::future<void> timerFiredFuture = timerFiredPromise.get_future();

    EXPECT_CALL(mockHttpRequest, post(_, _, _))
        .Times(AtLeast(1))
        .WillRepeatedly(Invoke(
            [this, &timerFiredPromise](
                RequestParamsVariant requestParams, auto postParams, const ConfigurationParameters& configParams)
            {
                this->simulateSuccessfulPost(requestParams, postParams, configParams);
                try
                {
                    timerFiredPromise.set_value();
                }
                catch (...)
                {
                }
            }));

    IndexerConnectorAsyncImplLargeBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-flush-interval-timer");

    // 3 items — below the 25000-element count threshold
    connector.bulkIndex("id0", "test_index", R"({"data":"x"})");
    connector.bulkIndex("id1", "test_index", R"({"data":"x"})");
    connector.bulkIndex("id2", "test_index", R"({"data":"x"})");

    // 3s window
    auto status = timerFiredFuture.wait_for(std::chrono::seconds(3));
    EXPECT_EQ(status, std::future_status::ready)
        << "Expected 1s timer (from JSON flush_interval_seconds) to fire within 3s";
    EXPECT_GT(callCount, 0);
}

/****************************************************************************************
 * Error-logger fast path & sizing (bulkResponseHasErrors + logger_queue_size/threads)
 ****************************************************************************************/

TEST_F(IndexerConnectorAsyncTest, BulkResponseHasErrors_FalseIsDetected)
{
    // Canonical OpenSearch response head
    EXPECT_FALSE(
        IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"took":30,"errors":false,"items":[{"create":{}}]})"));
    // With whitespace around the colon
    EXPECT_FALSE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"took":1,"errors": false,"items":[]})"));
    EXPECT_FALSE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors("{\"took\":1,\"errors\":\n\tfalse}"));
}

TEST_F(IndexerConnectorAsyncTest, BulkResponseHasErrors_TrueIsDetected)
{
    EXPECT_TRUE(
        IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"took":30,"errors":true,"items":[{"create":{}}]})"));
    EXPECT_TRUE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"took":1,"errors": true})"));
}

TEST_F(IndexerConnectorAsyncTest, BulkResponseHasErrors_ConservativeWhenUnrecognized)
{
    // Field absent from the head -> conservative true (the logger's full parse decides)
    EXPECT_TRUE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"took":30,"items":[]})"));
    // Empty / malformed responses -> conservative true
    EXPECT_TRUE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(""));
    EXPECT_TRUE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(R"({"errors")"));
    // Field beyond the scanned head (first 256 bytes) -> conservative true
    const std::string longHead = "{\"took\":1,\"padding\":\"" + std::string(300, 'x') + "\",\"errors\":false}";
    EXPECT_TRUE(IndexerConnectorAsyncImplTest::bulkResponseHasErrors(longHead));
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithLoggerSizingConfig)
{
    // Explicit logger sizing must be accepted and the connector must keep indexing normally.
    config["logger_queue_size"] = 4;
    config["logger_threads"] = 2;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(
            config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-logger-sizing");
        connector.bulkIndex("id1", "index1", R"({"field":"value"})");
    });
}

TEST_F(IndexerConnectorAsyncTest, ConstructorWithZeroLoggerSizingFallsBackToDefaults)
{
    // Zero values are invalid; the connector falls back to the defaults instead of
    // creating an unbounded queue or zero threads.
    config["logger_queue_size"] = 0;
    config["logger_threads"] = 0;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    EXPECT_NO_THROW({
        IndexerConnectorAsyncImplTest connector(
            config, nullptr, &mockHttpRequest, std::move(mockSelector), "test-logger-zero");
        connector.bulkIndex("id1", "index1", R"({"field":"value"})");
    });
}

// =============================================================================
// Data-stream documents with a caller-supplied _id — Async
// =============================================================================

// A non-empty id becomes the `_id` of the create action.
TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamWithIdAction)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [](size_t, const PostRequestParametersVariant& postParams) { answerSuccess(postParams); });

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    const std::string data = R"({"@timestamp":"2026-01-01T00:00:00Z","msg":"with id"})";
    connector.bulkIndexDataStream("ds", "abc_-9", data);

    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    const auto bodies = log.bodies();
    ASSERT_EQ(bodies.size(), 1u);
    EXPECT_EQ(bodies[0], std::string(R"({"create":{"_index":"ds","_id":"abc_-9"}})") + "\n" + data + "\n");
}

// The id is JSON-escaped: every action line parses and gives back the original id byte for byte.
TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamEscapesId)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [](size_t, const PostRequestParametersVariant& postParams) { answerSuccess(postParams); });

    // Small bulk threshold: each document goes out in its own bulk, in push order.
    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    const std::vector<std::string> ids {
        R"(a"b\c)",
        std::string("n\0l\x01\n\r\t\b\f\x1fz", 11),                 // controls and an embedded NUL
        std::string("\xc3\xb1-\xe2\x82\xac-\xf0\x9f\x98\x80", 11)}; // UTF-8: 2, 3 and 4-byte characters
    ASSERT_EQ(ids[1].size(), 11u);
    ASSERT_EQ(ids[1][1], '\0');

    for (size_t i = 0; i < ids.size(); ++i)
    {
        connector.bulkIndexDataStream("ds", ids[i], R"({"doc":)" + std::to_string(i) + "}");
    }

    ASSERT_TRUE(log.waitAnswered(ids.size())) << "Timeout waiting for the bulks";
    const auto bodies = log.bodies();
    ASSERT_EQ(bodies.size(), ids.size());

    for (size_t i = 0; i < ids.size(); ++i)
    {
        SCOPED_TRACE("id #" + std::to_string(i));
        const auto& body = bodies[i];
        ASSERT_FALSE(body.empty());
        ASSERT_EQ(body.back(), '\n');
        const auto actionEnd = body.find('\n');
        ASSERT_NE(actionEnd, std::string::npos);
        ASSERT_EQ(body.find('\n', actionEnd + 1), body.size() - 1) << "exactly two NDJSON lines";

        nlohmann::json action;
        ASSERT_NO_THROW(action = nlohmann::json::parse(body.substr(0, actionEnd)));
        ASSERT_NO_THROW(std::ignore = nlohmann::json::parse(body.substr(actionEnd + 1, body.size() - actionEnd - 2)));
        EXPECT_EQ(action["create"]["_index"].get<std::string>(), "ds");
        EXPECT_EQ(action["create"]["_id"].get<std::string>(), ids[i]);
    }
}

// The 512-byte limit applies to the original id, before escaping; a longer id is rejected and
// nothing is queued.
TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamIdLengthLimit)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [](size_t, const PostRequestParametersVariant& postParams) { answerSuccess(postParams); });

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    const std::string data = R"({"msg":"limit"})";
    const std::string ascii512(512, 'a');
    const std::string ascii513(513, 'a');
    const std::string quotes512(512, '"'); // 1024 bytes once escaped
    const std::string multibyte513 = std::string(511, 'a') + "\xc3\xa9";
    ASSERT_EQ(multibyte513.size(), 513u);

    EXPECT_THROW(connector.bulkIndexDataStream("ds", ascii513, data), IndexerConnectorException);
    EXPECT_THROW(connector.bulkIndexDataStream("ds", multibyte513, data), IndexerConnectorException);
    EXPECT_EQ(connector.getQueueSize(), 0u) << "a rejected id queues nothing";

    connector.bulkIndexDataStream("ds", ascii512, data);
    connector.bulkIndexDataStream("ds", quotes512, data);

    ASSERT_TRUE(log.waitAnswered(2)) << "Timeout waiting for the bulks";

    std::string escapedQuotes;
    for (size_t i = 0; i < quotes512.size(); ++i)
    {
        escapedQuotes += R"(\")";
    }

    // The queue is FIFO: had a rejected id been queued, it would have been posted first.
    const auto bodies = log.bodies();
    ASSERT_EQ(bodies.size(), 2u);
    EXPECT_EQ(bodies[0], dataStreamEntry("ds", ascii512, data));
    EXPECT_EQ(bodies[1], dataStreamEntry("ds", escapedQuotes, data));
    EXPECT_EQ(log.posts(), 2u);
}

// An empty id and the two-argument overload both queue the legacy action, without `_id`.
TEST_F(IndexerConnectorAsyncTest, BulkIndexDataStreamEmptyIdKeepsLegacyAction)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [](size_t, const PostRequestParametersVariant& postParams) { answerSuccess(postParams); });

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    const std::string emptyIdData = R"({"msg":"empty id"})";
    const std::string twoArgData = R"({"msg":"two arguments"})";
    connector.bulkIndexDataStream("ds", "", emptyIdData);
    connector.bulkIndexDataStream("ds", twoArgData);

    ASSERT_TRUE(log.waitAnswered(2)) << "Timeout waiting for the bulks";
    const auto bodies = log.bodies();
    ASSERT_EQ(bodies.size(), 2u);
    EXPECT_EQ(bodies[0], std::string(R"({"create":{"_index":"ds"}})") + "\n" + emptyIdData + "\n");
    EXPECT_EQ(bodies[1], std::string(R"({"create":{"_index":"ds"}})") + "\n" + twoArgData + "\n");
}

// Every retried failure resends the same body, `_id` included, byte for byte — also when the
// resend goes to another node.
TEST_F(IndexerConnectorAsyncTest, DataStreamIdSurvivesRetry)
{
    struct Scenario
    {
        std::string name;
        std::function<void(const PostRequestParametersVariant&)> firstAnswer;
        bool alternateNodes;
    };
    const std::vector<Scenario> scenarios {
        // Code 0: no HTTP answer at all; a request timeout takes this same path.
        {"transport failure (code 0)",
         [](const PostRequestParametersVariant& p) { answerError(p, "Timeout was reached", 0); },
         false},
        {"HTTP 429", [](const PostRequestParametersVariant& p) { answerError(p, "Too Many Requests", 429); }, false},
        {"HTTP 503", [](const PostRequestParametersVariant& p) { answerError(p, "Service Unavailable", 503); }, false},
        {"transport failure (code 0), next node",
         [](const PostRequestParametersVariant& p) { answerError(p, "Couldn't connect to server", 0); },
         true}};

    const std::string data = R"({"@timestamp":"2026-01-01T00:00:00Z","msg":"retried"})";
    const std::string expected = dataStreamEntry("ds", "evt-42", data);

    for (const auto& scenario : scenarios)
    {
        SCOPED_TRACE(scenario.name);

        auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
        std::atomic<int> selections {0};
        if (scenario.alternateNodes)
        {
            ON_CALL(*mockSelector, getNext())
                .WillByDefault(Invoke([&selections]() { return std::string(selections++ % 2 == 0 ? "n1" : "n2"); }));
        }
        else
        {
            ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));
        }

        PostLog log;
        recordPosts(mockHttpRequest,
                    log,
                    [&scenario](size_t index, const PostRequestParametersVariant& postParams)
                    {
                        if (index == 0)
                        {
                            scenario.firstAnswer(postParams);
                        }
                        else
                        {
                            answerSuccess(postParams);
                        }
                    });

        {
            IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
            connector.bulkIndexDataStream("ds", "evt-42", data);

            // Only the second (successful) answer returns without throwing.
            ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the resend";
            EXPECT_EQ(log.posts(), 2u);
            EXPECT_EQ(connector.getQueueSize(), 0u);

            const auto bodies = log.bodies();
            ASSERT_EQ(bodies.size(), 2u);
            EXPECT_EQ(bodies[0], expected);
            EXPECT_EQ(bodies[1], bodies[0]) << "the resend carries the same action and _id";

            if (scenario.alternateNodes)
            {
                EXPECT_EQ(log.urls(), (std::vector<std::string> {"n1/_bulk", "n2/_bulk"}));
            }
        }

        ::testing::Mock::VerifyAndClearExpectations(&mockHttpRequest);
    }
}

// After a 413 the requeued batch is split into smaller bulks, mixed with documents queued
// meanwhile; every action+document pair still goes out byte for byte, exactly once.
TEST_F(IndexerConnectorAsyncTest, DataStreamIdSurvivesSplitAndMix)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    // Entry sizes (action + document + newlines) against the 8192-byte threshold, halved to 4096 by the
    // 413: the four old entries (8500 bytes) wake the dispatcher only once the fourth is queued and go
    // out together; after the 413 the queue drains [old-1, old-2], [old-3, old-4, new-1], [new-2]. Every
    // send is triggered by the threshold, never by the flush timer (60 s below).
    struct Doc
    {
        std::string id;
        size_t entryBytes;
    };
    const std::vector<Doc> oldDocs {{"old-1", 2500}, {"old-2", 2500}, {"old-3", 2500}, {"old-4", 1000}};
    const std::vector<Doc> newDocs {{"new-1", 1000}, {"new-2", 4200}};

    const auto sizedData = [](const Doc& doc)
    {
        const auto overhead = dataStreamEntry("ds", doc.id, R"({"tag":")" + doc.id + R"(","pad":""})").size();
        return R"({"tag":")" + doc.id + R"(","pad":")" + std::string(doc.entryBytes - overhead, 'p') + R"("})";
    };

    std::vector<std::string> oldData, newData, oldEntries, newEntries;
    for (const auto& doc : oldDocs)
    {
        oldData.push_back(sizedData(doc));
        oldEntries.push_back(dataStreamEntry("ds", doc.id, oldData.back()));
        ASSERT_EQ(oldEntries.back().size(), doc.entryBytes);
    }
    for (const auto& doc : newDocs)
    {
        newData.push_back(sizedData(doc));
        newEntries.push_back(dataStreamEntry("ds", doc.id, newData.back()));
        ASSERT_EQ(newEntries.back().size(), doc.entryBytes);
    }

    std::promise<void> firstPostEntered;
    auto firstPostEnteredFuture = firstPostEntered.get_future();
    std::promise<void> newQueued;
    std::shared_future<void> newQueuedFuture = newQueued.get_future().share();

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&firstPostEntered, newQueuedFuture](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        // Hold the first send until the two new documents are queued, so that the
                        // requeued batch shares the queue with them.
                        firstPostEntered.set_value();
                        static_cast<void>(newQueuedFuture.wait_for(std::chrono::seconds(10)));
                        answerError(postParams, "Payload Too Large", 413);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    config["flush_interval_seconds"] = 60;
    IndexerConnectorAsyncImplSplitBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (size_t i = 0; i < oldDocs.size(); ++i)
    {
        connector.bulkIndexDataStream("ds", oldDocs[i].id, oldData[i]);
    }
    ASSERT_EQ(firstPostEnteredFuture.wait_for(std::chrono::seconds(10)), std::future_status::ready)
        << "Timeout waiting for the first bulk";
    for (size_t i = 0; i < newDocs.size(); ++i)
    {
        connector.bulkIndexDataStream("ds", newDocs[i].id, newData[i]);
    }
    newQueued.set_value();

    std::vector<std::string> allEntries = oldEntries;
    allEntries.insert(allEntries.end(), newEntries.begin(), newEntries.end());

    const auto resentOf = [](const std::vector<std::string>& bodies)
    {
        std::string resent;
        for (size_t i = 1; i < bodies.size(); ++i)
        {
            resent += bodies[i];
        }
        return resent;
    };
    ASSERT_TRUE(log.waitUntil(
        [&allEntries, &resentOf](const std::vector<std::string>& bodies)
        {
            const auto resent = resentOf(bodies);
            return std::all_of(allEntries.begin(),
                               allEntries.end(),
                               [&resent](const std::string& entry) { return resent.find(entry) != std::string::npos; });
        }))
        << "Timeout waiting for every entry to go out after the 413";

    const auto bodies = log.bodies();
    std::string firstBulk;
    for (const auto& entry : oldEntries)
    {
        firstBulk += entry;
    }
    EXPECT_EQ(bodies[0], firstBulk) << "the four documents go out together before the 413";
    EXPECT_GE(bodies.size(), 3u) << "at least two bulks after the 413";

    // Each pair goes out exactly once after the 413, byte for byte, and nothing else does.
    const auto resent = resentOf(bodies);
    size_t expectedBytes = 0;
    for (const auto& entry : allEntries)
    {
        expectedBytes += entry.size();
        size_t occurrences = 0;
        for (auto pos = resent.find(entry); pos != std::string::npos; pos = resent.find(entry, pos + 1))
        {
            ++occurrences;
        }
        EXPECT_EQ(occurrences, 1u) << entry.substr(0, 48);
    }
    EXPECT_EQ(resent.size(), expectedBytes);

    // At least one bulk after the 413 mixes requeued and newly queued documents.
    const auto contains = [](const std::string& body, const std::vector<std::string>& entries)
    {
        return std::any_of(entries.begin(),
                           entries.end(),
                           [&body](const std::string& entry) { return body.find(entry) != std::string::npos; });
    };
    EXPECT_TRUE(std::any_of(bodies.begin() + 1,
                            bodies.end(),
                            [&](const std::string& body)
                            { return contains(body, oldEntries) && contains(body, newEntries); }))
        << "no bulk mixes old and new documents";
}

// A per-item 429 on a document with an id is dropped and counted, not resent nor deduplicated.
TEST_F(IndexerConnectorAsyncTest, PerItem429WithIdIsDroppedNotResent)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    const auto throttled = bulkResponse({bulkItem("create", 429, "es_rejected_execution_exception")});

    PauseLog pauses;
    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&throttled](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        answerSuccessWith(postParams, throttled);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    IndexerConnectorAsyncImplSmallBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, pauses.observer());

    connector.bulkIndexDataStream("ds", "evt-429", R"({"msg":"throttled"})");

    // The answer returned without throwing: the batch was not requeued.
    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    EXPECT_EQ(connector.getQueueSize(), 0u);

    // The logger counts the drop before it requests the backoff.
    ASSERT_TRUE(pauses.waitExternal()) << "Timeout waiting for the backoff after the per-item 429";

    EXPECT_EQ(log.posts(), 1u);
    EXPECT_EQ(connector.getDroppedEvents(), 1u);
    EXPECT_EQ(connector.getDeduplicatedEvents(), 0u);
}

// Create items answered 409 version_conflict_engine_exception are counted and reported by one
// WARN, with no per-document line; another error in the same bulk still quotes its own document.
TEST_F(IndexerConnectorAsyncTest, AppliedConflictsCountedAndWarnedOnce)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    const auto response = bulkResponse({appliedConflictItem(),
                                        appliedConflictItem(),
                                        appliedConflictItem(),
                                        bulkItem("create", 400, "mapper_parsing_exception")});

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&response](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        answerSuccessWith(postParams, response);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    IndexerConnectorAsyncImplMultiItemBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (const auto* tag : {"doc-A", "doc-B", "doc-C", "doc-D"})
    {
        connector.bulkIndexDataStream("ds", tag, std::string(R"({"doc":")") + tag + R"("})");
    }

    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    ASSERT_NE(log.bodies()[0].find("doc-D"), std::string::npos) << "the four documents must go out in one bulk";

    // Counted and reported on the dispatch thread, inside the answer.
    EXPECT_EQ(connector.getDeduplicatedEvents(), 3u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, dedupWarn(3)), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, DEDUP_WARN_TAIL), 1u);

    // The logger walks the items in order: once the last one is logged, the 409s were handled.
    ASSERT_TRUE(waitForWarnings(logs, "type mapper_parsing_exception", 1))
        << "Timeout waiting for the mapper_parsing_exception line";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Error indexing document"), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "version_conflict_engine_exception"), 0u)
        << "no per-document line for the applied conflicts";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING,
                                R"(reason of mapper_parsing_exception') - Associated event: {"create":{"_index":"ds",)"
                                R"("_id":"doc-D"}}\n{"doc":"doc-D"})"),
              1u)
        << "the mapper_parsing_exception line quotes its own document";
    for (const auto* other : {"doc-A", "doc-B", "doc-C"})
    {
        EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, other), 0u) << other;
    }
    EXPECT_EQ(log.posts(), 1u);
}

// An applied conflict next to a per-item 429 and a cluster_block_exception: only the 429 is dropped,
// the backoff is requested as before and nothing is requeued.
TEST_F(IndexerConnectorAsyncTest, AppliedConflictsMixedWithThrottleAndBlock)
{
    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    const auto response = bulkResponse({appliedConflictItem(),
                                        bulkItem("create", 429, "es_rejected_execution_exception"),
                                        bulkItem("create", 403, "cluster_block_exception")});

    PauseLog pauses;
    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&response](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        answerSuccessWith(postParams, response);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    IndexerConnectorAsyncImplMultiItemBulk connector(
        config, nullptr, &mockHttpRequest, std::move(mockSelector), "", std::nullopt, pauses.observer());

    for (const auto* tag : {"doc-applied", "doc-throttled", "doc-blocked"})
    {
        connector.bulkIndexDataStream("ds", tag, std::string(R"({"doc":")") + tag + R"("})");
    }

    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    ASSERT_NE(log.bodies()[0].find("doc-blocked"), std::string::npos) << "the three documents must go out in one bulk";
    EXPECT_EQ(connector.getDeduplicatedEvents(), 1u);
    EXPECT_EQ(connector.getQueueSize(), 0u) << "nothing requeued";

    ASSERT_TRUE(pauses.waitExternal()) << "Timeout waiting for the backoff";
    EXPECT_EQ(connector.getDroppedEvents(), 1u) << "only the 429 is dropped";
    EXPECT_EQ(connector.getDeduplicatedEvents(), 1u);
    EXPECT_EQ(log.posts(), 1u);
}

// The dedup WARN is edge-triggered. It re-arms on a clean answer or on an error answer with an
// `items` array and no applied conflict; an unparseable answer, or one without an `items` array,
// neither re-arms it nor counts.
TEST_F(IndexerConnectorAsyncTest, AppliedConflictWarnIsEdgeTriggered)
{
    const auto applied = bulkResponse({appliedConflictItem()});
    const std::string clean = CLEAN_BULK_RESPONSE;
    const auto notDeduplicable = bulkResponse({bulkItem("create", 400, "mapper_parsing_exception")});
    // Marker, not a body: the post is answered with an HTTP 503 (the batch is requeued and resent).
    const std::string UNAVAILABLE_503 = "<http 503>";

    struct Sequence
    {
        std::string name;
        std::vector<std::string> responses;
        size_t expectedWarnings;
        uint64_t expectedDeduplicated;
        // 0 = one per response. A 503 answer requeues its document: one more POST than documents,
        // and the 503 POST is not answered (its callback throws).
        size_t documents {0};
        size_t answered {0};
        size_t posts {0};
    };
    const std::vector<Sequence> sequences {
        {"(a) applied, applied, clean, applied", {applied, applied, clean, applied}, 2, 3},
        {"(b) applied, not deduplicable, applied", {applied, notDeduplicable, applied}, 2, 2},
        {"(c) applied, invalid body, applied", {applied, "not a json body", applied}, 1, 2},
        {"(c) applied, no items, applied", {applied, R"({"took":1,"errors":true})", applied}, 1, 2},
        {"(c) applied, items object, applied", {applied, R"({"took":1,"errors":true,"items":{}})", applied}, 1, 2},
        {"(c) applied, items null, applied", {applied, R"({"took":1,"errors":true,"items":null})", applied}, 1, 2},
        // An HTTP error answer goes through onError and does not end the streak.
        {"(d) applied, HTTP 503, applied", {applied, UNAVAILABLE_503, applied}, 1, 2, 2, 2, 3}};

    for (const auto& sequence : sequences)
    {
        SCOPED_TRACE(sequence.name);

        // Installed before the connector: its threads log until the connector is destroyed.
        ScopedLogCapture logs;

        auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
        ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

        PostLog log;
        recordPosts(mockHttpRequest,
                    log,
                    [&sequence, &UNAVAILABLE_503](size_t index, const PostRequestParametersVariant& postParams)
                    {
                        if (index < sequence.responses.size() && sequence.responses[index] == UNAVAILABLE_503)
                        {
                            answerError(postParams, "Service Unavailable", 503);
                        }
                        else if (index < sequence.responses.size())
                        {
                            answerSuccessWith(postParams, sequence.responses[index]);
                        }
                        else
                        {
                            answerSuccess(postParams);
                        }
                    });

        {
            // Small bulk threshold: one document, and one answer of the sequence, per bulk.
            IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
            const auto documents = sequence.documents != 0 ? sequence.documents : sequence.responses.size();
            const auto answered = sequence.answered != 0 ? sequence.answered : sequence.responses.size();
            const auto posts = sequence.posts != 0 ? sequence.posts : sequence.responses.size();
            for (size_t i = 0; i < documents; ++i)
            {
                connector.bulkIndexDataStream("ds", "evt-" + std::to_string(i), R"({"n":)" + std::to_string(i) + "}");
            }

            ASSERT_TRUE(log.waitAnswered(answered)) << "Timeout waiting for the bulks";
            EXPECT_EQ(log.posts(), posts);
            EXPECT_EQ(connector.getDeduplicatedEvents(), sequence.expectedDeduplicated);
            EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, DEDUP_WARN_TAIL), sequence.expectedWarnings);
            EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, dedupWarn(1)), sequence.expectedWarnings);
        }

        ::testing::Mock::VerifyAndClearExpectations(&mockHttpRequest);
    }
}

// Only a create answered 409 with version_conflict_engine_exception is an applied document. Any
// other conflict is neither counted nor warned about, and is still logged per document.
TEST_F(IndexerConnectorAsyncTest, OtherConflictsAreNotDeduplicated)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    const auto response = bulkResponse({bulkItem("create", 409, "foo_exception"),
                                        bulkItem("create", 400, "version_conflict_engine_exception"),
                                        bulkItem("index", 409, "version_conflict_engine_exception"),
                                        bulkItem("delete", 409, "version_conflict_engine_exception")});

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&response](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        answerSuccessWith(postParams, response);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    IndexerConnectorAsyncImplMultiItemBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));

    for (const auto* tag : {"doc-1", "doc-2", "doc-3", "doc-4"})
    {
        connector.bulkIndexDataStream("ds", tag, std::string(R"({"doc":")") + tag + R"("})");
    }

    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    ASSERT_NE(log.bodies()[0].find("doc-4"), std::string::npos) << "the four documents must go out in one bulk";
    EXPECT_EQ(connector.getDeduplicatedEvents(), 0u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, DEDUP_WARN_TAIL), 0u);

    ASSERT_TRUE(waitForWarnings(logs, "Error deleting document", 1)) << "Timeout waiting for the per-document lines";
    ASSERT_TRUE(waitForWarnings(logs, "Error indexing document", 3)) << "Timeout waiting for the per-document lines";
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Error indexing document"), 3u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "Error deleting document"), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "(type foo_exception"), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, "(type version_conflict_engine_exception"), 3u);
    for (const auto* tag : {"doc-1", "doc-2", "doc-3", "doc-4"})
    {
        EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, std::string(R"("_id":")") + tag + R"("}})"), 1u) << tag;
    }
    EXPECT_EQ(connector.getDeduplicatedEvents(), 0u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, DEDUP_WARN_TAIL), 0u);
}

// An applied conflict in an answer whose item count does not match the bulk: the logger keeps today's
// mismatch WARN and the dispatch thread still counts the applied item.
TEST_F(IndexerConnectorAsyncTest, AppliedConflictKeepsMismatchDiagnostic)
{
    // Installed before the connector: its threads log until the connector is destroyed.
    ScopedLogCapture logs;

    auto mockSelector = std::make_unique<NiceMock<MockServerSelector>>();
    ON_CALL(*mockSelector, getNext()).WillByDefault(Return("mockserver:9200"));

    const auto response = bulkResponse({appliedConflictItem(), bulkItem("create", 201)});

    PostLog log;
    recordPosts(mockHttpRequest,
                log,
                [&response](size_t index, const PostRequestParametersVariant& postParams)
                {
                    if (index == 0)
                    {
                        answerSuccessWith(postParams, response);
                    }
                    else
                    {
                        answerSuccess(postParams);
                    }
                });

    IndexerConnectorAsyncImplSmallBulk connector(config, nullptr, &mockHttpRequest, std::move(mockSelector));
    connector.bulkIndexDataStream("ds", "evt-mismatch", R"({"msg":"one document, two items"})");

    ASSERT_TRUE(log.waitAnswered(1)) << "Timeout waiting for the bulk";
    EXPECT_EQ(connector.getDeduplicatedEvents(), 1u);
    EXPECT_EQ(logs.countAtLevel(Log::LOGLEVEL_WARNING, dedupWarn(1)), 1u);

    ASSERT_TRUE(waitForWarnings(logs, "Mismatch between the number of events (1) and response items (2)", 1))
        << "Timeout waiting for the mismatch WARN";
    EXPECT_EQ(log.posts(), 1u);
}
