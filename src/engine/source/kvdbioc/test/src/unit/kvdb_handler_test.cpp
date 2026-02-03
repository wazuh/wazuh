#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <kvdbioc/mockManager.hpp>
#include <kvdbioc/mockReadOnlyHandler.hpp>

#include <atomic>
#include <chrono>
#include <mutex>
#include <thread>
#include <vector>

using namespace kvdbioc;
using ::testing::_;
using ::testing::NiceMock;
using ::testing::Return;
using ::testing::ReturnRef;
using ::testing::StrictMock;

// Unit tests using mocks to isolate Handler behavior
class HandlerUnitTest : public ::testing::Test
{
protected:
    NiceMock<MockReadOnlyKVDBHandler> mockHandler;
    std::string dbName {"test_database"};
};

TEST_F(HandlerUnitTest, NameReturnsExpectedValue)
{
    EXPECT_CALL(mockHandler, name()).WillOnce(ReturnRef(dbName));

    const auto& result = mockHandler.name();
    EXPECT_EQ(result, "test_database");
}

TEST_F(HandlerUnitTest, GetReturnsValidJson)
{
    json::Json expectedData(R"({"key":"user:100","name":"TestUser","active":true})");

    EXPECT_CALL(mockHandler, get("user:100")).WillOnce(Return(expectedData));

    auto result = mockHandler.get("user:100");

    EXPECT_TRUE(result.has_value());
    EXPECT_TRUE(result->isObject());
    EXPECT_EQ(result->getString("/name").value(), "TestUser");
    EXPECT_TRUE(result->getBool("/active").value());
}

TEST_F(HandlerUnitTest, GetReturnsErrorForMissingKey)
{
    EXPECT_CALL(mockHandler, get("missing:key"))
        .WillOnce(::testing::Throw(std::runtime_error("Key 'missing:key' not found")));

    EXPECT_THROW({ auto result = mockHandler.get("missing:key"); }, std::runtime_error);
}

TEST_F(HandlerUnitTest, GetCanReturnDifferentValuesForDifferentKeys)
{
    json::Json user1(R"({"key":"user:1","name":"Alice"})");
    json::Json user2(R"({"key":"user:2","name":"Bob"})");

    EXPECT_CALL(mockHandler, get("user:1")).WillOnce(Return(user1));
    EXPECT_CALL(mockHandler, get("user:2")).WillOnce(Return(user2));

    auto result1 = mockHandler.get("user:1");
    auto result2 = mockHandler.get("user:2");

    EXPECT_EQ(result1->getString("/name").value(), "Alice");
    EXPECT_EQ(result2->getString("/name").value(), "Bob");
}

TEST_F(HandlerUnitTest, GetCalledMultipleTimesWithSameKey)
{
    json::Json data(R"({"key":"config","value":"setting"})");

    EXPECT_CALL(mockHandler, get("config")).Times(3).WillRepeatedly(Return(data));

    for (int i = 0; i < 3; ++i)
    {
        auto result = mockHandler.get("config");
        EXPECT_TRUE(result.has_value());
        EXPECT_TRUE(result->isObject());
    }
}

TEST_F(HandlerUnitTest, HandlerInterfaceCompliance)
{
    // Verify handler implements IReadOnlyKVDBHandler interface
    IReadOnlyKVDBHandler* handler = &mockHandler;
    EXPECT_NE(handler, nullptr);
}

// Test handler behavior with complex JSON structures
TEST_F(HandlerUnitTest, GetReturnsComplexNestedJson)
{
    json::Json complexData(R"({
        "key":"config:app",
        "settings": {
            "database": {
                "host": "localhost",
                "port": 5432
            },
            "features": ["auth", "logging", "metrics"]
        }
    })");

    EXPECT_CALL(mockHandler, get("config:app")).WillOnce(Return(complexData));

    auto result = mockHandler.get("config:app");

    EXPECT_TRUE(result.has_value());
    EXPECT_EQ(result->getString("/settings/database/host").value(), "localhost");
    EXPECT_EQ(result->getInt("/settings/database/port").value(), 5432);
}

// Test error scenarios
TEST_F(HandlerUnitTest, GetReturnsErrorForDatabaseError)
{
    EXPECT_CALL(mockHandler, get("any:key")).WillOnce(::testing::Throw(std::runtime_error("RocksDB error: IO Error")));

    EXPECT_THROW({ auto result = mockHandler.get("any:key"); }, std::runtime_error);
}

TEST_F(HandlerUnitTest, GetReturnsErrorForNoInstancePublished)
{
    EXPECT_CALL(mockHandler, get("key"))
        .WillOnce(::testing::Throw(std::runtime_error("KVDB 'testdb': no instance published")));

    EXPECT_THROW({ auto result = mockHandler.get("key"); }, std::runtime_error);
}

// Strict mock test - ensures only expected calls are made
TEST(HandlerStrictTest, OnlyExpectedCallsAreMade)
{
    StrictMock<MockReadOnlyKVDBHandler> strictHandler;
    std::string name = "strict_db";

    EXPECT_CALL(strictHandler, name()).WillOnce(ReturnRef(name));

    // This call is expected
    strictHandler.name();

    // Any unexpected call would fail the test with StrictMock
}

// ============================================================================
// MULTITHREAD TESTS
// ============================================================================

class HandlerMultiThreadTest : public ::testing::Test
{
protected:
    NiceMock<MockReadOnlyKVDBHandler> mockHandler;
    std::string dbName {"test_database"};
};

// Test multiple threads reading the same key concurrently
TEST_F(HandlerMultiThreadTest, ConcurrentReadsSameKey)
{
    const int numThreads = 10;
    const int operationsPerThread = 100;
    json::Json expectedData(R"({"key":"user:100","name":"TestUser","active":true})");

    EXPECT_CALL(mockHandler, get("user:100"))
        .Times(numThreads * operationsPerThread)
        .WillRepeatedly(Return(expectedData));

    std::vector<std::thread> threads;
    std::atomic<int> successCount {0};
    std::atomic<int> errorCount {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < operationsPerThread; ++j)
                {
                    try
                    {
                        auto result = mockHandler.get("user:100");
                        if (result.has_value() && result->getString("/name").value() == "TestUser")
                        {
                            successCount++;
                        }
                    }
                    catch (const std::exception&)
                    {
                        errorCount++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successCount, numThreads * operationsPerThread);
    EXPECT_EQ(errorCount, 0);
}

// Test multiple threads reading different keys concurrently
TEST_F(HandlerMultiThreadTest, ConcurrentReadsDifferentKeys)
{
    const int numThreads = 8;
    const int operationsPerThread = 50;

    // Setup expectations for different keys
    for (int i = 0; i < numThreads; ++i)
    {
        std::string key = "user:" + std::to_string(i);
        std::string jsonStr = R"({"key":")" + key + R"(","name":"User)" + std::to_string(i) + R"("})";
        json::Json data(jsonStr.c_str());

        EXPECT_CALL(mockHandler, get(key)).Times(operationsPerThread).WillRepeatedly(Return(data));
    }

    std::vector<std::thread> threads;
    std::atomic<int> totalReads {0};
    std::mutex resultsMutex;
    std::vector<bool> threadResults(numThreads, true);

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, threadId = i]()
            {
                std::string key = "user:" + std::to_string(threadId);
                std::string expectedName = "User" + std::to_string(threadId);

                for (int j = 0; j < operationsPerThread; ++j)
                {
                    try
                    {
                        auto result = mockHandler.get(key);
                        totalReads++;

                        if (!result.has_value() || result->getString("/name").value() != expectedName)
                        {
                            std::lock_guard<std::mutex> lock(resultsMutex);
                            threadResults[threadId] = false;
                        }
                    }
                    catch (const std::exception&)
                    {
                        std::lock_guard<std::mutex> lock(resultsMutex);
                        threadResults[threadId] = false;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(totalReads, numThreads * operationsPerThread);
    for (int i = 0; i < numThreads; ++i)
    {
        EXPECT_TRUE(threadResults[i]) << "Thread " << i << " failed";
    }
}

// Test concurrent reads with mixed success and error results
TEST_F(HandlerMultiThreadTest, ConcurrentReadsWithErrors)
{
    const int numThreads = 6;
    const int operationsPerThread = 30;
    json::Json successData(R"({"key":"valid:key","status":"ok"})");

    EXPECT_CALL(mockHandler, get("valid:key")).WillRepeatedly(Return(successData));

    EXPECT_CALL(mockHandler, get("invalid:key")).WillRepeatedly(::testing::Throw(std::runtime_error("Key not found")));

    std::vector<std::thread> threads;
    std::atomic<int> successReads {0};
    std::atomic<int> errorReads {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, threadId = i]()
            {
                for (int j = 0; j < operationsPerThread; ++j)
                {
                    // Alternate between valid and invalid keys
                    std::string key = (j % 2 == 0) ? "valid:key" : "invalid:key";
                    try
                    {
                        auto result = mockHandler.get(key);
                        successReads++;
                    }
                    catch (const std::exception&)
                    {
                        errorReads++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    int totalOps = numThreads * operationsPerThread;
    EXPECT_EQ(successReads + errorReads, totalOps);
    EXPECT_GT(successReads, 0);
    EXPECT_GT(errorReads, 0);
}

// Stress test with many threads and operations
TEST_F(HandlerMultiThreadTest, StressTestManyThreads)
{
    const int numThreads = 20;
    const int operationsPerThread = 200;
    json::Json data(R"({"key":"stress:test","data":"value"})");

    EXPECT_CALL(mockHandler, get("stress:test")).Times(numThreads * operationsPerThread).WillRepeatedly(Return(data));

    std::vector<std::thread> threads;
    std::atomic<int> completedOps {0};
    std::atomic<bool> allSuccess {true};

    auto startTime = std::chrono::high_resolution_clock::now();

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < operationsPerThread; ++j)
                {
                    try
                    {
                        auto result = mockHandler.get("stress:test");
                        completedOps++;
                    }
                    catch (const std::exception&)
                    {
                        allSuccess = false;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);

    EXPECT_EQ(completedOps, numThreads * operationsPerThread);
    EXPECT_TRUE(allSuccess);

    // Performance check - should complete in reasonable time (adjust as needed)
    EXPECT_LT(duration.count(), 5000) << "Stress test took too long: " << duration.count() << "ms";
}

// Test concurrent access to handler name
TEST_F(HandlerMultiThreadTest, ConcurrentNameAccess)
{
    const int numThreads = 10;
    const int operationsPerThread = 100;

    EXPECT_CALL(mockHandler, name()).Times(numThreads * operationsPerThread).WillRepeatedly(ReturnRef(dbName));

    std::vector<std::thread> threads;
    std::atomic<bool> allCorrect {true};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < operationsPerThread; ++j)
                {
                    const auto& name = mockHandler.name();
                    if (name != "test_database")
                    {
                        allCorrect = false;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_TRUE(allCorrect);
}

// Test with complex JSON in concurrent scenario
TEST_F(HandlerMultiThreadTest, ConcurrentComplexJsonReads)
{
    const int numThreads = 8;
    const int operationsPerThread = 50;

    json::Json complexData(R"({
        "key":"config:app",
        "settings": {
            "database": {
                "host": "localhost",
                "port": 5432
            },
            "features": ["auth", "logging", "metrics"]
        },
        "counters": {
            "requests": 12345,
            "errors": 42
        }
    })");

    EXPECT_CALL(mockHandler, get("config:app"))
        .Times(numThreads * operationsPerThread)
        .WillRepeatedly(Return(complexData));

    std::vector<std::thread> threads;
    std::atomic<int> validationErrors {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < operationsPerThread; ++j)
                {
                    try
                    {
                        auto result = mockHandler.get("config:app");

                        // Validate different parts of the JSON
                        if (!result.has_value() || result->getString("/settings/database/host").value() != "localhost"
                            || result->getInt("/settings/database/port").value() != 5432
                            || result->getInt("/counters/requests").value() != 12345)
                        {
                            validationErrors++;
                        }
                    }
                    catch (const std::exception&)
                    {
                        validationErrors++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(validationErrors, 0);
}
