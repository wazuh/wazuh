#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <kvdbioc/manager.hpp>
#include <store/mockStore.hpp>

namespace fs = std::filesystem;

// Component/Integration tests for full KVDB workflow
class KVDBComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Use unique directory per test to allow parallel execution
        auto testInfo = ::testing::UnitTest::GetInstance()->current_test_info();
        std::string testName = std::string(testInfo->test_suite_name()) + "_" + std::string(testInfo->name());
        testDir = fs::temp_directory_path() / ("kvdbioc_test_" + testName);
        fs::remove_all(testDir);
        fs::create_directories(testDir);

        // Create mock store with default behaviors
        auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();
        ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));
        ON_CALL(*mockStore, readDoc(::testing::_)).WillByDefault(::testing::Return(base::Error {"Not found"}));
        ON_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_)).WillByDefault(::testing::Return(std::nullopt));
        store = mockStore;
    }

    void TearDown() override { fs::remove_all(testDir); }

    fs::path testDir;
    std::shared_ptr<store::IStore> store;
};

// ============================================================================
// CONCURRENCY TESTS WITH PRIMITIVE API
// ============================================================================

// Test readers during hot-swap: threads reading → swap happens → threads see new data
TEST_F(KVDBComponentTest, ConcurrentReadsDuringHotSwap)
{
    kvdbioc::KVDBManager manager(testDir, store);

    // Create production DB with initial data
    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.put("production", "status", R"({"state":"initial"})"));

    const int numReaders = 10;
    std::atomic<bool> keepReading {true};
    std::atomic<int> readsVersion1 {0};
    std::atomic<int> readsVersion2 {0};
    std::vector<std::thread> readers;

    // Launch readers that continuously read from PRODUCTION
    for (int i = 0; i < numReaders; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                while (keepReading)
                {
                    EXPECT_NO_THROW({
                        auto result = manager.get("production", "status");
                        if (result.has_value())
                        {
                            auto state = result->getString("/state").value();
                            if (state == "initial")
                            {
                                readsVersion1++;
                            }
                            else if (state == "updated")
                            {
                                readsVersion2++;
                            }
                        }
                    });
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
            });
    }

    // Let readers see initial version
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Build new STAGING database with updated data
    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "status", R"({"state":"updated"})"));
    // Hot-swap: replace production's data with staging's data
    EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

    // Let readers see the new version (production handle now points to staging's data)
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    keepReading = false;
    for (auto& t : readers)
    {
        t.join();
    }

    // Should have reads from both versions
    EXPECT_GT(readsVersion1.load(), 0);
    EXPECT_GT(readsVersion2.load(), 0);
}

// Test concurrent operations on multiple databases
TEST_F(KVDBComponentTest, MultiDatabaseConcurrentOperations)
{
    kvdbioc::KVDBManager manager(testDir, store);

    const int numDBs = 5;
    const int numReadersPerDB = 3;
    std::vector<std::thread> threads;
    std::atomic<int> totalSuccesses {0};

    // Create multiple DBs
    for (int db = 0; db < numDBs; ++db)
    {
        std::string stageName = "stage-" + std::to_string(db);
        std::string dbName = "multidb-" + std::to_string(db);

        EXPECT_NO_THROW(manager.add(stageName));
        for (int i = 0; i < 50; ++i)
        {
            std::string key = "key:" + std::to_string(i);
            std::string value = R"({"db":)" + std::to_string(db) + R"(,"item":)" + std::to_string(i) + "}";
            EXPECT_NO_THROW(manager.put(stageName, key, value));
        }

        EXPECT_NO_THROW(manager.add(dbName));
        EXPECT_NO_THROW(manager.hotSwap(stageName, dbName));
    }

    // Launch readers for each DB
    for (int db = 0; db < numDBs; ++db)
    {
        std::string dbName = "multidb-" + std::to_string(db);

        for (int r = 0; r < numReadersPerDB; ++r)
        {
            threads.emplace_back(
                [&manager, &totalSuccesses, dbName, db]()
                {
                    for (int i = 0; i < 100; ++i)
                    {
                        int keyId = i % 50;
                        std::string key = "key:" + std::to_string(keyId);
                        EXPECT_NO_THROW({
                            auto result = manager.get(dbName, key);
                            if (result.has_value() && result->getInt("/db").value() == db)
                            {
                                totalSuccesses++;
                            }
                        });
                    }
                });
        }
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(totalSuccesses.load(), numDBs * numReadersPerDB * 100);
}

// Test rapid database creation and deletion
TEST_F(KVDBComponentTest, RapidCreateDeleteCycle)
{
    kvdbioc::KVDBManager manager(testDir, store);

    const int numCycles = 10;

    for (int cycle = 0; cycle < numCycles; ++cycle)
    {
        EXPECT_NO_THROW(manager.add("staging"));
        for (int i = 0; i < 20; ++i)
        {
            std::string key = "item:" + std::to_string(i);
            std::string value = R"({"cycle":)" + std::to_string(cycle) + R"(,"item":)" + std::to_string(i) + "}";
            EXPECT_NO_THROW(manager.put("staging", key, value));
        }

        EXPECT_NO_THROW(manager.add("rapid-cycle"));
        EXPECT_NO_THROW(manager.hotSwap("staging", "rapid-cycle"));

        EXPECT_NO_THROW({
            auto result = manager.get("rapid-cycle", "item:0");
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(result->getInt("/cycle").value(), cycle);
        });

        EXPECT_NO_THROW(manager.remove("rapid-cycle"));
    }
}

// Test massive parallel put operations
TEST_F(KVDBComponentTest, MassiveParallelPuts)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));

    const int numThreads = 10;
    const int putsPerThread = 100;
    std::vector<std::thread> writers;
    std::atomic<int> successfulPuts {0};

    for (int t = 0; t < numThreads; ++t)
    {
        writers.emplace_back(
            [&, threadId = t]()
            {
                for (int i = 0; i < putsPerThread; ++i)
                {
                    std::string key = "t" + std::to_string(threadId) + ":i" + std::to_string(i);
                    std::string value =
                        R"({"thread":)" + std::to_string(threadId) + R"(,"index":)" + std::to_string(i) + "}";
                    EXPECT_NO_THROW(manager.put("staging", key, value));
                    successfulPuts++;
                }
            });
    }

    for (auto& t : writers)
    {
        t.join();
    }

    EXPECT_EQ(successfulPuts.load(), numThreads * putsPerThread);

    EXPECT_NO_THROW(manager.add("massive-puts"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "massive-puts"));

    // Spot check
    EXPECT_NO_THROW({
        auto r1 = manager.get("massive-puts", "t0:i0");
        EXPECT_TRUE(r1.has_value());
        EXPECT_EQ(r1->getInt("/thread").value(), 0);
    });
    EXPECT_NO_THROW({
        auto r2 = manager.get("massive-puts", "t5:i50");
        EXPECT_TRUE(r2.has_value());
        EXPECT_EQ(r2->getInt("/thread").value(), 5);
        EXPECT_EQ(r2->getInt("/index").value(), 50);
    });
}

// Test removal works correctly
TEST_F(KVDBComponentTest, RemovalTest)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "key1", R"({"version":1})"));

    EXPECT_NO_THROW(manager.add("lifetime-test"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "lifetime-test"));

    EXPECT_NO_THROW({
        auto result = manager.get("lifetime-test", "key1");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getInt("/version").value(), 1);
    });

    EXPECT_NO_THROW(manager.remove("lifetime-test"));

    // After removal, get should throw exception for non-existent DB
    EXPECT_THROW(manager.get("lifetime-test", "key1"), std::runtime_error);
}

// Test concurrent get operations
TEST_F(KVDBComponentTest, ConcurrentGetOperations)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    for (int i = 0; i < 50; ++i)
    {
        std::string key = "item:" + std::to_string(i);
        std::string value = R"({"id":)" + std::to_string(i) + "}";
        EXPECT_NO_THROW(manager.put("staging", key, value));
    }

    EXPECT_NO_THROW(manager.add("handler-factory"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "handler-factory"));

    const int numThreads = 20;
    std::vector<std::thread> threads;
    std::atomic<int> successfulReads {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                for (int j = 0; j < 10; ++j)
                {
                    int id = j;
                    std::string key = "item:" + std::to_string(id);
                    EXPECT_NO_THROW({
                        auto result = manager.get("handler-factory", key);
                        if (result.has_value() && result->getInt("/id").value() == id)
                        {
                            successfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(successfulReads.load(), numThreads * 10);
}

// Test error handling under concurrency
TEST_F(KVDBComponentTest, ConcurrentErrorHandling)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "existing", R"({"data":"value"})"));

    EXPECT_NO_THROW(manager.add("error-test"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "error-test"));

    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> nulloptReturns {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, threadId = i]()
            {
                for (int j = 0; j < 5; ++j)
                {
                    std::string key = "nonexistent:" + std::to_string(threadId);
                    EXPECT_NO_THROW({
                        auto result = manager.get("error-test", key);
                        if (!result.has_value())
                        {
                            nulloptReturns++;
                        }
                    });
                }

                EXPECT_NO_THROW({
                    auto result = manager.get("error-test", "existing");
                    EXPECT_TRUE(result.has_value());
                    EXPECT_TRUE(result->isObject());
                });
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(nulloptReturns.load(), numThreads * 5);
}

// Test concurrent reads with multiget
TEST_F(KVDBComponentTest, ConcurrentMultigetOperations)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    for (int i = 0; i < 50; ++i)
    {
        std::string key = "item:" + std::to_string(i);
        std::string value = R"({"value":)" + std::to_string(i) + "}";
        EXPECT_NO_THROW(manager.put("staging", key, value));
    }

    EXPECT_NO_THROW(manager.add("concurrent-db"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "concurrent-db"));

    const int numThreads = 5;
    const int opsPerThread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> successfulReads {0};

    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&manager, &successfulReads, opsPerThread]()
            {
                for (int i = 0; i < opsPerThread; ++i)
                {
                    int key = i % 50;
                    std::string keyStr = "item:" + std::to_string(key);

                    EXPECT_NO_THROW({
                        auto result = manager.get("concurrent-db", keyStr);
                        if (result.has_value() && result->getInt("/value").value() == key)
                        {
                            successfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successfulReads.load(), numThreads * opsPerThread);
}

// Test concurrent multiget operations
TEST_F(KVDBComponentTest, ConcurrentMultigetBatch)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "config:timeout", R"({"value":30})"));
    EXPECT_NO_THROW(manager.put("staging", "config:retries", R"({"value":5})"));

    EXPECT_NO_THROW(manager.add("shared-db"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "shared-db"));

    const int numThreads = 5;
    std::vector<std::thread> threads;
    std::atomic<int> totalSuccessfulReads {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&manager, &totalSuccessfulReads]()
            {
                for (int j = 0; j < 20; ++j)
                {
                    std::vector<std::string_view> keys = {"config:timeout", "config:retries"};
                    EXPECT_NO_THROW({
                        auto results = manager.multiGet("shared-db", keys);
                        if (results.size() == 2 && results[0].has_value() && results[1].has_value()
                            && results[0]->getInt("/value").value() == 30 && results[1]->getInt("/value").value() == 5)
                        {
                            totalSuccessfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(totalSuccessfulReads.load(), numThreads * 20);
}

// Test thread-safe concurrent access
TEST_F(KVDBComponentTest, ThreadSafeConcurrentAccess)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "item:1", R"({"value":"data"})"));

    EXPECT_NO_THROW(manager.add("destruction-db"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "destruction-db"));

    std::atomic<int> successfulReads {0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back(
            [&manager, &successfulReads]()
            {
                for (int j = 0; j < 20; ++j)
                {
                    EXPECT_NO_THROW({
                        auto result = manager.get("destruction-db", "item:1");
                        if (result.has_value())
                        {
                            successfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successfulReads.load(), 5 * 20);
}

// ============================================================================
// ADVANCED HOT-SWAP AND CONCURRENCY TESTS
// ============================================================================

// Test hot-swap from staging to production (different DBs)
TEST_F(KVDBComponentTest, HotSwapBetweenDifferentDatabases)
{
    kvdbioc::KVDBManager manager(testDir, store);

    // Create initial production
    EXPECT_NO_THROW(manager.add("initial"));
    EXPECT_NO_THROW(manager.put("initial", "version", R"({"number":1})"));
    EXPECT_NO_THROW(manager.put("initial", "config", R"({"timeout":30})"));

    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.hotSwap("initial", "production"));

    // Launch readers to verify initial state
    std::atomic<int> readsV1 {0};
    std::atomic<bool> keepReading {true};
    std::vector<std::thread> readers;

    for (int i = 0; i < 5; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                while (keepReading)
                {
                    EXPECT_NO_THROW({
                        auto v = manager.get("production", "version");
                        if (v.has_value() && v->getInt("/number").value() == 1)
                            readsV1++;
                    });
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
            });
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Build new version in staging
    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "version", R"({"number":2})"));
    EXPECT_NO_THROW(manager.put("staging", "config", R"({"timeout":60})"));
    EXPECT_NO_THROW(manager.put("staging", "new-feature", R"({"enabled":true})"));

    // Hot-swap: move staging data to production
    EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

    keepReading = false;
    for (auto& t : readers) t.join();

    EXPECT_GT(readsV1.load(), 0);

    // Verify with multiple threads
    std::atomic<int> successfulChecks {0};
    std::vector<std::thread> verifiers;

    for (int i = 0; i < 10; ++i)
    {
        verifiers.emplace_back(
            [&]()
            {
                EXPECT_NO_THROW({
                    auto v2 = manager.get("production", "version");
                    auto config = manager.get("production", "config");
                    auto feature = manager.get("production", "new-feature");

                    if (v2.has_value() && v2->getInt("/number").value() == 2 && config.has_value()
                        && config->getInt("/timeout").value() == 60 && feature.has_value()
                        && feature->getBool("/enabled").value())
                    {
                        successfulChecks++;
                    }
                });
            });
    }

    for (auto& t : verifiers) t.join();
    EXPECT_EQ(successfulChecks.load(), 10);
}

// Test reading from staging BEFORE hot-swap (DB is immediately queryable)
TEST_F(KVDBComponentTest, ReadFromStagingBeforeHotSwap)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "key1", R"({"value":"data1"})"));
    EXPECT_NO_THROW(manager.put("staging", "key2", R"({"value":"data2"})"));

    // Multiple threads reading while populating
    std::atomic<int> successfulReads {0};
    std::vector<std::thread> readers;

    for (int i = 0; i < 8; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                for (int j = 0; j < 10; ++j)
                {
                    EXPECT_NO_THROW({
                        auto r1 = manager.get("staging", "key1");
                        auto r2 = manager.get("staging", "key2");

                        if (r1.has_value() && r1->getString("/value").value() == "data1" && r2.has_value()
                            && r2->getString("/value").value() == "data2")
                        {
                            successfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& t : readers) t.join();
    EXPECT_EQ(successfulReads.load(), 80);

    // Now hot-swap to production
    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

    // Multiple threads verifying production
    successfulReads = 0;
    readers.clear();

    for (int i = 0; i < 8; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                for (int j = 0; j < 10; ++j)
                {
                    EXPECT_NO_THROW({
                        auto r3 = manager.get("production", "key1");
                        if (r3.has_value() && r3->getString("/value").value() == "data1")
                        {
                            successfulReads++;
                        }
                    });
                }
            });
    }

    for (auto& t : readers) t.join();
    EXPECT_EQ(successfulReads.load(), 80);
}

// Test multiple consecutive hot-swaps
TEST_F(KVDBComponentTest, MultipleConsecutiveHotSwaps)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("initial"));
    EXPECT_NO_THROW(manager.put("initial", "counter", R"({"value":1})"));

    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.hotSwap("initial", "production"));

    for (int i = 2; i <= 5; ++i)
    {
        EXPECT_NO_THROW(manager.add("staging"));
        EXPECT_NO_THROW(manager.put("staging", "counter", R"({"value":)" + std::to_string(i) + "}"));

        // Launch readers while building
        std::atomic<bool> keepReading {true};
        std::atomic<int> correctReads {0};
        std::vector<std::thread> readers;

        for (int t = 0; t < 5; ++t)
        {
            readers.emplace_back(
                [&, expected = i - 1]()
                {
                    while (keepReading)
                    {
                        EXPECT_NO_THROW({
                            auto r = manager.get("production", "counter");
                            if (r.has_value() && r->getInt("/value").value() == expected)
                            {
                                correctReads++;
                            }
                        });
                        std::this_thread::sleep_for(std::chrono::microseconds(50));
                    }
                });
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        EXPECT_NO_THROW(manager.hotSwap("staging", "production"));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));

        keepReading = false;
        for (auto& t : readers) t.join();

        EXPECT_GT(correctReads.load(), 0);

        EXPECT_NO_THROW({
            auto result = manager.get("production", "counter");
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(result->getInt("/value").value(), i);
        });
    }
}

// Test hot-swap with empty database
TEST_F(KVDBComponentTest, HotSwapWithEmptyDatabase)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("initial"));
    EXPECT_NO_THROW(manager.put("initial", "key1", R"({"data":"value"})"));

    EXPECT_NO_THROW(manager.add("filled"));
    EXPECT_NO_THROW(manager.hotSwap("initial", "filled"));

    // Multiple threads verify data exists
    std::atomic<int> foundCount {0};
    std::vector<std::thread> readers;

    for (int i = 0; i < 6; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                EXPECT_NO_THROW({
                    auto before = manager.get("filled", "key1");
                    if (before.has_value())
                        foundCount++;
                });
            });
    }
    for (auto& t : readers) t.join();
    EXPECT_EQ(foundCount.load(), 6);

    // Create empty staging and swap
    EXPECT_NO_THROW(manager.add("empty"));
    EXPECT_NO_THROW(manager.hotSwap("empty", "filled"));

    // Multiple threads verify data is gone
    std::atomic<int> notFoundCount {0};
    readers.clear();

    for (int i = 0; i < 6; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                EXPECT_NO_THROW({
                    auto after = manager.get("filled", "key1");
                    if (!after.has_value())
                        notFoundCount++;
                });
            });
    }
    for (auto& t : readers) t.join();
    EXPECT_EQ(notFoundCount.load(), 6);
}

// Test multiget with mixed existing and non-existing keys
TEST_F(KVDBComponentTest, MultigetWithMixedKeys)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "exists1", R"({"value":1})"));
    EXPECT_NO_THROW(manager.put("staging", "exists2", R"({"value":2})"));

    EXPECT_NO_THROW(manager.add("testdb"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "testdb"));

    std::vector<std::string_view> keys = {"exists1", "nonexistent1", "exists2", "nonexistent2"};
    EXPECT_NO_THROW({
        auto results = manager.multiGet("testdb", keys);
        ASSERT_EQ(results.size(), 4);
        EXPECT_TRUE(results[0].has_value());
        EXPECT_EQ(results[0]->getInt("/value").value(), 1);
        EXPECT_FALSE(results[1].has_value());
        EXPECT_TRUE(results[2].has_value());
        EXPECT_EQ(results[2]->getInt("/value").value(), 2);
        EXPECT_FALSE(results[3].has_value());
    });
}

// Test concurrent readers on source DB during hot-swap
// Note: After hotSwap(source, target), source loses its instance (moved to target)
TEST_F(KVDBComponentTest, ReadersOnSourceDuringHotSwap)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("source"));
    EXPECT_NO_THROW(manager.put("source", "data", R"({"value":"source-data"})"));

    std::atomic<bool> keepReading {true};
    std::atomic<int> successfulReads {0};
    std::atomic<int> failedReads {0};

    // Launch readers on source
    std::thread reader(
        [&]()
        {
            while (keepReading)
            {
                try
                {
                    auto result = manager.get("source", "data");
                    if (result.has_value())
                    {
                        successfulReads++;
                    }
                }
                catch (const std::runtime_error&)
                {
                    // After hotSwap, source has no instance - expected
                    failedReads++;
                }
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Perform hot-swap to target while readers are active
    EXPECT_NO_THROW(manager.add("target"));
    EXPECT_NO_THROW(manager.put("target", "data", R"({"value":"target-data"})"));

    std::thread swapper([&]() { EXPECT_NO_THROW(manager.hotSwap("source", "target")); });

    swapper.join();

    // Verify target has the source data (not original target data)
    EXPECT_NO_THROW({
        auto targetResult = manager.get("target", "data");
        EXPECT_TRUE(targetResult.has_value());
        EXPECT_EQ(targetResult->getString("/value").value(), "source-data");
    });

    // Verify source is NO LONGER readable (instance moved to target)
    EXPECT_THROW({ manager.get("source", "data"); }, std::runtime_error);

    keepReading = false;
    reader.join();

    // Should have some successful reads BEFORE swap, and failures AFTER swap
    EXPECT_GT(successfulReads.load(), 0);
    EXPECT_GT(failedReads.load(), 0);
}

// Test attempting to remove DB while it has active operations
TEST_F(KVDBComponentTest, CannotRemoveDatabaseDuringOperations)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "key", R"({"value":"data"})"));

    EXPECT_NO_THROW(manager.add("busy-db"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "busy-db"));

    std::atomic<bool> keepReading {true};
    std::atomic<int> successfulReads {0};
    std::thread reader(
        [&]()
        {
            while (keepReading)
            {
                try
                {
                    manager.get("busy-db", "key");
                    successfulReads++;
                }
                catch (const std::runtime_error&)
                {
                    // Expected after remove() is called
                }
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Attempting to remove while reader is active should succeed
    // (removal only fails if handlers exist, not during concurrent reads)
    EXPECT_NO_THROW(manager.remove("busy-db"));

    keepReading = false;
    reader.join();

    // Verify that some reads succeeded before removal
    EXPECT_GT(successfulReads.load(), 0);

    // After removal, database should not exist
    EXPECT_THROW(manager.get("busy-db", "key"), std::runtime_error);
}

// Test hot-swap while another DB is being written
TEST_F(KVDBComponentTest, HotSwapWhileAnotherDBIsBeingWritten)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging1"));
    EXPECT_NO_THROW(manager.put("staging1", "key", R"({"value":1})"));

    EXPECT_NO_THROW(manager.add("db1"));
    EXPECT_NO_THROW(manager.hotSwap("staging1", "db1"));

    EXPECT_NO_THROW(manager.add("db2"));

    std::atomic<bool> keepWriting {true};
    std::thread writer(
        [&]()
        {
            int counter = 0;
            while (keepWriting)
            {
                EXPECT_NO_THROW(manager.put("db2", "item:" + std::to_string(counter++), R"({"data":"value"})"));
                std::this_thread::sleep_for(std::chrono::microseconds(100));
            }
        });

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Hot-swap db1 while db2 is being written
    EXPECT_NO_THROW(manager.add("staging2"));
    EXPECT_NO_THROW(manager.put("staging2", "key", R"({"value":2})"));
    EXPECT_NO_THROW(manager.hotSwap("staging2", "db1"));

    EXPECT_NO_THROW({
        auto result = manager.get("db1", "key");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getInt("/value").value(), 2);
    });

    keepWriting = false;
    writer.join();

    // db2 should be readable
    EXPECT_NO_THROW({
        auto db2Result = manager.get("db2", "item:0");
        EXPECT_TRUE(db2Result.has_value());
    });
}

// Test rapid hot-swaps between staging and production
TEST_F(KVDBComponentTest, RapidHotSwapsBetweenTwoDatabases)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    EXPECT_NO_THROW(manager.put("staging", "version", R"({"number":1})"));

    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

    for (int i = 2; i <= 10; ++i)
    {
        EXPECT_NO_THROW(manager.add("staging"));
        EXPECT_NO_THROW(manager.put("staging", "version", R"({"number":)" + std::to_string(i) + "}"));
        EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

        EXPECT_NO_THROW({
            auto result = manager.get("production", "version");
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(result->getInt("/number").value(), i);
        });
    }
}

// Test multiget performance with large key sets
TEST_F(KVDBComponentTest, MultigetWithLargeKeySet)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("staging"));
    const int numKeys = 100;
    for (int i = 0; i < numKeys; ++i)
    {
        std::string key = "key:" + std::to_string(i);
        std::string value = R"({"index":)" + std::to_string(i) + "}";
        EXPECT_NO_THROW(manager.put("staging", key, value));
    }

    EXPECT_NO_THROW(manager.add("large-db"));
    EXPECT_NO_THROW(manager.hotSwap("staging", "large-db"));

    std::vector<std::string> keyStrings;
    std::vector<std::string_view> keys;
    for (int i = 0; i < numKeys; i += 2)
    {
        keyStrings.push_back("key:" + std::to_string(i));
    }
    for (const auto& k : keyStrings)
    {
        keys.push_back(k);
    }

    EXPECT_NO_THROW({
        auto results = manager.multiGet("large-db", keys);
        ASSERT_EQ(results.size(), numKeys / 2);
        for (size_t i = 0; i < results.size(); ++i)
        {
            EXPECT_TRUE(results[i].has_value());
            EXPECT_EQ(results[i]->getInt("/index").value(), static_cast<int>(i * 2));
        }
    });
}

// Test hot-swap chain: A -> B, B -> C
TEST_F(KVDBComponentTest, HotSwapChain)
{
    kvdbioc::KVDBManager manager(testDir, store);

    // Create A
    EXPECT_NO_THROW(manager.add("dbA"));
    EXPECT_NO_THROW(manager.put("dbA", "data", R"({"source":"A"})"));

    // Create B and swap A into B
    EXPECT_NO_THROW(manager.add("dbB"));
    EXPECT_NO_THROW(manager.put("dbB", "temp", R"({"value":"temp"})"));
    EXPECT_NO_THROW(manager.hotSwap("dbA", "dbB"));

    EXPECT_NO_THROW({
        auto bResult = manager.get("dbB", "data");
        EXPECT_TRUE(bResult.has_value());
        EXPECT_EQ(bResult->getString("/source").value(), "A");
    });

    // Create C and swap B into C
    // Note: After the first swap, dbB has a published instance but no build state
    // So we need to create new data in dbB before we can swap it to dbC
    EXPECT_NO_THROW(manager.put("dbB", "data", R"({"source":"A"})"));

    EXPECT_NO_THROW(manager.add("dbC"));
    EXPECT_NO_THROW(manager.hotSwap("dbB", "dbC"));

    EXPECT_NO_THROW({
        auto cResult = manager.get("dbC", "data");
        EXPECT_TRUE(cResult.has_value());
        EXPECT_EQ(cResult->getString("/source").value(), "A");
    });
}

// Test concurrent hot-swaps on different databases
TEST_F(KVDBComponentTest, ConcurrentHotSwapsOnDifferentDatabases)
{
    kvdbioc::KVDBManager manager(testDir, store);

    const int numDBs = 5;

    // Create initial production DBs
    for (int i = 0; i < numDBs; ++i)
    {
        std::string stageName = "init-" + std::to_string(i);
        std::string prodName = "prod-" + std::to_string(i);

        EXPECT_NO_THROW(manager.add(stageName));
        EXPECT_NO_THROW(manager.put(stageName, "version", R"({"number":1})"));

        EXPECT_NO_THROW(manager.add(prodName));
        EXPECT_NO_THROW(manager.hotSwap(stageName, prodName));
    }

    std::vector<std::thread> swappers;

    // Perform concurrent hot-swaps using staging DBs
    for (int i = 0; i < numDBs; ++i)
    {
        swappers.emplace_back(
            [&, i]()
            {
                std::string prodName = "prod-" + std::to_string(i);
                for (int v = 2; v <= 5; ++v)
                {
                    std::string stageName = "stage-" + std::to_string(i) + "-v" + std::to_string(v);
                    EXPECT_NO_THROW(manager.add(stageName));
                    EXPECT_NO_THROW(manager.put(stageName, "version", R"({"number":)" + std::to_string(v) + "}"));
                    EXPECT_NO_THROW(manager.hotSwap(stageName, prodName));
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            });
    }

    for (auto& t : swappers)
    {
        t.join();
    }

    // Verify final versions in production DBs
    for (int i = 0; i < numDBs; ++i)
    {
        std::string prodName = "prod-" + std::to_string(i);
        EXPECT_NO_THROW({
            auto result = manager.get(prodName, "version");
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(result->getInt("/number").value(), 5);
        });
    }
}

// Test multiget on non-existent database
TEST_F(KVDBComponentTest, MultigetOnNonExistentDatabase)
{
    kvdbioc::KVDBManager manager(testDir, store);

    std::vector<std::string_view> keys = {"key1", "key2"};

    // Should throw exception for non-existent DB
    EXPECT_THROW(manager.multiGet("nonexistent", keys), std::runtime_error);
}

// Test that source DB becomes unusable after hot-swap
TEST_F(KVDBComponentTest, SourceDatabaseAfterHotSwap)
{
    kvdbioc::KVDBManager manager(testDir, store);

    EXPECT_NO_THROW(manager.add("source"));
    EXPECT_NO_THROW(manager.put("source", "key", R"({"value":"original"})"));

    EXPECT_NO_THROW(manager.add("target"));
    EXPECT_NO_THROW(manager.hotSwap("source", "target"));

    // Multiple threads trying to put to source should fail
    std::atomic<int> exceptions {0};
    std::vector<std::thread> writers;

    for (int i = 0; i < 8; ++i)
    {
        writers.emplace_back(
            [&, id = i]()
            {
                try
                {
                    manager.put("source", "new-key-" + std::to_string(id), R"({"value":"new"})");
                }
                catch (const std::runtime_error&)
                {
                    exceptions++;
                }
            });
    }

    for (auto& t : writers) t.join();
    EXPECT_EQ(exceptions.load(), 8);

    // Multiple threads verify target has the data
    std::atomic<int> correctReads {0};
    std::vector<std::thread> readers;

    for (int i = 0; i < 10; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                EXPECT_NO_THROW({
                    auto result = manager.get("target", "key");
                    if (result.has_value() && result->getString("/value").value() == "original")
                    {
                        correctReads++;
                    }
                });
            });
    }

    for (auto& t : readers) t.join();
    EXPECT_EQ(correctReads.load(), 10);
}

// Test stress: rapid operations on same database
TEST_F(KVDBComponentTest, StressTestRapidOperations)
{
    kvdbioc::KVDBManager manager(testDir, store);

    const int numIterations = 50;

    // Create initial production
    EXPECT_NO_THROW(manager.add("init"));
    EXPECT_NO_THROW(manager.put("init", "key:0", R"({"iteration":0,"item":0})"));

    EXPECT_NO_THROW(manager.add("production"));
    EXPECT_NO_THROW(manager.hotSwap("init", "production"));

    for (int i = 1; i < numIterations; ++i)
    {
        EXPECT_NO_THROW(manager.add("staging"));

        for (int j = 0; j < 10; ++j)
        {
            std::string key = "key:" + std::to_string(j);
            std::string value = R"({"iteration":)" + std::to_string(i) + R"(,"item":)" + std::to_string(j) + "}";
            EXPECT_NO_THROW(manager.put("staging", key, value));
        }

        // Read during build from staging
        EXPECT_NO_THROW({
            auto buildRead = manager.get("staging", "key:5");
            EXPECT_TRUE(buildRead.has_value());
        });

        EXPECT_NO_THROW(manager.hotSwap("staging", "production"));

        // Verify production has new data
        EXPECT_NO_THROW({
            auto result = manager.get("production", "key:5");
            EXPECT_TRUE(result.has_value());
            EXPECT_EQ(result->getInt("/iteration").value(), i);
        });
    }
}

// ============================================================================
// PERSISTENCE TESTS
// ============================================================================

// Test state is saved after add
TEST_F(KVDBComponentTest, PersistenceAfterAdd)
{
    std::shared_ptr<json::Json> capturedState;
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    // Capture what gets saved
    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_))
        .WillRepeatedly(
            ::testing::DoAll(::testing::Invoke([&capturedState](const base::Name&, const json::Json& j)
                                               { capturedState = std::make_shared<json::Json>(j.str().c_str()); }),
                             ::testing::Return(std::nullopt)));

    ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));

    {
        kvdbioc::KVDBManager manager(testDir, mockStore);
        EXPECT_NO_THROW(manager.add("testdb"));
        EXPECT_NO_THROW(manager.put("testdb", "key1", R"({"value":"data"})"));
    }

    // Verify state was saved with correct structure
    ASSERT_NE(capturedState, nullptr);
    EXPECT_TRUE(capturedState->isArray());
    auto arr = capturedState->getArray();
    EXPECT_TRUE(arr.has_value());
    EXPECT_EQ(arr->size(), 1);

    auto dbState = (*arr)[0];
    EXPECT_EQ(dbState.getString("/name").value(), "testdb");
    EXPECT_TRUE(dbState.exists("/instance_path"));
    EXPECT_TRUE(dbState.exists("/created"));
}

// Test state is loaded on manager restart
TEST_F(KVDBComponentTest, PersistenceLoadStateOnRestart)
{
    std::shared_ptr<json::Json> savedState;
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    // First manager - create DB and capture state
    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_))
        .WillRepeatedly(
            ::testing::DoAll(::testing::Invoke([&savedState](const base::Name&, const json::Json& j)
                                               { savedState = std::make_shared<json::Json>(j.str().c_str()); }),
                             ::testing::Return(std::nullopt)));

    ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));

    {
        kvdbioc::KVDBManager manager(testDir, mockStore);
        EXPECT_NO_THROW(manager.add("persistent-db"));
        EXPECT_NO_THROW(manager.put("persistent-db", "key1", R"({"value":"original"})"));

        // Verify data exists
        auto result = manager.get("persistent-db", "key1");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getString("/value").value(), "original");
    }

    ASSERT_NE(savedState, nullptr);

    // Second manager - restore from saved state
    EXPECT_CALL(*mockStore, existsDoc(::testing::_)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockStore, readDoc(::testing::_)).WillOnce(::testing::Return(*savedState));

    {
        kvdbioc::KVDBManager manager(testDir, mockStore);

        // Should be able to read data from restored DB
        auto result = manager.get("persistent-db", "key1");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getString("/value").value(), "original");

        // Should be able to write to restored DB
        EXPECT_NO_THROW(manager.put("persistent-db", "key2", R"({"value":"new"})"));

        auto newResult = manager.get("persistent-db", "key2");
        EXPECT_TRUE(newResult.has_value());
        EXPECT_EQ(newResult->getString("/value").value(), "new");
    }
}

// Test state is updated after hotSwap
TEST_F(KVDBComponentTest, PersistenceAfterHotSwap)
{
    std::vector<std::shared_ptr<json::Json>> savedStates;
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    // Capture all state saves
    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_))
        .WillRepeatedly(::testing::DoAll(
            ::testing::Invoke([&savedStates](const base::Name&, const json::Json& j)
                              { savedStates.push_back(std::make_shared<json::Json>(j.str().c_str())); }),
            ::testing::Return(std::nullopt)));

    ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));

    {
        kvdbioc::KVDBManager manager(testDir, mockStore);

        // Create staging and target
        EXPECT_NO_THROW(manager.add("staging"));
        EXPECT_NO_THROW(manager.put("staging", "key1", R"({"value":"staged"})"));
        EXPECT_NO_THROW(manager.add("target"));

        // Perform hot-swap
        EXPECT_NO_THROW(manager.hotSwap("staging", "target"));
    }

    // Verify final state has only target (source was removed)
    EXPECT_FALSE(savedStates.empty());
    auto finalState = savedStates.back();

    EXPECT_TRUE(finalState->isArray());
    auto arr = finalState->getArray();
    EXPECT_TRUE(arr.has_value());

    // Should only have target DB, staging should be removed
    EXPECT_EQ(arr->size(), 1);
    EXPECT_EQ((*arr)[0].getString("/name").value(), "target");
}

// Test state is updated after remove
TEST_F(KVDBComponentTest, PersistenceAfterRemove)
{
    std::shared_ptr<json::Json> finalState;
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_))
        .WillRepeatedly(
            ::testing::DoAll(::testing::Invoke([&finalState](const base::Name&, const json::Json& j)
                                               { finalState = std::make_shared<json::Json>(j.str().c_str()); }),
                             ::testing::Return(std::nullopt)));

    ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));

    {
        kvdbioc::KVDBManager manager(testDir, mockStore);

        // Create two DBs
        EXPECT_NO_THROW(manager.add("db1"));
        EXPECT_NO_THROW(manager.add("db2"));

        // Remove one
        EXPECT_NO_THROW(manager.remove("db1"));
    }

    // Verify state only has db2
    ASSERT_NE(finalState, nullptr);
    EXPECT_TRUE(finalState->isArray());
    auto arr = finalState->getArray();
    EXPECT_TRUE(arr.has_value());
    EXPECT_EQ(arr->size(), 1);
    EXPECT_EQ((*arr)[0].getString("/name").value(), "db2");
}

// Test manager handles missing persisted DB files gracefully
TEST_F(KVDBComponentTest, PersistenceHandlesMissingFiles)
{
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    // Create corrupted state pointing to non-existent path
    json::Json corruptedState;
    corruptedState.setArray();
    json::Json dbEntry;
    dbEntry.setString("missing-db", "/name");
    dbEntry.setString("non-existent/path", "/instance_path");
    dbEntry.setInt64(123456789, "/created");
    corruptedState.appendJson(dbEntry);

    EXPECT_CALL(*mockStore, existsDoc(::testing::_)).WillOnce(::testing::Return(true));
    EXPECT_CALL(*mockStore, readDoc(::testing::_)).WillOnce(::testing::Return(corruptedState));
    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_)).WillRepeatedly(::testing::Return(std::nullopt));

    // Manager should start without crashing
    EXPECT_NO_THROW({
        kvdbioc::KVDBManager manager(testDir, mockStore);

        // The DB handle exists but has no instance
        // Trying to read should fail
        EXPECT_THROW(manager.get("missing-db", "key1"), std::runtime_error);
    });
}

// Test persistence survives multiple restart cycles
TEST_F(KVDBComponentTest, PersistenceMultipleRestarts)
{
    std::shared_ptr<json::Json> persistedState;
    auto mockStore = std::make_shared<::testing::NiceMock<store::mocks::MockStore>>();

    EXPECT_CALL(*mockStore, upsertDoc(::testing::_, ::testing::_))
        .WillRepeatedly(
            ::testing::DoAll(::testing::Invoke([&persistedState](const base::Name&, const json::Json& j)
                                               { persistedState = std::make_shared<json::Json>(j.str().c_str()); }),
                             ::testing::Return(std::nullopt)));

    // First manager - create initial DB
    {
        ON_CALL(*mockStore, existsDoc(::testing::_)).WillByDefault(::testing::Return(false));

        kvdbioc::KVDBManager manager(testDir, mockStore);
        EXPECT_NO_THROW(manager.add("cycle-db"));
        EXPECT_NO_THROW(manager.put("cycle-db", "counter", R"({"value":1})"));
    }

    ASSERT_NE(persistedState, nullptr);

    // Second restart - read and update
    {
        EXPECT_CALL(*mockStore, existsDoc(::testing::_)).WillOnce(::testing::Return(true));
        EXPECT_CALL(*mockStore, readDoc(::testing::_)).WillOnce(::testing::Return(*persistedState));

        kvdbioc::KVDBManager manager(testDir, mockStore);
        auto result = manager.get("cycle-db", "counter");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getInt("/value").value(), 1);

        EXPECT_NO_THROW(manager.put("cycle-db", "counter", R"({"value":2})"));
    }

    // Third restart - verify persistence again
    {
        EXPECT_CALL(*mockStore, existsDoc(::testing::_)).WillOnce(::testing::Return(true));
        EXPECT_CALL(*mockStore, readDoc(::testing::_)).WillOnce(::testing::Return(*persistedState));

        kvdbioc::KVDBManager manager(testDir, mockStore);
        auto result = manager.get("cycle-db", "counter");
        EXPECT_TRUE(result.has_value());
        EXPECT_EQ(result->getInt("/value").value(), 2);
    }
}
