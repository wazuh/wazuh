#include <atomic>
#include <chrono>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include <kvdbioc/iReadOnlyHandler.hpp>
#include <kvdbioc/manager.hpp>

namespace fs = std::filesystem;

// Component/Integration tests for full KVDB workflow
class KVDBComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        testDir = fs::temp_directory_path() / "kvdbioc_component_test";
        fs::remove_all(testDir);
        fs::create_directories(testDir);
    }

    void TearDown() override { fs::remove_all(testDir); }

    fs::path testDir;
};

// ============================================================================
// CONCURRENCY TESTS WITH PRIMITIVE API
// ============================================================================

// Test readers during hot-swap: threads reading → swap happens → threads see new data
TEST_F(KVDBComponentTest, ConcurrentReadsDuringHotSwap)
{
    kvdb::KVDBManager manager(testDir);

    // Create initial version with data
    manager.add("swap-test");
    manager.put("swap-test", "status", R"({"state":"initial"})");
    manager.hotSwap("swap-test");

    const int numReaders = 10;
    std::atomic<bool> keepReading {true};
    std::atomic<int> readsVersion1 {0};
    std::atomic<int> readsVersion2 {0};
    std::vector<std::thread> readers;

    // Launch readers that continuously read from same DB
    for (int i = 0; i < numReaders; ++i)
    {
        readers.emplace_back(
            [&]()
            {
                auto handler = manager.openReadOnly("swap-test");

                while (keepReading)
                {
                    try
                    {
                        auto result = handler->get("status");
                        auto state = result.getString("/state").value();

                        if (state == "initial")
                        {
                            readsVersion1++;
                        }
                        else if (state == "updated")
                        {
                            readsVersion2++;
                        }
                    }
                    catch (const std::exception&)
                    {
                        // Ignore errors during transition
                    }
                    std::this_thread::sleep_for(std::chrono::microseconds(100));
                }
            });
    }

    // Let readers see initial version
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Now build and hot-swap new version ON THE SAME DB
    manager.add("swap-test");
    manager.put("swap-test", "status", R"({"state":"updated"})");
    manager.hotSwap("swap-test");

    // Let readers see the new version (they share same DbHandle)
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
    kvdb::KVDBManager manager(testDir);

    const int numDBs = 5;
    const int numReadersPerDB = 3;
    std::vector<std::thread> threads;
    std::atomic<int> totalSuccesses {0};

    // Create multiple DBs
    for (int db = 0; db < numDBs; ++db)
    {
        std::string dbName = "multidb-" + std::to_string(db);

        manager.add(dbName);
        for (int i = 0; i < 50; ++i)
        {
            std::string key = "key:" + std::to_string(i);
            std::string value = R"({"db":)" + std::to_string(db) + R"(,"item":)" + std::to_string(i) + "}";
            manager.put(dbName, key, value);
        }
        manager.hotSwap(dbName);
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
                    auto handler = manager.openReadOnly(dbName);

                    for (int i = 0; i < 100; ++i)
                    {
                        int keyId = i % 50;
                        std::string key = "key:" + std::to_string(keyId);
                        auto result = handler->get(key);

                        if (result.getInt("/db").value() == db)
                        {
                            totalSuccesses++;
                        }
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
    kvdb::KVDBManager manager(testDir);

    const int numCycles = 10;

    for (int cycle = 0; cycle < numCycles; ++cycle)
    {
        manager.add("rapid-cycle");
        for (int i = 0; i < 20; ++i)
        {
            std::string key = "item:" + std::to_string(i);
            std::string value = R"({"cycle":)" + std::to_string(cycle) + R"(,"item":)" + std::to_string(i) + "}";
            manager.put("rapid-cycle", key, value);
        }
        manager.hotSwap("rapid-cycle");

        auto handler = manager.openReadOnly("rapid-cycle");
        auto result = handler->get("item:0");
        EXPECT_EQ(result.getInt("/cycle").value(), cycle);

        handler.reset();
        manager.remove("rapid-cycle");
    }
}

// Test massive parallel put operations
TEST_F(KVDBComponentTest, MassiveParallelPuts)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("massive-puts");

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
                    manager.put("massive-puts", key, value);
                    successfulPuts++;
                }
            });
    }

    for (auto& t : writers)
    {
        t.join();
    }

    EXPECT_EQ(successfulPuts.load(), numThreads * putsPerThread);

    manager.hotSwap("massive-puts");

    auto handler = manager.openReadOnly("massive-puts");

    // Spot check
    auto r1 = handler->get("t0:i0");
    EXPECT_EQ(r1.getInt("/thread").value(), 0);

    auto r2 = handler->get("t5:i50");
    EXPECT_EQ(r2.getInt("/thread").value(), 5);
    EXPECT_EQ(r2.getInt("/index").value(), 50);
}

// Test handler lifetime across operations
TEST_F(KVDBComponentTest, HandlerLifetimeStress)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("lifetime-test");
    manager.put("lifetime-test", "key1", R"({"version":1})");
    manager.hotSwap("lifetime-test");

    // Create 20 handlers
    std::vector<std::shared_ptr<kvdb::IReadOnlyKVDBHandler>> handlers;
    for (int i = 0; i < 20; ++i)
    {
        handlers.push_back(manager.openReadOnly("lifetime-test"));
    }

    for (auto& handler : handlers)
    {
        auto result = handler->get("key1");
        EXPECT_EQ(result.getInt("/version").value(), 1);
    }

    EXPECT_THROW(manager.remove("lifetime-test"), std::runtime_error);

    handlers.clear();

    EXPECT_NO_THROW(manager.remove("lifetime-test"));
}

// Test concurrent handler creation
TEST_F(KVDBComponentTest, ConcurrentHandlerCreation)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("handler-factory");
    for (int i = 0; i < 50; ++i)
    {
        std::string key = "item:" + std::to_string(i);
        std::string value = R"({"id":)" + std::to_string(i) + "}";
        manager.put("handler-factory", key, value);
    }
    manager.hotSwap("handler-factory");

    const int numThreads = 20;
    std::vector<std::thread> threads;
    std::atomic<int> successfulReads {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&]()
            {
                auto handler = manager.openReadOnly("handler-factory");

                for (int j = 0; j < 10; ++j)
                {
                    int id = j;
                    std::string key = "item:" + std::to_string(id);
                    auto result = handler->get(key);
                    if (result.getInt("/id").value() == id)
                    {
                        successfulReads++;
                    }
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
    kvdb::KVDBManager manager(testDir);

    manager.add("error-test");
    manager.put("error-test", "existing", R"({"data":"value"})");
    manager.hotSwap("error-test");

    const int numThreads = 10;
    std::vector<std::thread> threads;
    std::atomic<int> expectedErrors {0};

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, threadId = i]()
            {
                auto handler = manager.openReadOnly("error-test");

                for (int j = 0; j < 5; ++j)
                {
                    try
                    {
                        std::string key = "nonexistent:" + std::to_string(threadId);
                        handler->get(key);
                    }
                    catch (const std::runtime_error&)
                    {
                        expectedErrors++;
                    }
                }

                auto result = handler->get("existing");
                EXPECT_TRUE(result.isObject());
            });
    }

    for (auto& t : threads)
    {
        t.join();
    }

    EXPECT_EQ(expectedErrors.load(), numThreads * 5);
}

// Test concurrent reads with single handler
TEST_F(KVDBComponentTest, ConcurrentReadsFromSingleHandler)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("concurrent-db");
    for (int i = 0; i < 50; ++i)
    {
        std::string key = "item:" + std::to_string(i);
        std::string value = R"({"value":)" + std::to_string(i) + "}";
        manager.put("concurrent-db", key, value);
    }
    manager.hotSwap("concurrent-db");

    auto handler = manager.openReadOnly("concurrent-db");

    const int numThreads = 5;
    const int opsPerThread = 50;
    std::vector<std::thread> threads;
    std::atomic<int> successfulReads {0};

    for (int t = 0; t < numThreads; ++t)
    {
        threads.emplace_back(
            [&handler, &successfulReads, opsPerThread]()
            {
                for (int i = 0; i < opsPerThread; ++i)
                {
                    int key = i % 50;
                    std::string keyStr = "item:" + std::to_string(key);

                    auto result = handler->get(keyStr);
                    if (result.getInt("/value").value() == key)
                    {
                        successfulReads++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successfulReads.load(), numThreads * opsPerThread);
}

// Test concurrent readers with multiple handlers
TEST_F(KVDBComponentTest, ConcurrentReadersMultipleHandlers)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("shared-db");
    manager.put("shared-db", "config:timeout", R"({"value":30})");
    manager.put("shared-db", "config:retries", R"({"value":5})");
    manager.hotSwap("shared-db");

    const int numHandlers = 5;
    std::vector<std::shared_ptr<kvdb::IReadOnlyKVDBHandler>> handlers;

    for (int i = 0; i < numHandlers; ++i)
    {
        handlers.push_back(manager.openReadOnly("shared-db"));
    }

    std::vector<std::thread> threads;
    std::atomic<int> totalSuccessfulReads {0};

    for (int i = 0; i < numHandlers; ++i)
    {
        threads.emplace_back(
            [&handler = handlers[i], &totalSuccessfulReads]()
            {
                for (int j = 0; j < 20; ++j)
                {
                    auto timeout = handler->get("config:timeout");
                    auto retries = handler->get("config:retries");

                    if (timeout.getInt("/value").value() == 30 && retries.getInt("/value").value() == 5)
                    {
                        totalSuccessfulReads++;
                    }
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(totalSuccessfulReads.load(), numHandlers * 20);
}

// Test thread-safe handler destruction
TEST_F(KVDBComponentTest, ThreadSafeHandlerDestruction)
{
    kvdb::KVDBManager manager(testDir);

    manager.add("destruction-db");
    manager.put("destruction-db", "item:1", R"({"value":"data"})");
    manager.hotSwap("destruction-db");

    std::atomic<int> successfulReads {0};
    std::vector<std::thread> threads;

    for (int i = 0; i < 5; ++i)
    {
        threads.emplace_back(
            [&manager, &successfulReads]()
            {
                for (int j = 0; j < 20; ++j)
                {
                    auto handler = manager.openReadOnly("destruction-db");
                    auto result = handler->get("item:1");
                    successfulReads++;
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(successfulReads.load(), 5 * 20);
}
