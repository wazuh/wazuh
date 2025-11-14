#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <ctistore/cm.hpp>

// Helper utilities for generating isolated configurations for ContentManager tests.
namespace
{
std::string makeIsolatedConfig(cti::store::ContentManagerConfig& cfg, const std::string& tag)
{
    // Use high resolution clock + pid to avoid collisions in fast/parallel CI runs.
    auto now = std::chrono::high_resolution_clock::now().time_since_epoch().count();
    std::string base = "/tmp/cti_store_" + tag + '_' + std::to_string(now) + '_' + std::to_string(::getpid());
    cfg.outputFolder = base + "/content";
    cfg.databasePath = base + "/rocksdb";
    cfg.assetStorePath = base + "/assets";
    return base;
}
} // namespace

TEST(ContentManagerTest, init)
{
    // Use writable temp directories to avoid permission issues with default absolute paths.
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_init");

    std::unique_ptr<cti::store::ContentManager> cm;
    ASSERT_NO_THROW({ cm = std::make_unique<cti::store::ContentManager>(cfg); });
    ASSERT_NE(cm, nullptr);

    // Clean up
    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, processClassificationAllTypes)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_proc");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    // Create a temporary content file with one line for each type
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/batch.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    f << R"({"name":"policy","offset":1,"version":1,"inserted_at":"2025-01-01T00:00:00Z","payload":{"integrations":["i1"],"title":"Sample Policy","type":"policy"}})"
      << '\n';
    f << R"({"name":"i1","offset":2,"version":1,"inserted_at":"2025-01-01T00:00:01Z","payload":{"document":{"title":"Integration 1","decoders":["d1"],"kvdbs":["k1"],"id":"i1"},"type":"integration"}})"
      << '\n';
    f << R"({"name":"d1","offset":3,"version":1,"inserted_at":"2025-01-01T00:00:02Z","payload":{"document":{"metadata":{"module":"mod1"},"id":"d1"},"type":"decoder"},"integration_id":"i1"})"
      << '\n';
    f << R"({"name":"k1","offset":4,"version":1,"inserted_at":"2025-01-01T00:00:03Z","payload":{"type":"kvdb","integration_id":"i1","document":{"id":"k1","content":{"k":"v"}}}})"
      << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";

    auto result = cm.testProcessMessage(message);

    EXPECT_EQ(std::get<0>(result), 4); // highest offset processed
    EXPECT_TRUE(std::get<2>(result));

    std::filesystem::remove_all(base);
}

TEST(ContentManagerTest, processSkipsUnclassifiedLines)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_proc_skip");
    cfg.deleteDownloadedContent = false;

    cti::store::ContentManager cm(cfg);

    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/batch.json";
    std::ofstream f(filePath);
    ASSERT_TRUE(f.is_open());
    // Missing type -> should be unclassified but still offset updated
    f << R"({"name":"unknown","offset":10})" << '\n';
    // Valid decoder line
    f << R"({"name":"dX","offset":11,"payload":{"document":{"metadata":{"module":"m"}},"type":"decoder"}})" << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";
    auto result = cm.testProcessMessage(message);

    EXPECT_EQ(std::get<0>(result), 11); // last offset from second line
    EXPECT_TRUE(std::get<2>(result));

    std::filesystem::remove_all(base);
}

TEST(ContentManagerConcurrencyTest, MultipleReadGuardsAllowConcurrentAccess)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_concurrent_read");

    auto cm = std::make_shared<cti::store::ContentManager>(cfg);

    // Tracks when readers are active
    std::atomic<int> activeReaders {0};
    std::atomic<int> maxConcurrentReaders {0};

    const int numReaders = 5;
    std::vector<std::thread> readers;

    for (int i = 0; i < numReaders; ++i)
    {
        readers.emplace_back(
            [&cm, &activeReaders, &maxConcurrentReaders]()
            {
                // Acquire read guard
                auto readGuard = cm->acquireReadGuard();

                // Track concurrent readers atomically to avoid race conditions
                int current = ++activeReaders;

                // Update maxConcurrentReaders using compare_exchange to avoid race conditions
                int expected = maxConcurrentReaders.load(std::memory_order_relaxed);
                while (current > expected
                       && !maxConcurrentReaders.compare_exchange_weak(
                           expected, current, std::memory_order_relaxed, std::memory_order_relaxed))
                {
                    // Loop retries if another thread updated the value
                }

                // Simulate some read work
                std::this_thread::sleep_for(std::chrono::milliseconds(50));

                --activeReaders;
            });
    }

    // Wait for all readers to complete
    for (auto& t : readers)
    {
        t.join();
    }

    // Verify that multiple readers were active simultaneously
    EXPECT_GT(maxConcurrentReaders.load(), 1) << "Multiple readers should be able to access concurrently";

    std::filesystem::remove_all(base);
}

TEST(ContentManagerConcurrencyTest, WriteGuardBlocksReaders)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_write_blocks_read");
    cfg.deleteDownloadedContent = false;

    auto cm = std::make_shared<cti::store::ContentManager>(cfg);

    std::atomic<bool> writerHasLock {false};
    std::atomic<bool> readerBlocked {true};
    std::atomic<bool> readerAcquiredLock {false};

    // Create a file for writing
    std::filesystem::create_directories(cfg.outputFolder);
    const std::string filePath = cfg.outputFolder + "/write_test.json";
    std::ofstream f(filePath);
    f << R"({"name":"d1","offset":1,"payload":{"document":{"metadata":{"module":"m"}},"type":"decoder"}})" << '\n';
    f.close();

    std::string message = std::string("{\"paths\":[\"") + filePath + "\"],\"type\":\"raw\",\"offset\":0}";

    // Writer thread - acquires write lock
    std::thread writer(
        [&cm, &writerHasLock, &readerBlocked]()
        {
            // Acquire write guard
            auto writeGuard = cm->acquireWriteGuard();

            writerHasLock = true;

            // Hold the write lock for a bit
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Check if reader is still blocked
            EXPECT_TRUE(readerBlocked.load()) << "Reader should still be blocked while writer holds lock";
        });

    // Wait for writer to acquire lock
    while (!writerHasLock)
    {
        std::this_thread::yield();
    }

    // Reader thread - tries to acquire read lock while writer holds it
    std::thread reader(
        [&cm, &readerBlocked, &readerAcquiredLock]()
        {
            // Try to acquire read guard - should block until writer releases
            auto readGuard = cm->acquireReadGuard();

            readerBlocked = false;
            readerAcquiredLock = true;
        });

    // Give reader a chance to try acquiring the lock
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // At this point, reader should still be blocked
    EXPECT_TRUE(readerBlocked) << "Reader should be blocked while writer holds lock";

    writer.join();
    reader.join();

    // Verify reader eventually acquired the lock after writer released it
    EXPECT_TRUE(readerAcquiredLock) << "Reader should acquire lock after writer releases it";

    std::filesystem::remove_all(base);
}

TEST(ContentManagerConcurrencyTest, ReadGuardBlocksWriter)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_read_blocks_write");

    auto cm = std::make_shared<cti::store::ContentManager>(cfg);

    std::atomic<bool> readerHasLock {false};
    std::atomic<bool> writerBlocked {true};
    std::atomic<bool> writerAcquiredLock {false};

    // Reader thread - holds read lock
    std::thread reader(
        [&cm, &readerHasLock, &writerBlocked]()
        {
            auto readGuard = cm->acquireReadGuard();
            readerHasLock = true;

            // Hold the read lock for a bit
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            // Check if writer is still blocked
            EXPECT_TRUE(writerBlocked.load()) << "Writer should still be blocked while reader holds lock";
        });

    // Wait for reader to acquire lock
    while (!readerHasLock)
    {
        std::this_thread::yield();
    }

    // Writer thread - tries to acquire write lock while reader holds read lock
    std::thread writer(
        [&cm, &writerBlocked, &writerAcquiredLock]()
        {
            // Try to acquire write guard - should block until reader releases
            auto writeGuard = cm->acquireWriteGuard();

            writerBlocked = false;
            writerAcquiredLock = true;
        });

    // Give writer a chance to try acquiring the lock
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // At this point, writer should still be blocked
    EXPECT_TRUE(writerBlocked) << "Writer should be blocked while reader holds lock";

    reader.join();
    writer.join();

    // Verify writer eventually acquired the lock after reader released it
    EXPECT_TRUE(writerAcquiredLock) << "Writer should acquire lock after reader releases it";

    std::filesystem::remove_all(base);
}

TEST(ContentManagerConcurrencyTest, WriteGuardBlocksMultipleReaders)
{
    cti::store::ContentManagerConfig cfg;
    auto base = makeIsolatedConfig(cfg, "cm_write_blocks_multiple_reads");

    auto cm = std::make_shared<cti::store::ContentManager>(cfg);

    std::atomic<bool> writerHasLock {false};
    std::atomic<int> readersAcquiredLock {0};
    std::atomic<bool> writeLockReleased {false};

    // Writer thread - holds write lock
    std::thread writer(
        [&cm, &writerHasLock, &writeLockReleased, &readersAcquiredLock]()
        {
            auto writeGuard = cm->acquireWriteGuard();

            writerHasLock = true;

            // Hold the write lock for a bit
            std::this_thread::sleep_for(std::chrono::milliseconds(100));

            writeLockReleased = true;
            EXPECT_EQ(readersAcquiredLock.load(), 0) << "No readers should acquire locks while writer holds lock";
        });

    // Wait for writer to acquire lock
    while (!writerHasLock)
    {
        std::this_thread::yield();
    }

    // Multiple reader threads - all try to acquire read locks
    const int numReaders = 3;
    std::vector<std::thread> readers;

    for (int i = 0; i < numReaders; ++i)
    {
        readers.emplace_back(
            [&cm, &readersAcquiredLock]()
            {
                auto readGuard = cm->acquireReadGuard();
                ++readersAcquiredLock;

                // Hold lock briefly
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
            });
    }

    // Give readers a chance to try acquiring locks
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // No readers should have acquired locks yet
    EXPECT_EQ(readersAcquiredLock.load(), 0) << "No readers should acquire locks while writer holds lock";

    writer.join();

    // Wait for all readers to complete
    for (auto& t : readers)
    {
        t.join();
    }

    // All readers should have acquired locks after writer released
    EXPECT_EQ(readersAcquiredLock.load(), numReaders) << "All readers should acquire locks after writer releases";

    std::filesystem::remove_all(base);
}
