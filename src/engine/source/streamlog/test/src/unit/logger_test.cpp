#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <streamlog/logger.hpp>

#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

namespace
{

// Get unique random temp folder
std::filesystem::path getTempDir()
{
    const auto pid = std::to_string(getpid());
    auto strTime = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    strTime = strTime.substr(strTime.size() - 5);
    const auto relativePath = std::filesystem::path("engine") / (pid + "_" + strTime);

    // Create a unique temp directory
    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / relativePath;
    if (std::filesystem::exists(tmpDir))
    {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to remove existing temp directory: " + ec.message());
        }
    }
    std::error_code ec;
    std::filesystem::create_directories(tmpDir, ec);
    if (ec)
    {
        throw std::runtime_error("Failed to create temp directory: " + ec.message());
    }

    return tmpDir;
}

// Helper to read file contents
std::string readFileContents(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

} // namespace

class LogManagerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        // Initialize logging system for tests
        logging::testInit(logging::Level::Off); // Turn off logging to avoid noise in tests

        tmpDir = getTempDir();
        defaultConfig = {
            .basePath = tmpDir,
            .pattern = "wazuh-${name}-${YYYY}-${MM}-${DD}.json",
            .maxSize = 0,    // No size limit for most tests
            .bufferSize = 10 // Small buffer for testing
        };

        // Create mock store and scheduler
        mockStore = std::make_shared<store::mocks::MockStore>();
        mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

        // Set up default expectations for store operations
        using ::testing::_;
        using ::testing::AnyNumber;
        using ::testing::Return;

        // Default store expectations - return error for read operations (no previous state)
        // Use EXPECT_CALL with AnyNumber() to suppress GMock warnings
        EXPECT_CALL(*mockStore, readInternalDoc(_))
            .Times(AnyNumber())
            .WillRepeatedly(Return(store::mocks::storeReadError<store::Doc>()));

        EXPECT_CALL(*mockStore, upsertInternalDoc(_, _))
            .Times(AnyNumber())
            .WillRepeatedly(Return(store::mocks::storeOk()));
    }

    void TearDown() override
    {
        // Clean up temp directory
        if (std::filesystem::exists(tmpDir))
        {
            std::error_code ec;
            std::filesystem::remove_all(tmpDir, ec);
        }
    }

    // Helper to create LogManager with mocks
    std::unique_ptr<streamlog::LogManager> createLogManager()
    {
        return std::make_unique<streamlog::LogManager>(mockStore, mockScheduler);
    }

    std::filesystem::path tmpDir;
    streamlog::RotationConfig defaultConfig;
    std::shared_ptr<store::mocks::MockStore> mockStore;
    std::shared_ptr<scheduler::mocks::MockIScheduler> mockScheduler;
};

// ============= BASIC FUNCTIONALITY TESTS =============

TEST_F(LogManagerTest, DefaultConstruction)
{
    EXPECT_NO_THROW({ auto logManager = createLogManager(); });
}

TEST_F(LogManagerTest, RegisterLogSuccess)
{
    auto logManager = createLogManager();

    EXPECT_NO_THROW(logManager->registerLog("test-channel", defaultConfig, "log"));

    // Verify the channel exists
    EXPECT_TRUE(logManager->hasChannel("test-channel"));
    EXPECT_FALSE(logManager->hasChannel("non-existent"));
}

TEST_F(LogManagerTest, RegisterLogDuplicate)
{
    auto logManager = createLogManager();

    // Register first channel
    EXPECT_NO_THROW(logManager->registerLog("test-channel", defaultConfig, "log"));

    // Attempt to register duplicate should throw
    EXPECT_THROW(logManager->registerLog("test-channel", defaultConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, RegisterLogInvalidConfig)
{
    auto logManager = createLogManager();

    // Invalid base path
    auto invalidConfig = defaultConfig;
    invalidConfig.basePath = "/non/existent/path";
    EXPECT_THROW(logManager->registerLog("test", invalidConfig, "log"), std::runtime_error);

    // Empty pattern
    invalidConfig = defaultConfig;
    invalidConfig.pattern = "";
    EXPECT_THROW(logManager->registerLog("test", invalidConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, RegisterLogInvalidChannelName)
{
    auto logManager = createLogManager();

    // Empty name
    EXPECT_THROW(logManager->registerLog("", defaultConfig, "log"), std::runtime_error);

    // Invalid characters
    EXPECT_THROW(logManager->registerLog("test channel", defaultConfig, "log"), std::runtime_error);
    EXPECT_THROW(logManager->registerLog("test.channel", defaultConfig, "log"), std::runtime_error);
    EXPECT_THROW(logManager->registerLog("test/channel", defaultConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, HasChannelFunctionality)
{
    auto logManager = createLogManager();

    // Initially no channels
    EXPECT_FALSE(logManager->hasChannel("test-channel"));
    EXPECT_FALSE(logManager->hasChannel("another-channel"));

    // Register some channels
    logManager->registerLog("test-channel", defaultConfig, "log");
    logManager->registerLog("another-channel", defaultConfig, "log");

    // Verify channels exist
    EXPECT_TRUE(logManager->hasChannel("test-channel"));
    EXPECT_TRUE(logManager->hasChannel("another-channel"));
    EXPECT_FALSE(logManager->hasChannel("non-existent"));
}

TEST_F(LogManagerTest, GetConfigSuccess)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    const auto& config = logManager->getConfig("test-channel");
    EXPECT_EQ(config.basePath, defaultConfig.basePath);
    EXPECT_EQ(config.pattern, defaultConfig.pattern);
    EXPECT_EQ(config.maxSize, defaultConfig.maxSize);
    EXPECT_EQ(config.bufferSize, defaultConfig.bufferSize);
}

TEST_F(LogManagerTest, GetConfigNonExistent)
{
    auto logManager = createLogManager();

    EXPECT_THROW(logManager->getConfig("non-existent"), std::runtime_error);
}

TEST_F(LogManagerTest, GetWriterSuccess)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    auto writer = logManager->getWriter("test-channel");
    EXPECT_NE(writer, nullptr);

    // Verify writer count increased
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);
}

TEST_F(LogManagerTest, GetWriterNonExistent)
{
    auto logManager = createLogManager();

    EXPECT_THROW(logManager->getWriter("non-existent"), std::runtime_error);
}

TEST_F(LogManagerTest, GetActiveWritersCountSuccess)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    // Initially no writers
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 0);

    // Create writers and verify count
    auto writer1 = logManager->getWriter("test-channel");
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);

    auto writer2 = logManager->getWriter("test-channel");
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 2);

    // Destroy writers and verify count decreases
    writer1.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Brief pause for cleanup
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);

    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Brief pause for cleanup
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 0);
}

TEST_F(LogManagerTest, GetActiveWritersCountNonExistent)
{
    auto logManager = createLogManager();
    EXPECT_THROW(logManager->getActiveWritersCount("non-existent"), std::runtime_error);
}

TEST_F(LogManagerTest, UpdateConfigSuccess)
{
    auto logManager = createLogManager();
    std::string channelName {"test-channel"};
    logManager->registerLog(channelName, defaultConfig, "log");

    // Create new config
    auto newConfig = defaultConfig;
    newConfig.maxSize = 1024; // This will be normalized to 1MB minimum
    newConfig.bufferSize = 20;

    // Update config (no active writers)
    EXPECT_NO_THROW(logManager->updateConfig(channelName, newConfig, "log"));

    logManager->destroyChannel(channelName);
    EXPECT_FALSE(logManager->hasChannel(channelName));

    // // Verify config was updated (accounting for normalization)
    // const auto& updatedConfig = logManager->getConfig("test-channel");
    // EXPECT_EQ(updatedConfig.maxSize, 1048576); // 1MB minimum due to normalization
    // EXPECT_EQ(updatedConfig.bufferSize, 20);
}

TEST_F(LogManagerTest, UpdateConfigNonExistent)
{
    auto logManager = createLogManager();

    EXPECT_THROW(logManager->updateConfig("non-existent", defaultConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, UpdateConfigWithActiveWriters)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    // Create an active writer
    auto writer = logManager->getWriter("test-channel");

    // Attempt to update config should throw
    auto newConfig = defaultConfig;
    newConfig.maxSize = 1024;
    EXPECT_THROW(logManager->updateConfig("test-channel", newConfig, "log"), std::runtime_error);

    // After destroying writer, update should work
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Brief pause for cleanup
    EXPECT_NO_THROW(logManager->updateConfig("test-channel", newConfig, "log"));
}

TEST_F(LogManagerTest, UpdateConfigInvalidConfig)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    // Invalid base path
    auto invalidConfig = defaultConfig;
    invalidConfig.basePath = "/non/existent/path";
    EXPECT_THROW(logManager->updateConfig("test-channel", invalidConfig, "log"), std::runtime_error);

    // Empty pattern
    invalidConfig = defaultConfig;
    invalidConfig.pattern = "";
    EXPECT_THROW(logManager->updateConfig("test-channel", invalidConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, DestroyChannelSuccess)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    // Verify channel exists
    EXPECT_TRUE(logManager->hasChannel("test-channel"));

    // Destroy channel
    EXPECT_NO_THROW(logManager->destroyChannel("test-channel"));

    // Verify channel no longer exists
    EXPECT_FALSE(logManager->hasChannel("test-channel"));
}

TEST_F(LogManagerTest, DestroyChannelNonExistent)
{
    auto logManager = createLogManager();

    EXPECT_THROW(logManager->destroyChannel("non-existent"), std::runtime_error);
}

TEST_F(LogManagerTest, DestroyChannelWithActiveWriters)
{
    auto logManager = createLogManager();
    logManager->registerLog("test-channel", defaultConfig, "log");

    // Create an active writer
    auto writer = logManager->getWriter("test-channel");

    // Attempt to destroy should throw
    EXPECT_THROW(logManager->destroyChannel("test-channel"), std::runtime_error);

    // After destroying writer, destruction should work
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10)); // Brief pause for cleanup
    EXPECT_NO_THROW(logManager->destroyChannel("test-channel"));
}

// ============= MULTI-CHANNEL TESTS =============

TEST_F(LogManagerTest, MultipleChannels)
{
    auto logManager = createLogManager();

    // Register multiple channels
    logManager->registerLog("channel-1", defaultConfig, "log");
    logManager->registerLog("channel-2", defaultConfig, "log");
    logManager->registerLog("channel-3", defaultConfig, "log");

    // Verify all channels exist
    EXPECT_TRUE(logManager->hasChannel("channel-1"));
    EXPECT_TRUE(logManager->hasChannel("channel-2"));
    EXPECT_TRUE(logManager->hasChannel("channel-3"));

    // Create writers for different channels
    auto writer1 = logManager->getWriter("channel-1");
    auto writer2 = logManager->getWriter("channel-2");
    auto writer3a = logManager->getWriter("channel-3");
    auto writer3b = logManager->getWriter("channel-3");

    // Verify writer counts
    EXPECT_EQ(logManager->getActiveWritersCount("channel-1"), 1);
    EXPECT_EQ(logManager->getActiveWritersCount("channel-2"), 1);
    EXPECT_EQ(logManager->getActiveWritersCount("channel-3"), 2);

    // Destroy one channel
    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    logManager->destroyChannel("channel-2");

    // Verify only channel-2 is gone
    EXPECT_TRUE(logManager->hasChannel("channel-1"));
    EXPECT_FALSE(logManager->hasChannel("channel-2"));
    EXPECT_TRUE(logManager->hasChannel("channel-3"));
}

TEST_F(LogManagerTest, ConcurrentChannelAccess)
{
    auto logManager = createLogManager();
    logManager->registerLog("concurrent-channel", defaultConfig, "log");

    const int numThreads = 5;
    const int writersPerThread = 3;
    std::vector<std::thread> threads;
    std::vector<std::vector<std::shared_ptr<streamlog::WriterEvent>>> writers(numThreads);

    // Create multiple threads that get writers
    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                for (int j = 0; j < writersPerThread; ++j)
                {
                    writers[i].push_back(logManager->getWriter("concurrent-channel"));
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            });
    }

    // Wait for all threads
    for (auto& thread : threads)
    {
        thread.join();
    }

    // Verify total writer count
    EXPECT_EQ(logManager->getActiveWritersCount("concurrent-channel"), numThreads * writersPerThread);

    // Clean up writers
    for (auto& threadWriters : writers)
    {
        threadWriters.clear();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(50)); // Allow cleanup

    EXPECT_EQ(logManager->getActiveWritersCount("concurrent-channel"), 0);
}

// ============= FUNCTIONAL TESTS =============

TEST_F(LogManagerTest, WriterFunctionality)
{
    auto logManager = createLogManager();
    logManager->registerLog("write-test", defaultConfig, "log");

    auto writer = logManager->getWriter("write-test");
    ASSERT_NE(writer, nullptr);

    // Test writing messages
    EXPECT_TRUE((*writer)(std::string("Test message 1")));
    EXPECT_TRUE((*writer)(std::string("Test message 2")));
    EXPECT_TRUE((*writer)(std::string("Test message 3")));

    // Allow some time for asynchronous writing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Destroy writer and wait for cleanup
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // Verify no active writers remain
    EXPECT_EQ(logManager->getActiveWritersCount("write-test"), 0);
}

TEST_F(LogManagerTest, ConfigurationPersistence)
{
    auto logManager = createLogManager();

    auto customConfig = defaultConfig;
    customConfig.maxSize = 2048; // This will be normalized to 1MB minimum
    customConfig.bufferSize = 50;
    customConfig.pattern = "custom-${name}-${YYYY}.log"; // ${counter} will be added due to maxSize

    logManager->registerLog("persist-test", customConfig, "log");

    // Verify configuration is stored correctly (accounting for normalization)
    const auto& storedConfig = logManager->getConfig("persist-test");
    EXPECT_EQ(storedConfig.basePath, customConfig.basePath);
    EXPECT_EQ(storedConfig.pattern, "custom-${name}-${YYYY}-${counter}.log"); // Counter added
    EXPECT_EQ(storedConfig.maxSize, 1048576);                                 // 1MB minimum due to normalization
    EXPECT_EQ(storedConfig.bufferSize, customConfig.bufferSize);

    // Create and destroy writers, config should persist
    auto writer1 = logManager->getWriter("persist-test");
    writer1.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    auto writer2 = logManager->getWriter("persist-test");
    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Configuration should still be the same
    const auto& finalConfig = logManager->getConfig("persist-test");
    EXPECT_EQ(finalConfig.basePath, customConfig.basePath);
    EXPECT_EQ(finalConfig.pattern, "custom-${name}-${YYYY}-${counter}.log"); // Counter added
    EXPECT_EQ(finalConfig.maxSize, 1048576);                                 // 1MB minimum due to normalization
    EXPECT_EQ(finalConfig.bufferSize, customConfig.bufferSize);
}

// ============= EDGE CASES AND ERROR HANDLING =============

TEST_F(LogManagerTest, EmptyStringOperations)
{
    auto logManager = createLogManager();

    // hasChannel with empty string should return false (no validation needed for query)
    EXPECT_FALSE(logManager->hasChannel(""));

    // All modification operations with empty string should throw
    EXPECT_THROW(logManager->registerLog("", defaultConfig, "log"), std::runtime_error);
    EXPECT_THROW(logManager->getWriter(""), std::runtime_error);
    EXPECT_THROW(logManager->getConfig(""), std::runtime_error);
    EXPECT_THROW(logManager->getActiveWritersCount(""), std::runtime_error);
    EXPECT_THROW(logManager->updateConfig("", defaultConfig, "log"), std::runtime_error);
    EXPECT_THROW(logManager->destroyChannel(""), std::runtime_error);
}

TEST_F(LogManagerTest, LongChannelNames)
{
    auto logManager = createLogManager();

    // Test valid long name (should work)
    std::string longName = std::string(200, 'A');
    EXPECT_NO_THROW(logManager->registerLog(longName, defaultConfig, "log"));
    EXPECT_TRUE(logManager->hasChannel(longName));

    // Test extremely long name (may fail depending on limits)
    std::string extremelyLongName = std::string(300, 'B');
    // This might throw due to filesystem limits, but should be handled gracefully
    try
    {
        logManager->registerLog(extremelyLongName, defaultConfig, "log");
        EXPECT_TRUE(logManager->hasChannel(extremelyLongName));
    }
    catch (const std::runtime_error&)
    {
        // Expected for extremely long names
    }
}

TEST_F(LogManagerTest, DestructorCleanup)
{
    // Test that LogManager destructor properly cleans up
    {
        auto logManager = createLogManager();
        logManager->registerLog("cleanup-test", defaultConfig, "log");

        auto writer = logManager->getWriter("cleanup-test");
        EXPECT_EQ(logManager->getActiveWritersCount("cleanup-test"), 1);

        // LogManager destructor should clean up properly even with active writers
    } // LogManager destroyed here

    // No exceptions should be thrown
    EXPECT_TRUE(true);
}

TEST_F(LogManagerTest, MultipleWriterLifecycles)
{
    auto logManager = createLogManager();
    logManager->registerLog("lifecycle-test", defaultConfig, "log");

    // Create multiple writers in sequence
    for (int i = 0; i < 10; ++i)
    {
        {
            auto writer = logManager->getWriter("lifecycle-test");
            EXPECT_EQ(logManager->getActiveWritersCount("lifecycle-test"), 1);

            // Write some messages
            (*writer)(std::string("Message " + std::to_string(i)));
        } // writer goes out of scope

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        EXPECT_EQ(logManager->getActiveWritersCount("lifecycle-test"), 0);
    }
}
