#include <chrono>
#include <filesystem>
#include <fstream>
#include <memory>
#include <thread>
#include <unistd.h>

#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <fastqueue/iqueue.hpp>
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
            .pattern = "wazuh-${name}-${YYYY}-${MM}-${DD}",
            .maxSize = 0,                                // No size limit for most tests
            .bufferSize = fastqueue::MIN_QUEUE_CAPACITY, // Use minimum buffer size for testing
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
        EXPECT_CALL(*mockStore, readDoc(_))
            .Times(AnyNumber())
            .WillRepeatedly(Return(store::mocks::storeReadError<store::Doc>()));

        EXPECT_CALL(*mockStore, upsertDoc(_, _)).Times(AnyNumber()).WillRepeatedly(Return(store::mocks::storeOk()));
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

TEST_F(LogManagerTest, HasChannelFunctionality)
{
    auto logManager = createLogManager();

    // Initially no channels
    EXPECT_FALSE(logManager->hasChannel("test-channel"));
    EXPECT_FALSE(logManager->hasChannel("another-channel"));

    // Auto-register channels via ensureAndGetWriter
    auto w1 = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    auto w2 = logManager->ensureAndGetWriter("another-channel", defaultConfig, "log");

    // Verify channels exist
    EXPECT_TRUE(logManager->hasChannel("test-channel"));
    EXPECT_TRUE(logManager->hasChannel("another-channel"));
    EXPECT_FALSE(logManager->hasChannel("non-existent"));

    w1.reset();
    w2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

TEST_F(LogManagerTest, EnsureAndGetWriterRegistersChannelOnDemand)
{
    auto logManager = createLogManager();

    auto writer = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    EXPECT_NE(writer, nullptr);

    EXPECT_TRUE(logManager->hasChannel("test-channel"));

    // Verify writer count increased
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);
}

TEST_F(LogManagerTest, EnsureAndGetWriterReusesExistingChannel)
{
    auto logManager = createLogManager();

    auto writer1 = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    auto writer2 = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");

    EXPECT_NE(writer1, nullptr);
    EXPECT_NE(writer2, nullptr);
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 2);

    writer1.reset();
    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

TEST_F(LogManagerTest, EnsureAndGetWriterRejectsInvalidChannelNames)
{
    auto logManager = createLogManager();

    const std::vector<std::string> invalidNames = {"invalid name", "invalid.name", "invalid/name", "invalid:name"};

    for (const auto& name : invalidNames)
    {
        EXPECT_THROW(logManager->ensureAndGetWriter(name, defaultConfig, "log"), std::runtime_error)
            << "Expected invalid channel name to throw: " << name;
    }
}

TEST_F(LogManagerTest, EnsureAndGetWriterRejectsInvalidConfig)
{
    auto logManager = createLogManager();

    // Invalid base path
    auto invalidConfig = defaultConfig;
    invalidConfig.basePath = "/non/existent/path";
    EXPECT_THROW(logManager->ensureAndGetWriter("test", invalidConfig, "log"), std::runtime_error);

    // Empty pattern
    invalidConfig = defaultConfig;
    invalidConfig.pattern = "";
    EXPECT_THROW(logManager->ensureAndGetWriter("test2", invalidConfig, "log"), std::runtime_error);
}

TEST_F(LogManagerTest, GetActiveWritersCountSuccess)
{
    auto logManager = createLogManager();

    auto writer1 = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);

    auto writer2 = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 2);

    // Destroy writers and verify count decreases
    writer1.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 1);

    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_EQ(logManager->getActiveWritersCount("test-channel"), 0);
}

TEST_F(LogManagerTest, GetActiveWritersCountNonExistent)
{
    auto logManager = createLogManager();
    EXPECT_THROW(logManager->getActiveWritersCount("non-existent"), std::runtime_error);
}

TEST_F(LogManagerTest, DestroyChannelSuccess)
{
    auto logManager = createLogManager();

    auto writer = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");
    EXPECT_TRUE(logManager->hasChannel("test-channel"));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    EXPECT_NO_THROW(logManager->destroyChannel("test-channel"));
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

    auto writer = logManager->ensureAndGetWriter("test-channel", defaultConfig, "log");

    // Attempt to destroy should throw
    EXPECT_THROW(logManager->destroyChannel("test-channel"), std::runtime_error);

    // After destroying writer, destruction should work
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
    EXPECT_NO_THROW(logManager->destroyChannel("test-channel"));
}

// ============= MULTI-CHANNEL TESTS =============

TEST_F(LogManagerTest, MultipleChannels)
{
    auto logManager = createLogManager();

    // Auto-register multiple channels
    auto writer1 = logManager->ensureAndGetWriter("channel-1", defaultConfig, "log");
    auto writer2 = logManager->ensureAndGetWriter("channel-2", defaultConfig, "log");
    auto writer3a = logManager->ensureAndGetWriter("channel-3", defaultConfig, "log");
    auto writer3b = logManager->ensureAndGetWriter("channel-3", defaultConfig, "log");

    // Verify all channels exist
    EXPECT_TRUE(logManager->hasChannel("channel-1"));
    EXPECT_TRUE(logManager->hasChannel("channel-2"));
    EXPECT_TRUE(logManager->hasChannel("channel-3"));

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

    writer1.reset();
    writer3a.reset();
    writer3b.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
}

// ============= FUNCTIONAL TESTS =============

TEST_F(LogManagerTest, WriterFunctionality)
{
    auto logManager = createLogManager();

    auto writer = logManager->ensureAndGetWriter("write-test", defaultConfig, "log");
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

// ============= EDGE CASES AND ERROR HANDLING =============

TEST_F(LogManagerTest, EmptyStringOperations)
{
    auto logManager = createLogManager();

    // hasChannel with empty string should return false (no validation needed for query)
    EXPECT_FALSE(logManager->hasChannel(""));

    // All modification operations with empty string should throw
    EXPECT_THROW(logManager->ensureAndGetWriter("", defaultConfig, "log"), std::runtime_error);
    EXPECT_THROW(logManager->getActiveWritersCount(""), std::runtime_error);
    EXPECT_THROW(logManager->destroyChannel(""), std::runtime_error);
}

TEST_F(LogManagerTest, LongChannelNames)
{
    auto logManager = createLogManager();

    // Test valid long name (should work)
    std::string longName = std::string(200, 'A');
    auto writer = logManager->ensureAndGetWriter(longName, defaultConfig, "log");
    EXPECT_NE(writer, nullptr);
    EXPECT_TRUE(logManager->hasChannel(longName));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Test extremely long name (may fail depending on limits)
    std::string extremelyLongName = std::string(300, 'B');
    try
    {
        auto w = logManager->ensureAndGetWriter(extremelyLongName, defaultConfig, "log");
        EXPECT_TRUE(logManager->hasChannel(extremelyLongName));
        w.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
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

        auto writer = logManager->ensureAndGetWriter("cleanup-test", defaultConfig, "log");
        EXPECT_EQ(logManager->getActiveWritersCount("cleanup-test"), 1);

        // LogManager destructor should clean up properly even with active writers
    } // LogManager destroyed here

    // No exceptions should be thrown
    EXPECT_TRUE(true);
}

TEST_F(LogManagerTest, MultipleWriterLifecycles)
{
    auto logManager = createLogManager();

    // First call auto-registers the channel
    auto writer = logManager->ensureAndGetWriter("lifecycle-test", defaultConfig, "log");
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));

    // Create multiple writers in sequence
    for (int i = 0; i < 10; ++i)
    {
        {
            auto w = logManager->ensureAndGetWriter("lifecycle-test", defaultConfig, "log");
            EXPECT_EQ(logManager->getActiveWritersCount("lifecycle-test"), 1);

            // Write some messages
            (*w)(std::string("Message " + std::to_string(i)));
        } // writer goes out of scope

        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        EXPECT_EQ(logManager->getActiveWritersCount("lifecycle-test"), 0);
    }
}
