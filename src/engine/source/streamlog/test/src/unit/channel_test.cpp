#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <random>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

#include "channel.hpp"

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

// Helper to count lines in file
size_t countLines(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        return 0;
    }
    size_t count = 0;
    std::string line;
    while (std::getline(file, line))
    {
        count++;
    }
    return count;
}

// Helper to wait for condition with timeout
template<typename Condition>
bool waitFor(Condition&& condition, std::chrono::milliseconds timeout = std::chrono::milliseconds(5000))
{
    auto start = std::chrono::steady_clock::now();
    while (!condition())
    {
        if (std::chrono::steady_clock::now() - start > timeout)
        {
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

} // namespace

class ChannelHandlerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        tmpDir = getTempDir();

        // Default config for most tests
        defaultConfig = {
            tmpDir,                                   // basePath
            "wazuh-${name}-${YYYY}-${MM}-${DD}.json", // pattern
            0,                                        // maxSize (no limit)
            1024                                      // bufferSize
        };

        // Set up default mock store
        mockStore = std::make_shared<store::mocks::MockStore>();

        // Default mock store behavior - allow any readInternalDoc call to return empty
        EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

        // Allow any upsertInternalDoc call to succeed
        EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    }

    void TearDown() override
    {
        // Clean up temp directory
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }

    // Helper to create a basic channel handler with mocks
    std::shared_ptr<streamlog::ChannelHandler> createBasicHandler(const std::string& name)
    {
        return streamlog::ChannelHandler::create(
            defaultConfig, name, mockStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
    }

    std::shared_ptr<streamlog::ChannelHandler> createBasicHandler(const std::string& name,
                                                                  const streamlog::RotationConfig& config)
    {
        return streamlog::ChannelHandler::create(
            config, name, mockStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
    }

    // Helper to create a handler with scheduler mock
    std::shared_ptr<streamlog::ChannelHandler>
    createHandlerWithScheduler(const std::string& name,
                               const streamlog::RotationConfig& config,
                               std::shared_ptr<scheduler::mocks::MockIScheduler> scheduler)
    {
        return streamlog::ChannelHandler::create(config, name, mockStore, scheduler, "log");
    }

    // Helper to create test file with content
    void createTestFile(const std::string& filePath, const std::string& content = "test content")
    {
        std::ofstream file(filePath);
        file << content;
        file.close();
    }

    std::filesystem::path tmpDir;
    streamlog::RotationConfig defaultConfig;
    std::shared_ptr<store::mocks::MockStore> mockStore;
};

// Parameterized test for different channel names
class ChannelNameTest
    : public ChannelHandlerTest
    , public ::testing::WithParamInterface<std::string>
{
};

// Parameterized test for different patterns
class PatternTest
    : public ChannelHandlerTest
    , public ::testing::WithParamInterface<std::string>
{
};

// Parameterized test for different buffer sizes
class BufferSizeTest
    : public ChannelHandlerTest
    , public ::testing::WithParamInterface<size_t>
{
};

// Test basic creation and destruction
TEST_F(ChannelHandlerTest, BasicCreationAndDestruction)
{
    auto handler = createBasicHandler("test-channel");
    ASSERT_NE(handler, nullptr);

    // Handler should be created successfully
    EXPECT_NO_THROW({
        auto writer = handler->createWriter();
        EXPECT_NE(writer, nullptr);
    });
}

// Test factory method enforces shared_ptr usage
TEST_F(ChannelHandlerTest, FactoryMethodEnforcesSharedPtr)
{
    auto handler = createBasicHandler("test");
    EXPECT_NE(handler, nullptr);

    // Should be able to copy shared_ptr
    auto handler2 = handler;
    EXPECT_EQ(handler.get(), handler2.get());
}

// Test invalid configurations
TEST_F(ChannelHandlerTest, InvalidConfigurations)
{
    // Empty channel name
    EXPECT_THROW(createBasicHandler(""), std::runtime_error);

    // Empty pattern
    auto config = defaultConfig;
    config.pattern = "";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);

    // Non-existent base path
    config = defaultConfig;
    config.basePath = "/non/existent/path";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);

    // Relative path
    config = defaultConfig;
    config.basePath = "relative/path";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);
}

// Test channel name validation
TEST_F(ChannelHandlerTest, ChannelNameValidation)
{
    // Valid names should not throw
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("valid-name"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("valid_name"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("validName123"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("123validName"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("a"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("A-B_C123"));

    // Invalid names should throw
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName(""), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid name"), std::runtime_error);  // space
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid.name"), std::runtime_error);  // dot
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid/name"), std::runtime_error);  // slash
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid\\name"), std::runtime_error); // backslash
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid@name"), std::runtime_error);  // special char
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid#name"), std::runtime_error);  // hash
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid!name"), std::runtime_error);  // exclamation
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid%name"), std::runtime_error);  // percent
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("ñame"), std::runtime_error);          // unicode
}

// Test configuration validation and normalization
TEST_F(ChannelHandlerTest, ConfigurationValidation)
{
    auto config = defaultConfig;

    // Valid configuration should not throw
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));

    // Test empty base path
    config = defaultConfig;
    config.basePath = "";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    // Test relative base path
    config = defaultConfig;
    config.basePath = "relative/path";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    // Test non-existent base path
    config = defaultConfig;
    config.basePath = "/non/existent/path/that/does/not/exist";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    // Test empty pattern
    config = defaultConfig;
    config.pattern = "";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    // Test pattern without time placeholders and no maxSize
    config = defaultConfig;
    config.pattern = "static-name.log";
    config.maxSize = 0;
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    // Test pattern with maxSize but without counter (should auto-add counter)
    config = defaultConfig;
    config.pattern = "${YYYY}-${MM}-${DD}.log";
    config.maxSize = 1024;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_NE(config.pattern.find("${counter}"), std::string::npos);

    // Test pattern with maxSize and existing counter
    config = defaultConfig;
    config.pattern = "${YYYY}-${MM}-${DD}-${counter}.log";
    config.maxSize = 1024;
    auto originalPattern = config.pattern;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.pattern, originalPattern); // Should not be modified

    // Test bufferSize normalization (0 should become default)
    config = defaultConfig;
    config.bufferSize = 0;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.bufferSize, 1 << 20);

    // Test maxSize normalization (small values should be increased)
    config = defaultConfig;
    config.maxSize = 100; // Very small
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.maxSize, 1 << 20);

    // Test maxSize with acceptable value (should not be changed)
    config = defaultConfig;
    config.maxSize = 10 << 20; // 10 MB
    auto originalMaxSize = config.maxSize;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.maxSize, originalMaxSize);
}

// Test configuration getter
TEST_F(ChannelHandlerTest, ConfigurationGetter)
{
    auto handler = createBasicHandler("test-config");

    const auto& retrievedConfig = handler->getConfig();

    // Should be the same as what we passed in (after normalization)
    EXPECT_EQ(retrievedConfig.basePath, defaultConfig.basePath);
    EXPECT_EQ(retrievedConfig.bufferSize, defaultConfig.bufferSize);

    // Pattern might be modified if maxSize was set and counter was added
    if (defaultConfig.maxSize > 0)
    {
        // Should contain counter placeholder
        EXPECT_NE(retrievedConfig.pattern.find("${counter}"), std::string::npos);
    }
}

// Test that configuration is immutable after creation
TEST_F(ChannelHandlerTest, ConfigurationImmutability)
{
    auto handler = createBasicHandler("test-immutable");

    const auto& config1 = handler->getConfig();
    const auto& config2 = handler->getConfig();

    // Should return the same reference
    EXPECT_EQ(&config1, &config2);

    // Configuration should be accessible and contain expected values
    EXPECT_FALSE(config1.basePath.empty());
    EXPECT_FALSE(config1.pattern.empty());
    EXPECT_GT(config1.bufferSize, 0);
}

// Test valid channel names
TEST_P(ChannelNameTest, ValidChannelNames)
{
    const std::string channelName = GetParam();
    EXPECT_NO_THROW({
        auto handler = createBasicHandler(channelName);
        EXPECT_NE(handler, nullptr);
    });
}

INSTANTIATE_TEST_SUITE_P(ChannelNames,
                         ChannelNameTest,
                         ::testing::Values("simple",
                                           "with-dashes",
                                           "with_underscores",
                                           "withNumbers123",
                                           "MixedCase",
                                           "very-long-channel-name-with-many-characters",
                                           "alerts",
                                           "events",
                                           "audit"));

// Test different patterns
TEST_P(PatternTest, DifferentPatterns)
{
    const std::string pattern = GetParam();
    auto config = defaultConfig;
    config.pattern = pattern;

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("test", config);
        auto writer = handler->createWriter();
        (*writer)("test message");

        // Give some time for async write
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
}

INSTANTIATE_TEST_SUITE_P(Patterns,
                         PatternTest,
                         ::testing::Values("${YYYY}-${MM}-${DD}-${name}.log",
                                           "logs/${YYYY}/${MM}/${name}-${DD}.json",
                                           "${name}-${YYYY}${MM}${DD}-${HH}.log"));

// Test different buffer sizes
TEST_P(BufferSizeTest, DifferentBufferSizes)
{
    const size_t bufferSize = GetParam();
    auto config = defaultConfig;
    config.bufferSize = bufferSize;

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("test", config);
        auto writer = handler->createWriter();

        // Write some messages
        for (int i = 0; i < 10; ++i)
        {
            (*writer)("test message " + std::to_string(i));
        }

        // Give time for processing
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
}

INSTANTIATE_TEST_SUITE_P(BufferSizes,
                         BufferSizeTest,
                         ::testing::Values(1,      // Minimum
                                           10,     // Small
                                           1024,   // Default
                                           1 << 20 // Large (1MB)
                                           ));

// Test writer lifecycle
TEST_F(ChannelHandlerTest, WriterLifecycle)
{
    auto handler = createBasicHandler("test");

    // No writers initially
    {
        auto writer1 = handler->createWriter();
        EXPECT_NE(writer1, nullptr);

        // Add second writer
        auto writer2 = handler->createWriter();
        EXPECT_NE(writer2, nullptr);

        // Both should work
        (*writer1)("message from writer1");
        (*writer2)("message from writer2");

        // Check the active writers count
        EXPECT_EQ(handler->getActiveWritersCount(), 2);
    }

    // The writer goes out of scope
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0); // Should be 0 after destruction

    // Create new writer after others are destroyed
    auto writer3 = handler->createWriter();
    EXPECT_NE(writer3, nullptr);
    (*writer3)("message from writer3");
    EXPECT_EQ(handler->getActiveWritersCount(), 1); // Should be 1 now
}

// Test writing messages
TEST_F(ChannelHandlerTest, BasicMessageWriting)
{
    auto handler = createBasicHandler("test");
    auto writer = handler->createWriter();

    const std::vector<std::string> messages = {"first message",
                                               "second message with special chars: áéíóú",
                                               "{\"json\": \"message\", \"number\": 42}",
                                               "very long message " + std::string(1000, 'x'),
                                               "message with\nnewlines\nand\ttabs"};

    for (const auto& msg : messages)
    {
        (*writer)(std::string(msg)); // Copy to test string handling
    }

    // Wait for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Find the created log file
    bool foundFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            foundFile = true;
            auto content = readFileContents(entry.path());

            // Each message should be on its own line
            for (const auto& msg : messages)
            {
                EXPECT_NE(content.find(msg), std::string::npos) << "Message not found: " << msg;
            }
            break;
        }
    }

    EXPECT_TRUE(foundFile) << "No log file was created";
}

// Test file rotation by size
TEST_F(ChannelHandlerTest, SizeBasedRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20; // 1MB
    config.pattern = "${name}-${counter}.log";

    auto handler = createBasicHandler("rotation-test", config);
    auto writer = handler->createWriter();

    // Write enough data to trigger rotation
    const std::string largeMessage = std::string(50 * 1024, 'A'); // ~50KB per message

    for (int i = 0; i < 50; ++i) // Total ~2.5MB
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should have multiple files due to rotation
    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            fileCount++;
        }
    }

    // 1 rotation should have occurred, resulting in at least 3 files (current + hardlink to current + rotated)
    EXPECT_GT(fileCount, 3) << "Size-based rotation did not create multiple files";
}

// Test time-based rotation
TEST_F(ChannelHandlerTest, TimeBasedRotation)
{
    auto config = defaultConfig;
    config.pattern = "${name}-${HH}.json"; // Rotate by hour

    auto handler = createBasicHandler("time-test", config);
    auto writer = handler->createWriter();

    (*writer)("message before time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Note: This test relies on the actual time, so it may not always trigger rotation
    // In a real scenario, you might need to mock the time system
    // TODO: Fix this test to reliably trigger time rotation
    (*writer)("message after time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

// Test hard link creation
TEST_F(ChannelHandlerTest, HardLinkCreation)
{
    auto handler = createBasicHandler("linktest");
    auto writer = handler->createWriter();

    (*writer)("test message for link");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Check if latest link exists
    auto latestLink = tmpDir / "linktest.log";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Latest link was not created: " << latestLink;

    // Content should be accessible through the link
    auto content = readFileContents(latestLink);
    EXPECT_NE(content.find("test message for link"), std::string::npos);
}

// Test concurrent writers
TEST_F(ChannelHandlerTest, ConcurrentWriters)
{
    auto config = defaultConfig;
    config.shouldCompress = false; // Disable compression for contingency
    auto handler = createBasicHandler("concurrent", config);

    const int numWriters = 5;
    const int messagesPerWriter = 20;
    std::vector<std::future<void>> futures;

    // Launch multiple writers concurrently
    for (int w = 0; w < numWriters; ++w)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&, w]()
                                     {
                                         auto writer = handler->createWriter();
                                         for (int m = 0; m < messagesPerWriter; ++m)
                                         {
                                             (*writer)("writer" + std::to_string(w) + "_message" + std::to_string(m));
                                             std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                         }
                                     }));
    }

    // Wait for all writers to complete
    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    // Verify all messages were written
    bool foundFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            foundFile = true;
            auto expectedCount = numWriters * messagesPerWriter;
            size_t lastLineCount = 0;

            for (int attempt = 0; attempt < 50; ++attempt)
            {
                auto lineCount = countLines(entry.path());
                size_t count = 0;
                if (lineCount == expectedCount)
                {
                    lastLineCount = lineCount;
                    break; // Found expected count
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            EXPECT_EQ(lastLineCount, expectedCount) << "Expected " << expectedCount << " lines, got " << lastLineCount;
            break;
        }
    }

    EXPECT_TRUE(foundFile);
}

// Test writer thread lifecycle
TEST_F(ChannelHandlerTest, WorkerThreadLifecycle)
{
    auto handler = createBasicHandler("thread-test");

    // No thread should be running initially
    // Create first writer - should start thread
    {
        auto writer1 = handler->createWriter();
        (*writer1)("message1");

        // Create second writer - should reuse thread
        {
            auto writer2 = handler->createWriter();
            (*writer2)("message2");

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            // Both writers should be active
            EXPECT_EQ(handler->getActiveWritersCount(), 2);
        }
        // writer2 destroyed, but writer1 still alive
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        EXPECT_EQ(handler->getActiveWritersCount(), 1); // Only writer1 should be active
        (*writer1)("message3");
    }
    // All writers destroyed, thread should stop
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0); // No active writers

    // Create new writer - should restart thread
    auto writer3 = handler->createWriter();
    (*writer3)("message4");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 1); // One active writer again

    // Cleanup
    writer3.reset(); // Should stop thread again
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0); // No active writers
}

// Test error handling - write to non-writable directory
TEST_F(ChannelHandlerTest, ErrorHandlingNonWritableDirectory)
{

    // Skip this test if running as root and we can't create read-only filesystem
    if (geteuid() == 0)
    {
        GTEST_SKIP() << "Skipping test when running as root - cannot reliably test write permissions";
        return;
    }

    // Create a directory without write permissions
    auto readOnlyDir = tmpDir / "readonly";
    std::filesystem::create_directory(readOnlyDir);
    std::filesystem::permissions(readOnlyDir,
                                 std::filesystem::perms::owner_read | std::filesystem::perms::owner_exec,
                                 std::filesystem::perm_options::replace);

    auto config = defaultConfig;
    config.basePath = readOnlyDir;

    // Should throw during creation
    EXPECT_THROW(createBasicHandler("readonly-test", config), std::runtime_error);

    // Restore permissions for cleanup
    std::filesystem::permissions(
        readOnlyDir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

// Test placeholder replacement
TEST_F(ChannelHandlerTest, PlaceholderReplacement)
{
    auto config = defaultConfig;
    config.pattern = "${YYYY}_${MM}_${DD}_${HH}_${name}_test.log";

    auto handler = createBasicHandler("placeholder-test", config);
    auto writer = handler->createWriter();

    (*writer)("test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Find created file and verify name format
    bool foundValidFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file())
        {
            std::string filename = entry.path().filename().string();

            // Should match pattern: YYYY_MM_DD_HH_placeholder-test_test.log
            if (filename.find("placeholder-test") != std::string::npos
                && filename.find("_test.log") != std::string::npos)
            {
                foundValidFile = true;

                // Verify format roughly (YYYY_MM_DD_HH format)
                EXPECT_TRUE(filename.length() > 25); // Reasonable minimum length
                EXPECT_NE(filename.find("_"), std::string::npos);
                break;
            }
        }
    }

    EXPECT_TRUE(foundValidFile) << "File with correct placeholder replacement not found";
}

// Test counter placeholder with size rotation
TEST_F(ChannelHandlerTest, CounterPlaceholderWithSizeRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20; // 1MB max size, minimize rotation
    config.pattern = "${name}-${counter}.log";

    auto handler = createBasicHandler("counter-test", config);
    auto writer = handler->createWriter();

    // Write enough to force multiple rotations
    for (int i = 0; i < 5000; ++i)
    {
        (*writer)("message " + std::to_string(i) + " " + std::string(1000, 'x'));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should have files with different counter values
    std::set<std::string> foundFiles;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            foundFiles.insert(entry.path().filename().string());
        }
    }

    EXPECT_EQ(foundFiles.size(), 5 + 1) << "Expected multiple files with different counters";

    // Verify counter pattern exists
    bool hasCounterPattern = false;
    for (const auto& filename : foundFiles)
    {
        if (filename.find("counter-test-") != std::string::npos)
        {
            hasCounterPattern = true;
            break;
        }
    }
    EXPECT_TRUE(hasCounterPattern) << "Counter pattern not found in filenames";
}

// Test writer non-copyability
TEST_F(ChannelHandlerTest, WriterNonCopyable)
{
    auto handler = createBasicHandler("nocopy-test");
    auto writer1 = handler->createWriter();

    // This should not compile, but we can't test compilation failures in runtime tests
    // The test ensures the design is correct by verifying we can't accidentally copy

    // Test that we can pass by value to functions (copy semantics work)
    auto testWriterByValue = [](std::shared_ptr<streamlog::WriterEvent> writer)
    {
        (*writer)("message via value");
    };

    EXPECT_NO_THROW(testWriterByValue(writer1));
}

// Test buffer overflow behavior
TEST_F(ChannelHandlerTest, BufferOverflowBehavior)
{
    auto config = defaultConfig;
    config.bufferSize = 2; // Very small buffer

    auto handler = createBasicHandler("overflow-test", config);
    auto writer = handler->createWriter();

    // Overwhelm the buffer quickly
    for (int i = 0; i < 100; ++i)
    {
        (*writer)("rapid message " + std::to_string(i));
    }

    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    // Should not crash, though some messages might be lost due to buffer limits
    // This tests the robustness of the system under stress
}

// Test directory creation
TEST_F(ChannelHandlerTest, DirectoryCreation)
{
    auto config = defaultConfig;
    config.pattern = "subdir1/subdir2/${name}-${counter}.json";
    config.maxSize = 0x1 << 20; // 1MB max size to avoid rotation

    auto handler = createBasicHandler("dir-test", config);
    auto writer = handler->createWriter();

    (*writer)("test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify subdirectories were created
    auto expectedDir = tmpDir / "subdir1" / "subdir2";
    EXPECT_TRUE(std::filesystem::exists(expectedDir)) << "Subdirectories were not created: " << expectedDir;

    auto expectedFile = expectedDir / "dir-test-0.json";
    EXPECT_TRUE(std::filesystem::exists(expectedFile)) << "Log file was not created in subdirectory: " << expectedFile;
}

// ============= CORNER CASES AND EDGE CASES TESTS =============

// Test invalid channel names with special characters
TEST_F(ChannelHandlerTest, InvalidChannelNames)
{
    std::vector<std::string> invalidNames = {
        "",              // Empty
        "test@channel",  // Special char @
        "test channel",  // Space
        "test/channel",  // Slash
        "test\\channel", // Backslash
        "test.channel",  // Dot
        "test:channel",  // Colon
        "test*channel",  // Asterisk
        "test?channel",  // Question mark
        "test<channel",  // Less than
        "test>channel",  // Greater than
        "test|channel",  // Pipe
        "test\"channel", // Quote
        "test'channel"   // Apostrophe
    };

    for (const auto& name : invalidNames)
    {
        EXPECT_THROW(createBasicHandler(name), std::runtime_error)
            << "Channel name should be invalid: '" << name << "'";
    }
}

// Test regex replacement edge cases
TEST_F(ChannelHandlerTest, RegexReplacementEdgeCases)
{
    auto config = defaultConfig;

    // Test with unusual but valid patterns
    std::vector<std::string> edgePatterns = {
        "${YYYY}${MM}${DD}${HH}${name}",           // No separators
        "${YYYY}-${MM}-${DD}-${HH}-${name}-end",   // Multiple occurrences
        "prefix-${name}-${YYYY}-suffix.log",       // Mixed order
        "${DD}${DD}${DD}.log",                     // Repeated placeholder
        "very/deep/nested/dir/${name}-${YYYY}.log" // Deep nesting
    };

    for (const auto& pattern : edgePatterns)
    {
        config.pattern = pattern;
        EXPECT_NO_THROW({
            auto handler = createBasicHandler("edge-test");
            auto writer = handler->createWriter();
            (*writer)("test message");
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }) << "Pattern should be valid: "
           << pattern;
    }
}

// Test extremely long messages
TEST_F(ChannelHandlerTest, ExtremelyLongMessages)
{
    auto handler = createBasicHandler("long-msg-test");
    auto writer = handler->createWriter();

    // Test various large message sizes
    std::vector<size_t> sizes = {1024, 10240, 102400, 1048576}; // 1KB to 1MB

    for (size_t size : sizes)
    {
        std::string longMessage(size, 'A');
        longMessage += "_END"; // Marker to verify complete write

        EXPECT_NO_THROW((*writer)(std::move(longMessage))) << "Failed with message size: " << size;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500)); // Wait for processing
}

// Test concurrent file access with multiple channels
TEST_F(ChannelHandlerTest, ConcurrentMultipleChannels)
{
    const int numChannels = 10;
    std::vector<std::shared_ptr<streamlog::ChannelHandler>> handlers;
    std::vector<std::future<void>> futures;

    // Create multiple channels concurrently
    for (int i = 0; i < numChannels; ++i)
    {
        auto handler = createBasicHandler("channel" + std::to_string(i));
        handlers.push_back(handler);
    }

    // Write to all channels concurrently
    for (int i = 0; i < numChannels; ++i)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&handlers, i]()
                                     {
                                         auto writer = handlers[i]->createWriter();
                                         for (int j = 0; j < 20; ++j)
                                         {
                                             (*writer)("Channel" + std::to_string(i) + "_Message" + std::to_string(j));
                                             std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                         }
                                     }));
    }

    // Wait for all to complete
    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Verify each channel created its file
    size_t totalFiles = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            totalFiles++;
        }
    }

    EXPECT_GE(totalFiles, numChannels) << "Not all channels created their files";
}

// Test zero-byte and empty message handling
TEST_F(ChannelHandlerTest, EmptyAndZeroByteMessages)
{
    auto handler = createBasicHandler("empty-test");
    auto writer = handler->createWriter();

    // Test various empty/minimal cases
    std::vector<std::string> testMessages = {
        "",                                 // Completely empty
        " ",                                // Single space
        "\n",                               // Just newline
        "\t",                               // Just tab
        "a",                                // Single character
        "\0",                               // Null character
        std::string(1, '\0') + "after_null" // Null in middle
    };

    for (const auto& msg : testMessages)
    {
        std::string msgCopy = msg; // Create copy for move
        EXPECT_NO_THROW((*writer)(std::move(msgCopy))) << "Failed with message: '" << msg << "'";
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// Test boundary conditions for maxSize
TEST_F(ChannelHandlerTest, MaxSizeBoundaryConditions)
{
    // Test exact boundary conditions
    std::vector<size_t> testSizes = {
        1,       // Minimum
        1023,    // Just under 1KB
        1024,    // Exactly 1KB
        1025,    // Just over 1KB
        1048575, // Just under 1MB (default minimum)
        1048576, // Exactly 1MB
        1048577  // Just over 1MB
    };

    for (size_t maxSize : testSizes)
    {
        auto config = defaultConfig;
        config.maxSize = maxSize;
        config.pattern = "${name}-${counter}-" + std::to_string(maxSize) + ".json";

        EXPECT_NO_THROW({
            auto handler = createBasicHandler("boundary-test", config);
            auto writer = handler->createWriter();

            // Write message that's exactly at the boundary
            std::string message(maxSize / 2, 'X');
            (*writer)(std::string(message)); // Copy for first write
            (*writer)(std::move(message));   // Move for second write - this should trigger rotation

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }) << "Failed with maxSize: "
           << maxSize;
    }
}

// Test pattern validation edge cases
TEST_F(ChannelHandlerTest, PatternValidationEdgeCases)
{
    std::vector<std::string> invalidPatterns = {
        "",                           // Empty pattern
        "no_placeholders.log",        // No placeholders at all
        "${INVALID}.log",             // Invalid placeholder
        "${YYYY}${INVALID}${DD}.log", // Mixed valid/invalid
        "unclosed${YYYY.log",         // Unclosed placeholder
        "${}.log",                    // Empty placeholder
        "$YYYY.log",                  // Missing braces
        "{YYYY}.log",                 // Missing $
        "${YYYY${MM}.log"             // Malformed nesting
    };

    for (const auto& pattern : invalidPatterns)
    {
        auto config = defaultConfig;
        config.pattern = pattern;
        config.maxSize = 0; // Disable size rotation to test pure pattern validation

        if (pattern == "no_placeholders.log")
        {
            EXPECT_THROW(createBasicHandler("invalid-pattern", config), std::runtime_error)
                << "Pattern should be invalid: " << pattern;
        }
        else
        {
            // Other patterns might be valid but produce unexpected results
            // The goal is to ensure no crashes occur
            try
            {
                auto handler = createBasicHandler("pattern-test", config);
                auto writer = handler->createWriter();
                (*writer)("test");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            catch (const std::runtime_error& e)
            {
                // May throw for invalid patterns - this is acceptable
            }
        }
    }
}

// Test thread interruption and cleanup
TEST_F(ChannelHandlerTest, ThreadInterruptionAndCleanup)
{
    auto handler = createBasicHandler("interrupt-test");

    {
        auto writer = handler->createWriter();
        (*writer)("message before destruction");

        // Rapidly create and destroy writers to test thread lifecycle
        for (int i = 0; i < 10; ++i)
        {
            auto tempWriter = handler->createWriter();
            (*tempWriter)("rapid message " + std::to_string(i));
            // tempWriter destroyed immediately
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    // Main writer destroyed

    std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Allow cleanup
    EXPECT_EQ(handler->getActiveWritersCount(), 0);              // Should be 0 after destruction

    // Create new writer after all others destroyed
    auto newWriter = handler->createWriter();
    (*newWriter)("message after restart");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 1); // Should be 1 now

    // Cleanup
    newWriter.reset(); // Should stop thread again
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0); // No active writers
}

// Test memory pressure with large buffer sizes
TEST_F(ChannelHandlerTest, MemoryPressureTest)
{
    auto config = defaultConfig;
    config.bufferSize = 1 << 16; // 64K buffer

    auto handler = createBasicHandler("memory-test", config);
    auto writer = handler->createWriter();

    // Rapidly enqueue many messages to test buffer behavior
    for (int i = 0; i < 1000; ++i)
    {
        (*writer)("Memory pressure test message " + std::to_string(i) + " " + std::string(100, 'M'));
    }

    // Don't wait - test immediate destruction while queue is full
}

// Test file size tracking with existing files (module restart scenario)
TEST_F(ChannelHandlerTest, ExistingFileResumption)
{
    const std::string channelName = "resume-test";
    const std::string predefinedContent = "Previous log line 1\nPrevious log line 2\nPrevious log line 3\n";

    // Create a predefined log file with content
    auto expectedFileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-resume-test-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();

    auto expectedFilePath = tmpDir / expectedFileName;
    {
        std::ofstream preExistingFile(expectedFilePath);
        preExistingFile << predefinedContent;
        preExistingFile.flush();
        preExistingFile.close();
    }

    // Verify file was created with expected size
    auto preExistingSize = std::filesystem::file_size(expectedFilePath);
    EXPECT_EQ(preExistingSize, predefinedContent.size());

    // Create channel handler - should detect and correctly size the existing file
    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    // Add new content
    const std::string newContent = "New log line after restart";
    (*writer)(std::string(newContent));

    // Wait for async write
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify final file contains both old and new content
    auto finalContent = readFileContents(expectedFilePath);
    EXPECT_TRUE(finalContent.find("Previous log line 1") != std::string::npos);
    EXPECT_TRUE(finalContent.find("Previous log line 2") != std::string::npos);
    EXPECT_TRUE(finalContent.find("Previous log line 3") != std::string::npos);
    EXPECT_TRUE(finalContent.find(newContent) != std::string::npos);

    // Verify file size tracking
    auto finalSize = std::filesystem::file_size(expectedFilePath);
    EXPECT_GT(finalSize, preExistingSize);

    // Content should be appended (old + new + newlines)
    auto expectedFinalSize = predefinedContent.size() + newContent.size() + 1; // +1 for newline
    EXPECT_EQ(finalSize, expectedFinalSize);
}

// Test file size tracking with rotation and existing files
TEST_F(ChannelHandlerTest, ExistingFileWithRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20; // 1 MB its the default minimum
    config.pattern = "resume-rotation-${counter}.log";

    const std::string channelName = "resume-rotation";

    // Create existing file with content near rotation threshold
    auto initialFilePath = tmpDir / "resume-rotation-0.log";
    const std::string existingContent = std::string(config.maxSize - 20, 'X'); // Slightly under 1MB
    {
        std::ofstream existingFile(initialFilePath);
        existingFile << existingContent;
        existingFile.flush();
    }

    auto existingSize = std::filesystem::file_size(initialFilePath);
    EXPECT_EQ(existingSize, existingContent.size());

    // Create handler - should resume from existing file
    auto handler = createBasicHandler(channelName, config);
    auto writer = handler->createWriter();

    // Add content that should trigger rotation (exceeds maxSize)
    const std::string newContent = std::string(25, 'Y');
    (*writer)(std::string(newContent));

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Should have rotated to new file
    auto rotatedFilePath = tmpDir / "resume-rotation-1.log";
    EXPECT_TRUE(std::filesystem::exists(rotatedFilePath));

    // Original file should contain old content only
    auto finalOriginalContent = readFileContents(initialFilePath);
    EXPECT_TRUE(finalOriginalContent.find(std::string(0x1 << 20 - 20, 'X')) != std::string::npos);
    EXPECT_TRUE(finalOriginalContent.find(newContent) == std::string::npos);

    // New file should contain new content
    auto newFileContent = readFileContents(rotatedFilePath);
    EXPECT_TRUE(newFileContent.find(newContent) != std::string::npos);

    // Verify sizes
    auto finalOriginalSize = std::filesystem::file_size(initialFilePath);
    EXPECT_EQ(finalOriginalSize, existingContent.size());

    auto newFileSize = std::filesystem::file_size(rotatedFilePath);
    EXPECT_EQ(newFileSize, newContent.size() + 1); // +1 for newline
}

// Test file size tracking accuracy with multiple writes
TEST_F(ChannelHandlerTest, FileSizeTrackingAccuracy)
{
    const std::string channelName = "size-accuracy";

    // Pre-populate file with known content
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-size-accuracy-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();

    auto filePath = tmpDir / fileName;
    const std::vector<std::string> existingLines = {
        "Line 1: Initial content", "Line 2: More initial content", "Line 3: Final initial content"};

    size_t expectedSize = 0;
    {
        std::ofstream file(filePath);
        for (const auto& line : existingLines)
        {
            file << line << "\n";
            expectedSize += line.size() + 1; // +1 for newline
        }
        file.flush();
    }

    // Verify initial file size
    auto actualInitialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(actualInitialSize, expectedSize);

    // Create handler and add more content
    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    // Add several new lines and track expected size
    const std::vector<std::string> newLines = {
        "New line 1 after restart",
        "New line 2 with different length",
        "Short",
        "This is a much longer line with more content to test size tracking accuracy"};

    for (const auto& line : newLines)
    {
        (*writer)(std::string(line));
        expectedSize += line.size() + 1; // +1 for newline
    }

    // Wait for all writes to complete
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify final file size matches expected
    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(finalSize, expectedSize);

    // Verify content integrity
    auto content = readFileContents(filePath);
    for (const auto& line : existingLines)
    {
        EXPECT_TRUE(content.find(line) != std::string::npos) << "Missing existing line: " << line;
    }
    for (const auto& line : newLines)
    {
        EXPECT_TRUE(content.find(line) != std::string::npos) << "Missing new line: " << line;
    }

    // Count actual lines
    size_t lineCount = countLines(filePath);
    EXPECT_EQ(lineCount, existingLines.size() + newLines.size());
}

// Test file size tracking with empty existing file
TEST_F(ChannelHandlerTest, EmptyExistingFileResumption)
{
    const std::string channelName = "empty-resume";

    // Create empty existing file
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-empty-resume-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    {
        std::ofstream emptyFile(filePath);
        // Create but don't write anything
    }

    // Verify file exists and is empty
    EXPECT_TRUE(std::filesystem::exists(filePath));
    EXPECT_EQ(std::filesystem::file_size(filePath), 0);

    // Create handler
    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    // Add content to empty file
    const std::string content = "First line in previously empty file";
    (*writer)(std::string(content));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify size tracking
    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(finalSize, content.size() + 1); // +1 for newline

    // Verify content
    auto fileContent = readFileContents(filePath);
    EXPECT_EQ(fileContent, content + "\n");
}

// Test file size tracking with concurrent writes on existing file
TEST_F(ChannelHandlerTest, ConcurrentWritesToExistingFile)
{
    const std::string channelName = "concurrent-existing";
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-concurrent-existing-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();

    // Create file with existing content
    auto filePath = tmpDir / fileName;
    const std::string existingContent = "Existing content line 1\nExisting content line 2\n";
    {
        std::ofstream file(filePath);
        file << existingContent;
        file.flush();
    }

    auto initialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(initialSize, existingContent.size());

    // Create handler and multiple writers
    auto handler = createBasicHandler(channelName);

    const int numWriters = 3;
    const int messagesPerWriter = 5;
    std::vector<std::future<void>> futures;

    // Launch concurrent writers
    for (int w = 0; w < numWriters; ++w)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&handler, w, messagesPerWriter]()
                                     {
                                         auto writer = handler->createWriter();
                                         for (int m = 0; m < messagesPerWriter; ++m)
                                         {
                                             std::string message =
                                                 "Writer" + std::to_string(w) + "_Message" + std::to_string(m);
                                             (*writer)(std::move(message));
                                             std::this_thread::sleep_for(std::chrono::milliseconds(10));
                                         }
                                     }));
    }

    // Wait for all writers to complete
    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Verify file grew appropriately
    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_GT(finalSize, initialSize);

    // Verify content integrity
    auto content = readFileContents(filePath);
    EXPECT_TRUE(content.find("Existing content line 1") != std::string::npos);
    EXPECT_TRUE(content.find("Existing content line 2") != std::string::npos);

    // Count total lines
    size_t totalLines = countLines(filePath);
    EXPECT_EQ(totalLines, 2 + (numWriters * messagesPerWriter)); // 2 existing + new messages
}

// Test file size tracking with large existing file
TEST_F(ChannelHandlerTest, LargeExistingFileResumption)
{
    const std::string channelName = "large-resume";

    // Create large existing file
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-large-resume-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    const size_t largeContentSize = 10000;                                          // 10KB
    const std::string largeContent = std::string(largeContentSize - 1, 'L') + "\n"; // -1 to account for newline
    {
        std::ofstream file(filePath);
        file << largeContent;
        file.flush();
    }

    auto initialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(initialSize, largeContentSize);

    // Create handler - should correctly detect large file size
    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    // Add small content to large file
    const std::string newContent = "Small addition to large file";
    (*writer)(std::string(newContent));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify size tracking
    auto finalSize = std::filesystem::file_size(filePath);
    auto expectedFinalSize = largeContentSize + newContent.size() + 1; // +1 for newline
    EXPECT_EQ(finalSize, expectedFinalSize);

    // Verify content was appended
    auto content = readFileContents(filePath);
    EXPECT_TRUE(content.find(newContent) != std::string::npos);
    EXPECT_EQ(content.size(), expectedFinalSize); // Content size should match file size
}

// Test file position and append behavior with existing content
TEST_F(ChannelHandlerTest, FileAppendPositioning)
{
    const std::string channelName = "append-position";

    // Create file with known content and exact positioning
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-append-position-%Y-%m-%d.json", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    const std::string marker1 = "FIRST_MARKER";
    const std::string marker2 = "SECOND_MARKER";
    const std::string marker3 = "THIRD_MARKER";

    // Write initial content with specific markers
    {
        std::ofstream file(filePath);
        file << marker1 << "\n";
        file << marker2 << "\n";
        file.flush(); // Ensure content is written
    }

    auto initialSize = std::filesystem::file_size(filePath);
    auto expectedInitialSize = marker1.size() + 1 + marker2.size() + 1; // +1 for each newline
    EXPECT_EQ(initialSize, expectedInitialSize);

    // Create handler - should open file in append mode at the end
    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    // Add third marker
    (*writer)(std::string(marker3));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Read entire file content and verify order
    auto content = readFileContents(filePath);

    // Find positions of markers to verify order
    auto pos1 = content.find(marker1);
    auto pos2 = content.find(marker2);
    auto pos3 = content.find(marker3);

    EXPECT_NE(pos1, std::string::npos) << "First marker not found";
    EXPECT_NE(pos2, std::string::npos) << "Second marker not found";
    EXPECT_NE(pos3, std::string::npos) << "Third marker not found";

    // Verify markers appear in correct order
    EXPECT_LT(pos1, pos2) << "Markers not in correct order: first should come before second";
    EXPECT_LT(pos2, pos3) << "Markers not in correct order: second should come before third";

    // Verify exact content and positioning
    std::vector<std::string> expectedLines = {marker1, marker2, marker3};
    auto actualLines = std::vector<std::string> {};

    std::ifstream file(filePath);
    std::string line;
    while (std::getline(file, line))
    {
        actualLines.push_back(line);
    }

    EXPECT_EQ(actualLines, expectedLines) << "File content doesn't match expected line order";

    // Verify final file size
    auto finalSize = std::filesystem::file_size(filePath);
    auto expectedFinalSize = marker1.size() + 1 + marker2.size() + 1 + marker3.size() + 1;
    EXPECT_EQ(finalSize, expectedFinalSize);
}

// Test channel with exactly 256 character limit name (edge case)
TEST_F(ChannelHandlerTest, LongChannelName)
{
    // Test with a very long but valid channel name
    std::string longName = std::string(200, 'A');

    EXPECT_NO_THROW({
        auto handler = createBasicHandler(longName);
        auto writer = handler->createWriter();
        (*writer)(std::string("test message for long channel name"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });

    // Test with an extremely long name that should be rejected or handled gracefully
    std::string tooLongName = std::string(1000, 'X');

    // This should either work or fail gracefully - important that it doesn't crash
    try
    {
        auto handler = createBasicHandler(tooLongName);
        auto writer = handler->createWriter();
        (*writer)(std::string("test message"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    catch (const std::exception&)
    {
        // Acceptable to throw for too long names
        // Test passes as long as it doesn't crash
    }
}

// ============= COMPRESSION TESTS =============

// Test compression configuration validation
TEST_F(ChannelHandlerTest, CompressionConfigValidation)
{
    // Test valid compression levels
    for (int level = 1; level <= 9; ++level)
    {
        auto config = defaultConfig;
        config.shouldCompress = true;
        config.compressionLevel = level;

        EXPECT_NO_THROW(createBasicHandler("test-channel", config));
    }

    // Test invalid compression levels
    auto config = defaultConfig;
    config.shouldCompress = true;

    // Too low
    config.compressionLevel = 0;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);

    // Too high
    config.compressionLevel = 10;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);

    // Negative
    config.compressionLevel = -1;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);
}

// Test compression enable by default
TEST_F(ChannelHandlerTest, CompressionDisabledByDefault)
{
    auto handler = createBasicHandler("test-channel");
    const auto& config = handler->getConfig();

    // shouldCompress should be true by default
    EXPECT_TRUE(config.shouldCompress);
    EXPECT_EQ(config.compressionLevel, 5); // Default level
}

// Test compression with mock scheduler
TEST_F(ChannelHandlerTest, CompressionWithMockScheduler)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 6;
    config.maxSize = 1 << 20; // 1MB - use the minimum valid size
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    // Create mock scheduler
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Expect scheduleTask to be called when rotation occurs
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [](std::string_view taskName, scheduler::TaskConfig&& config)
            {
                // Verify task configuration
                EXPECT_EQ(config.interval, 0); // One-time task
                EXPECT_EQ(config.CPUPriority, 0);
                EXPECT_EQ(config.timeout, 0);
                EXPECT_NE(config.taskFunction, nullptr);

                // Verify task name format
                std::string taskNameStr(taskName);
                EXPECT_TRUE(taskNameStr.find("CompressLog-test-channel-") == 0);

                // Execute the task function to simulate compression
                config.taskFunction();
            });

    // Set the mock scheduler
    auto handler = createHandlerWithScheduler("test-channel", config, mockScheduler);

    auto writer = handler->createWriter();

    // Write enough data to exceed 1MB and trigger rotation
    const std::string largeMessage(100000, 'X'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Wait for processing and rotations
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Verify that the file was created and compressed
    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().string().find("test-channel") != std::string::npos)
        {
            fileCount++;
            // Check extension to verify compression
            EXPECT_TRUE(entry.path().extension() == ".gz" || entry.path().extension() == ".log"
                        || entry.path().extension() == ".json");
        }
    }

    EXPECT_GE(fileCount, 1) << "No files created";
}

// Test compression without scheduler (should log warning)
TEST_F(ChannelHandlerTest, CompressionWithoutScheduler)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.maxSize = 1 << 20; // 1MB - use valid size
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto handler = createBasicHandler("test-channel", config);
    // Note: We don't set a scheduler here

    auto writer = handler->createWriter();

    // Write enough data to trigger rotation - should not crash despite no scheduler
    const std::string largeMessage(100000, 'B'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test should pass without crashing
    SUCCEED();
}

// Test compression task configuration creation
TEST_F(ChannelHandlerTest, CompressionTaskConfigCreation)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 7;

    auto handler = createBasicHandler("test-channel", config);

    // We can't directly test createCompressionTaskConfig as it's private,
    // but we can verify compression settings are properly stored
    const auto& storedConfig = handler->getConfig();
    EXPECT_TRUE(storedConfig.shouldCompress);
    EXPECT_EQ(storedConfig.compressionLevel, 7);
}

// Test compression with different compression levels
TEST_F(ChannelHandlerTest, CompressionWithDifferentLevels)
{
    using namespace ::testing;

    for (int level = 1; level <= 9; level += 2) // Test odd levels
    {
        auto config = defaultConfig;
        config.shouldCompress = true;
        config.compressionLevel = level;
        config.maxSize = 1 << 20; // 1MB - use valid size
        config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

        auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

        EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
            .Times(AtLeast(1)) // May or may not be called depending on rotation
            .WillRepeatedly(
                [level](std::string_view taskName, scheduler::TaskConfig&& taskConfig)
                {
                    EXPECT_EQ(taskConfig.interval, 0);
                    EXPECT_NE(taskConfig.taskFunction, nullptr);
                    // Execute the task function to ensure it works
                    taskConfig.taskFunction();
                });

        auto handler = createHandlerWithScheduler("test-channel-" + std::to_string(level), config, mockScheduler);

        auto writer = handler->createWriter();
        (*writer)("Test message with compression level " + std::to_string(level));

        // Write enough data to trigger rotation
        const std::string largeMessage(100000, 'C'); // 100KB message
        for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
        {
            (*writer)(largeMessage + std::to_string(i));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // Verify that the file was created
        size_t fileCount = 0;
        size_t compressedFileCount = 0;
        size_t uncompressedFileCount = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
        {
            if (entry.is_regular_file()
                && entry.path().string().find("test-channel-" + std::to_string(level)) != std::string::npos)
            {
                fileCount++;
                // Check extension to verify compression
                if (entry.path().extension() == ".gz")
                {
                    compressedFileCount++;
                }
                else if (entry.path().extension() == ".log" || entry.path().extension() == ".log")
                {
                    uncompressedFileCount++;
                }
                EXPECT_TRUE(entry.path().extension() == ".gz" || entry.path().extension() == ".log");
            }
        }
        EXPECT_GE(fileCount, 3) << "No files created for compression level " << level;
        EXPECT_GE(compressedFileCount, 1) << "No compressed files created for compression level " << level;
        EXPECT_GE(uncompressedFileCount, 2) << "No uncompressed files created for compression level " << level;
        // Clean up for next iteration
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        writer.reset();
        handler.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
        {
            if (entry.is_regular_file()
                && entry.path().string().find("test-channel-" + std::to_string(level)) != std::string::npos)
            {
                std::filesystem::remove(entry.path());
            }
        }
    }
}

// Test compression with time-based rotation
TEST_F(ChannelHandlerTest, CompressionWithTimeRotation)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 4;
    config.maxSize = 0; // No size limit, rely on time-based rotation
    config.pattern = "${YYYY}-${MM}-${DD}-${HH}-${name}.log";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // May not be called if no time change occurs during test
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(AtLeast(0));

    auto handler = createHandlerWithScheduler("test-time-rotation", config, mockScheduler);

    auto writer = handler->createWriter();
    (*writer)("Test message for time-based rotation");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

// Test compression is not triggered when disabled
TEST_F(ChannelHandlerTest, NoCompressionWhenDisabled)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = false; // Explicitly disable compression
    config.maxSize = 1 << 20;      // 1MB - use valid size
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Should never call scheduleTask since compression is disabled
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    auto handler = createHandlerWithScheduler("test-no-compression", config, mockScheduler);

    auto writer = handler->createWriter();

    // Write data that would trigger rotation
    const std::string largeMessage(100000, 'D'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

// Test store persistence functionality - initialization with no previous state
TEST_F(ChannelHandlerTest, StorePersistenceInitializationNoState)
{
    // Configure mock store to return error (no previous state), readInternalDoc can be called multiple times
    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    // Try Save the new state
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto handler = createBasicHandler("store-test");
    EXPECT_NE(handler, nullptr);
}

// Test store persistence functionality - successful initialization with previous state and pending compression
TEST_F(ChannelHandlerTest, StorePersistenceInitializationWithPendingFile)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20; // 1MB
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Create a test file that should be compressed during initialization
    std::string previousFilePath = tmpDir.string() + "/2025-08-25-store-test-5.log"; // Different from current file
    createTestFile(previousFilePath, "Previous file content to be compressed");

    // Configure mock store to return previous state
    json::Json previousState;
    previousState.setString(previousFilePath, "/last_current");

    // readInternalDoc can be called multiple times during operation
    EXPECT_CALL(*mockStore, readInternalDoc(testing::HasSubstr("store-test")))
        .WillRepeatedly(testing::Return(store::mocks::storeReadDocResp(previousState)));

    // Expect compression task to be scheduled for the previous file
    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(1);

    // Store save may or may not be called during initialization - make it optional
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::HasSubstr("store-test"), testing::_))
        .Times(testing::AnyNumber())
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    auto handler = createHandlerWithScheduler("store-test", config, mockScheduler);

    // Wait a moment for initialization
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

// Test store persistence functionality - save current file path during rotation
TEST_F(ChannelHandlerTest, StorePersistenceSaveDuringRotation)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20; // 1MB
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Configure mock store to return no initial state - can be called multiple times
    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    // Expect compression task scheduling during rotation
    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(1);

    // Expect save operation during rotation - can happen multiple times
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::HasSubstr("store-test"), testing::_))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(testing::Return(store::mocks::storeOk()));

    auto handler = createHandlerWithScheduler("store-test", config, mockScheduler);
    auto writer = handler->createWriter();

    // Write data to trigger rotation
    const std::string largeMessage(100000, 'A'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // Total: 1.2MB > 1MB threshold
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    // Wait for rotation and processing
    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

// Test store persistence functionality - store read error handling
TEST_F(ChannelHandlerTest, StorePersistenceReadError)
{
    // Configure mock store to return error, simulating read failure
    // Fail to read last state and fail to read the second time as well
    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    // Save the new state
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto handler = createBasicHandler("store-error-test");
    EXPECT_NE(handler, nullptr); // Should still create handler despite store error
}

// Test store persistence functionality - store save error handling
TEST_F(ChannelHandlerTest, StorePersistenceSaveError)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.maxSize = 1 << 20; // 1MB
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Configure mock store to return no initial state but fail on save - can be called multiple times
    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(1);

    // Simulate save error - allow multiple calls
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(testing::AtLeast(1))
        .WillRepeatedly(testing::Return(store::mocks::storeError()));

    auto handler = createHandlerWithScheduler("store-save-error", config, mockScheduler);
    auto writer = handler->createWriter();

    // Write data to trigger rotation - should not crash on save error
    const std::string largeMessage(100000, 'B');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    // Test passes if no crash occurs despite store save error
}

// Test store persistence functionality - corrupted state handling
TEST_F(ChannelHandlerTest, StorePersistenceCorruptedState)
{
    // Configure mock store to return corrupted state (missing currentFilePath field)
    json::Json corruptedState;
    corruptedState.setString("invalid_data", "/invalid");

    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .Times(2) // Can be called multiple times
        .WillRepeatedly(testing::Return(store::mocks::storeReadDocResp(corruptedState)));

    //  save the new state
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    // Should not attempt compression due to corrupted state
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(0);

    auto handler = createBasicHandler("corrupted-state-test");
    EXPECT_NE(handler, nullptr); // Should handle corrupted state gracefully
}

// Test store persistence functionality - previous file doesn't exist
TEST_F(ChannelHandlerTest, StorePersistencePreviousFileNotFound)
{
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Configure mock store to return state with non-existent file
    std::string nonExistentFile = tmpDir.string() + "/non-existent-file.log";
    json::Json state;
    state.setString(nonExistentFile, "/currentFilePath");

    // Expect call 2 times, 1 for try recover last state and 1 for save the current state
    EXPECT_CALL(*mockStore, readInternalDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadDocResp(state)));

    // Should not schedule compression for non-existent file
    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(0);

    // Should save current state without attempting compression
    EXPECT_CALL(*mockStore, upsertInternalDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto config = defaultConfig;
    config.shouldCompress = true;

    auto handler = createHandlerWithScheduler("missing-file-test", config, mockScheduler);
    EXPECT_NE(handler, nullptr);
}
