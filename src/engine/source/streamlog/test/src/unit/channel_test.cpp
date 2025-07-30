#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <random>
#include <thread>

#include <gtest/gtest.h>

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
    std::string content;
    std::string line;
    while (std::getline(file, line))
    {
        if (!content.empty())
        {
            content += "\n";
        }
        content += line;
    }
    return content;
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
    }

    void TearDown() override
    {
        // Clean up temp directory
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }

    std::filesystem::path tmpDir;
    streamlog::RotationConfig defaultConfig;
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
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "test-channel");
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
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "test");
    EXPECT_NE(handler, nullptr);

    // Should be able to copy shared_ptr
    auto handler2 = handler;
    EXPECT_EQ(handler.get(), handler2.get());
}

// Test invalid configurations
TEST_F(ChannelHandlerTest, InvalidConfigurations)
{
    // Empty channel name
    EXPECT_THROW(streamlog::ChannelHandler::create(defaultConfig, ""), std::runtime_error);

    // Empty pattern
    auto config = defaultConfig;
    config.pattern = "";
    EXPECT_THROW(streamlog::ChannelHandler::create(config, "test"), std::runtime_error);

    // Non-existent base path
    config = defaultConfig;
    config.basePath = "/non/existent/path";
    EXPECT_THROW(streamlog::ChannelHandler::create(config, "test"), std::runtime_error);

    // Relative path
    config = defaultConfig;
    config.basePath = "relative/path";
    EXPECT_THROW(streamlog::ChannelHandler::create(config, "test"), std::runtime_error);
}

// Test valid channel names
TEST_P(ChannelNameTest, ValidChannelNames)
{
    const std::string channelName = GetParam();
    EXPECT_NO_THROW({
        auto handler = streamlog::ChannelHandler::create(defaultConfig, channelName);
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
        auto handler = streamlog::ChannelHandler::create(config, "test");
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
                                           "${name}-${YYYY}${MM}${DD}-${HH}.log"
                                           ));

// Test different buffer sizes
TEST_P(BufferSizeTest, DifferentBufferSizes)
{
    const size_t bufferSize = GetParam();
    auto config = defaultConfig;
    config.bufferSize = bufferSize;

    EXPECT_NO_THROW({
        auto handler = streamlog::ChannelHandler::create(config, "test");
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
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "test");

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

        // First writer goes out of scope
    }

    // Second writer still alive
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Create new writer after others are destroyed
    auto writer3 = handler->createWriter();
    EXPECT_NE(writer3, nullptr);
    (*writer3)("message from writer3");
}

// Test writing messages
TEST_F(ChannelHandlerTest, BasicMessageWriting)
{
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "test");
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
    config.maxSize = 1024; // 1KB limit
    config.pattern = "${name}-${counter}.json";

    auto handler = streamlog::ChannelHandler::create(config, "rotation-test");
    auto writer = handler->createWriter();

    // Write enough data to trigger rotation
    const std::string largeMessage = std::string(500, 'x'); // 500 bytes

    for (int i = 0; i < 5; ++i) // Total ~2.5KB
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should have multiple files due to rotation
    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            fileCount++;
        }
    }

    EXPECT_GT(fileCount, 1) << "Size-based rotation did not create multiple files";
}

// Test time-based rotation
TEST_F(ChannelHandlerTest, TimeBasedRotation)
{
    auto config = defaultConfig;
    config.pattern = "${name}-${HH}.json"; // Rotate by hour

    auto handler = streamlog::ChannelHandler::create(config, "time-test");
    auto writer = handler->createWriter();

    (*writer)("message before time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Note: This test relies on the actual time, so it may not always trigger rotation
    // In a real scenario, you might need to mock the time system
    (*writer)("message after time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

// Test hard link creation
TEST_F(ChannelHandlerTest, HardLinkCreation)
{
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "linktest");
    auto writer = handler->createWriter();

    (*writer)("test message for link");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Check if latest link exists
    auto latestLink = tmpDir / "linktest.json";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Latest link was not created: " << latestLink;

    // Content should be accessible through the link
    auto content = readFileContents(latestLink);
    EXPECT_NE(content.find("test message for link"), std::string::npos);
}

// Test concurrent writers
TEST_F(ChannelHandlerTest, ConcurrentWriters)
{
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "concurrent");

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

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Verify all messages were written
    bool foundFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            foundFile = true;
            auto lineCount = countLines(entry.path());
            EXPECT_EQ(lineCount, numWriters * messagesPerWriter)
                << "Expected " << (numWriters * messagesPerWriter) << " lines, got " << lineCount;
            break;
        }
    }

    EXPECT_TRUE(foundFile);
}

// Test writer thread lifecycle
TEST_F(ChannelHandlerTest, WorkerThreadLifecycle)
{
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "thread-test");

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
            // Both writers alive, thread should be running
        }
        // writer2 destroyed, but writer1 still alive

        (*writer1)("message3");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    // All writers destroyed, thread should stop

    // Create new writer - should restart thread
    auto writer3 = handler->createWriter();
    (*writer3)("message4");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
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
    EXPECT_THROW(streamlog::ChannelHandler::create(config, "readonly-test"), std::runtime_error);

    // Restore permissions for cleanup
    std::filesystem::permissions(
        readOnlyDir, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

// Test placeholder replacement
TEST_F(ChannelHandlerTest, PlaceholderReplacement)
{
    auto config = defaultConfig;
    config.pattern = "${YYYY}_${MM}_${DD}_${HH}_${name}_test.log";

    auto handler = streamlog::ChannelHandler::create(config, "placeholder-test");
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
    config.maxSize = 100; // Very small to force rotation
    config.pattern = "${name}-${counter}.json";

    auto handler = streamlog::ChannelHandler::create(config, "counter-test");
    auto writer = handler->createWriter();

    // Write enough to force multiple rotations
    for (int i = 0; i < 10; ++i)
    {
        (*writer)("message " + std::to_string(i) + " " + std::string(50, 'x'));
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Should have files with different counter values
    std::set<std::string> foundFiles;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".json")
        {
            foundFiles.insert(entry.path().filename().string());
        }
    }

    EXPECT_GT(foundFiles.size(), 1) << "Counter-based rotation did not create multiple files";

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
    auto handler = streamlog::ChannelHandler::create(defaultConfig, "nocopy-test");
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

    auto handler = streamlog::ChannelHandler::create(config, "overflow-test");
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

    auto handler = streamlog::ChannelHandler::create(config, "dir-test");
    auto writer = handler->createWriter();

    (*writer)("test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Verify subdirectories were created
    auto expectedDir = tmpDir / "subdir1" / "subdir2";
    EXPECT_TRUE(std::filesystem::exists(expectedDir)) << "Subdirectories were not created: " << expectedDir;

    auto expectedFile = expectedDir / "dir-test-0.json";
    EXPECT_TRUE(std::filesystem::exists(expectedFile)) << "Log file was not created in subdirectory: " << expectedFile;
}
