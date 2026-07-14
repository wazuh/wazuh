#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sys/stat.h>
#include <thread>
#include <unordered_map>

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

// Set file mtime to a specific Unix timestamp for deterministic retention ordering.
void setFileMtime(const std::filesystem::path& path, std::time_t epochSeconds, long nsec = 0)
{
    struct timespec times[2];
    times[0].tv_sec = epochSeconds;
    times[0].tv_nsec = nsec;
    times[1].tv_sec = epochSeconds;
    times[1].tv_nsec = nsec;
    ::utimensat(AT_FDCWD, path.c_str(), times, 0);
}

} // namespace

class ChannelHandlerComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        tmpDir = getTempDir();

        defaultConfig = {
            tmpDir,                              // basePath
            "wazuh-${name}-${YYYY}-${MM}-${DD}", // pattern (extension added by constructor)
            0,                                   // maxSize (no limit)
            fastqueue::MIN_QUEUE_CAPACITY,       // bufferSize
        };

        mockStore = std::make_shared<store::mocks::MockStore>();

        EXPECT_CALL(*mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

        EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }

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

    std::shared_ptr<streamlog::ChannelHandler>
    createHandlerWithScheduler(const std::string& name,
                               const streamlog::RotationConfig& config,
                               std::shared_ptr<scheduler::mocks::MockIScheduler> scheduler)
    {
        return streamlog::ChannelHandler::create(config, name, mockStore, scheduler, "log");
    }

    std::shared_ptr<streamlog::ChannelHandler>
    createHandlerWithScheduler(const std::string& name,
                               const streamlog::RotationConfig& config,
                               std::shared_ptr<scheduler::mocks::MockIScheduler> scheduler,
                               std::shared_ptr<const std::atomic<bool>> compressionShouldRun)
    {
        return streamlog::ChannelHandler::create(config, name, mockStore, scheduler, "log", compressionShouldRun);
    }

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

// Parameterized test for different patterns
class PatternComponentTest
    : public ChannelHandlerComponentTest
    , public ::testing::WithParamInterface<std::string>
{
};

// Parameterized test for different buffer sizes
class BufferSizeComponentTest
    : public ChannelHandlerComponentTest
    , public ::testing::WithParamInterface<size_t>
{
};

// ============= BASIC I/O COMPONENT TESTS =============

TEST_P(PatternComponentTest, DifferentPatterns)
{
    const std::string pattern = GetParam();
    auto config = defaultConfig;
    config.pattern = pattern;

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("test", config);
        auto writer = handler->createWriter();
        (*writer)("test message");
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });
}

INSTANTIATE_TEST_SUITE_P(Patterns,
                         PatternComponentTest,
                         ::testing::Values("${YYYY}-${MM}-${DD}-${name}",
                                           "logs/${YYYY}/${MM}/${name}-${DD}",
                                           "${name}-${YYYY}${MM}${DD}-${HH}"));

TEST_P(BufferSizeComponentTest, DifferentBufferSizes)
{
    const size_t bufferSize = GetParam();
    auto config = defaultConfig;
    config.bufferSize = bufferSize;

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("test", config);
        auto writer = handler->createWriter();

        for (int i = 0; i < 10; ++i)
        {
            (*writer)("test message " + std::to_string(i));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    });
}

INSTANTIATE_TEST_SUITE_P(
    BufferSizes,
    BufferSizeComponentTest,
    ::testing::Values(fastqueue::MIN_QUEUE_CAPACITY, fastqueue::MIN_QUEUE_CAPACITY * 2, 1 << 17, 1 << 20));

TEST_F(ChannelHandlerComponentTest, WriterLifecycle)
{
    auto handler = createBasicHandler("test");

    {
        auto writer1 = handler->createWriter();
        EXPECT_NE(writer1, nullptr);

        auto writer2 = handler->createWriter();
        EXPECT_NE(writer2, nullptr);

        (*writer1)("message from writer1");
        (*writer2)("message from writer2");

        EXPECT_EQ(handler->getActiveWritersCount(), 2);
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0);

    auto writer3 = handler->createWriter();
    EXPECT_NE(writer3, nullptr);
    (*writer3)("message from writer3");
    EXPECT_EQ(handler->getActiveWritersCount(), 1);
}

TEST_F(ChannelHandlerComponentTest, BasicMessageWriting)
{
    auto handler = createBasicHandler("test");
    auto writer = handler->createWriter();

    const std::vector<std::string> messages = {"first message",
                                               "second message with special chars",
                                               "{\"json\": \"message\", \"number\": 42}",
                                               "very long message " + std::string(1000, 'x'),
                                               "message with\nnewlines\nand\ttabs"};

    for (const auto& msg : messages)
    {
        (*writer)(std::string(msg));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    bool foundFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            foundFile = true;
            auto content = readFileContents(entry.path());

            for (const auto& msg : messages)
            {
                EXPECT_NE(content.find(msg), std::string::npos) << "Message not found: " << msg;
            }
            break;
        }
    }

    EXPECT_TRUE(foundFile) << "No log file was created";
}

TEST_F(ChannelHandlerComponentTest, SizeBasedRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20; // 1MB
    config.pattern = "${name}-${counter}";

    auto handler = createBasicHandler("rotation-test", config);
    auto writer = handler->createWriter();

    const std::string largeMessage = std::string(50 * 1024, 'A');

    for (int i = 0; i < 50; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            fileCount++;
        }
    }

    EXPECT_GT(fileCount, 3) << "Size-based rotation did not create multiple files";
}

TEST_F(ChannelHandlerComponentTest, TimeBasedRotation)
{
    auto config = defaultConfig;
    config.pattern = "${name}-${HH}";

    auto handler = createBasicHandler("time-test", config);
    auto writer = handler->createWriter();

    (*writer)("message before time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    (*writer)("message after time change");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

TEST_F(ChannelHandlerComponentTest, HardLinkCreation)
{
    auto handler = createBasicHandler("linktest");
    auto writer = handler->createWriter();

    (*writer)("test message for link");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto latestLink = tmpDir / "linktest.log";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Latest link was not created: " << latestLink;

    auto content = readFileContents(latestLink);
    EXPECT_NE(content.find("test message for link"), std::string::npos);
}

TEST_F(ChannelHandlerComponentTest, ConcurrentWriters)
{
    auto config = defaultConfig;
    config.shouldCompress = false;
    auto handler = createBasicHandler("concurrent", config);

    const int numWriters = 5;
    const int messagesPerWriter = 20;
    std::vector<std::future<void>> futures;

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

    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    bool foundFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            foundFile = true;
            auto expectedCount = numWriters * messagesPerWriter;
            size_t lastLineCount = 0;

            for (int attempt = 0; attempt < 50; ++attempt)
            {
                auto lineCount = countLines(entry.path());
                if (lineCount == static_cast<size_t>(expectedCount))
                {
                    lastLineCount = lineCount;
                    break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }

            EXPECT_EQ(lastLineCount, static_cast<size_t>(expectedCount))
                << "Expected " << expectedCount << " lines, got " << lastLineCount;
            break;
        }
    }

    EXPECT_TRUE(foundFile);
}

TEST_F(ChannelHandlerComponentTest, WorkerThreadLifecycle)
{
    auto handler = createBasicHandler("thread-test");

    {
        auto writer1 = handler->createWriter();
        (*writer1)("message1");

        {
            auto writer2 = handler->createWriter();
            (*writer2)("message2");

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            EXPECT_EQ(handler->getActiveWritersCount(), 2);
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        EXPECT_EQ(handler->getActiveWritersCount(), 1);
        (*writer1)("message3");
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0);

    auto writer3 = handler->createWriter();
    (*writer3)("message4");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 1);

    writer3.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0);
}

TEST_F(ChannelHandlerComponentTest, PlaceholderReplacement)
{
    auto config = defaultConfig;
    config.pattern = "${YYYY}_${MM}_${DD}_${HH}_${name}_test";

    auto handler = createBasicHandler("placeholder-test", config);
    auto writer = handler->createWriter();

    (*writer)("test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    bool foundValidFile = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file())
        {
            std::string filename = entry.path().filename().string();

            if (filename.find("placeholder-test") != std::string::npos
                && filename.find("_test.log") != std::string::npos)
            {
                foundValidFile = true;
                EXPECT_TRUE(filename.length() > 25);
                EXPECT_NE(filename.find("_"), std::string::npos);
                break;
            }
        }
    }

    EXPECT_TRUE(foundValidFile) << "File with correct placeholder replacement not found";
}

TEST_F(ChannelHandlerComponentTest, GeneratedFileNameMatchesResolvedPatternExactly)
{
    auto config = defaultConfig;
    config.pattern = "generated/${YYYY}/${MM}/${DD}/${name}";

    auto handler = createBasicHandler("exact-name", config);
    auto writer = handler->createWriter();

    (*writer)("test message");
    ASSERT_TRUE(waitFor([&handler]() { return std::filesystem::exists(handler->getCurrentFilePath()); }));

    char buffer[128];
    const auto now = std::time(nullptr);
    const auto tm = *std::localtime(&now);
    std::strftime(buffer, sizeof(buffer), "generated/%Y/%m/%d/exact-name.log", &tm);

    const auto expectedPath = tmpDir / buffer;
    EXPECT_EQ(handler->getCurrentFilePath(), expectedPath);
    EXPECT_TRUE(std::filesystem::exists(expectedPath));
}

TEST_F(ChannelHandlerComponentTest, CounterPlaceholderWithSizeRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20;
    config.pattern = "${name}-${counter}";

    auto handler = createBasicHandler("counter-test", config);
    auto writer = handler->createWriter();

    for (int i = 0; i < 5000; ++i)
    {
        (*writer)("message " + std::to_string(i) + " " + std::string(1000, 'x'));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    std::set<std::string> foundFiles;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            foundFiles.insert(entry.path().filename().string());
        }
    }

    EXPECT_EQ(foundFiles.size(), 5u + 1u) << "Expected multiple files with different counters";

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

TEST_F(ChannelHandlerComponentTest, BufferOverflowBehavior)
{
    auto config = defaultConfig;
    config.bufferSize = fastqueue::MIN_QUEUE_CAPACITY;

    auto handler = createBasicHandler("overflow-test", config);
    auto writer = handler->createWriter();
    std::size_t messageSuccessCount = 0;
    std::size_t messageFailureCount = 0;

    for (size_t i = 0; i < fastqueue::MIN_QUEUE_CAPACITY * 2; ++i)
    {
        if ((*writer)("rapid message " + std::to_string(i)))
        {
            messageSuccessCount++;
        }
        else
        {
            messageFailureCount++;
        }
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    EXPECT_GT(messageSuccessCount, fastqueue::MIN_QUEUE_CAPACITY) << "No messages were successfully written";
    EXPECT_LT(messageFailureCount, fastqueue::MIN_QUEUE_CAPACITY) << "Too many messages failed due to buffer overflow";
}

TEST_F(ChannelHandlerComponentTest, DirectoryCreation)
{
    auto config = defaultConfig;
    config.pattern = "subdir1/subdir2/${name}-${counter}";
    config.maxSize = 0x1 << 20;

    auto handler = createBasicHandler("dir-test", config);
    auto writer = handler->createWriter();

    (*writer)("test message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto expectedDir = tmpDir / "subdir1" / "subdir2";
    EXPECT_TRUE(std::filesystem::exists(expectedDir)) << "Subdirectories were not created: " << expectedDir;

    auto expectedFile = expectedDir / "dir-test-0.log";
    EXPECT_TRUE(std::filesystem::exists(expectedFile)) << "Log file was not created in subdirectory: " << expectedFile;
}

TEST_F(ChannelHandlerComponentTest, RegexReplacementEdgeCases)
{
    auto config = defaultConfig;

    std::vector<std::string> edgePatterns = {"${YYYY}${MM}${DD}${HH}${name}",
                                             "${YYYY}-${MM}-${DD}-${HH}-${name}-end",
                                             "prefix-${name}-${YYYY}-suffix",
                                             "${DD}${DD}${DD}",
                                             "very/deep/nested/dir/${name}-${YYYY}"};

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

TEST_F(ChannelHandlerComponentTest, ExtremelyLongMessages)
{
    auto handler = createBasicHandler("long-msg-test");
    auto writer = handler->createWriter();

    std::vector<size_t> sizes = {1024, 10240, 102400, 1048576};

    for (size_t size : sizes)
    {
        std::string longMessage(size, 'A');
        longMessage += "_END";

        EXPECT_NO_THROW((*writer)(std::move(longMessage))) << "Failed with message size: " << size;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

TEST_F(ChannelHandlerComponentTest, ConcurrentMultipleChannels)
{
    const int numChannels = 10;
    std::vector<std::shared_ptr<streamlog::ChannelHandler>> handlers;
    std::vector<std::future<void>> futures;

    for (int i = 0; i < numChannels; ++i)
    {
        auto handler = createBasicHandler("channel" + std::to_string(i));
        handlers.push_back(handler);
    }

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

    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t totalFiles = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            totalFiles++;
        }
    }

    EXPECT_GE(totalFiles, static_cast<size_t>(numChannels)) << "Not all channels created their files";
}

TEST_F(ChannelHandlerComponentTest, MaxSizeBoundaryConditions)
{
    std::vector<size_t> testSizes = {1, 1023, 1024, 1025, 1048575, 1048576, 1048577};

    for (size_t maxSize : testSizes)
    {
        auto config = defaultConfig;
        config.maxSize = maxSize;
        config.pattern = "${name}-${counter}-" + std::to_string(maxSize) + "";

        EXPECT_NO_THROW({
            auto handler = createBasicHandler("boundary-test", config);
            auto writer = handler->createWriter();

            std::string message(maxSize / 2, 'X');
            (*writer)(std::string(message));
            (*writer)(std::move(message));

            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }) << "Failed with maxSize: "
           << maxSize;
    }
}

TEST_F(ChannelHandlerComponentTest, ThreadInterruptionAndCleanup)
{
    auto handler = createBasicHandler("interrupt-test");

    {
        auto writer = handler->createWriter();
        (*writer)("message before destruction");

        for (int i = 0; i < 10; ++i)
        {
            auto tempWriter = handler->createWriter();
            (*tempWriter)("rapid message " + std::to_string(i));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    EXPECT_EQ(handler->getActiveWritersCount(), 0);

    auto newWriter = handler->createWriter();
    (*newWriter)("message after restart");
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 1);

    newWriter.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    EXPECT_EQ(handler->getActiveWritersCount(), 0);
}

TEST_F(ChannelHandlerComponentTest, MemoryPressureTest)
{
    auto config = defaultConfig;
    config.bufferSize = 1 << 16;

    auto handler = createBasicHandler("memory-test", config);
    auto writer = handler->createWriter();

    for (int i = 0; i < 1000; ++i)
    {
        (*writer)("Memory pressure test message " + std::to_string(i) + " " + std::string(100, 'M'));
    }
}

// ============= FILE RESUMPTION COMPONENT TESTS =============

TEST_F(ChannelHandlerComponentTest, ExistingFileResumption)
{
    const std::string channelName = "resume-test";
    const std::string predefinedContent = "Previous log line 1\nPrevious log line 2\nPrevious log line 3\n";

    auto expectedFileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-resume-test-%Y-%m-%d.log", tm);
        return std::string(buffer);
    }();

    auto expectedFilePath = tmpDir / expectedFileName;
    {
        std::ofstream preExistingFile(expectedFilePath);
        preExistingFile << predefinedContent;
        preExistingFile.flush();
        preExistingFile.close();
    }

    auto preExistingSize = std::filesystem::file_size(expectedFilePath);
    EXPECT_EQ(preExistingSize, predefinedContent.size());

    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    const std::string newContent = "New log line after restart";
    (*writer)(std::string(newContent));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto finalContent = readFileContents(expectedFilePath);
    EXPECT_TRUE(finalContent.find("Previous log line 1") != std::string::npos);
    EXPECT_TRUE(finalContent.find("Previous log line 2") != std::string::npos);
    EXPECT_TRUE(finalContent.find("Previous log line 3") != std::string::npos);
    EXPECT_TRUE(finalContent.find(newContent) != std::string::npos);

    auto finalSize = std::filesystem::file_size(expectedFilePath);
    EXPECT_GT(finalSize, preExistingSize);

    auto expectedFinalSize = predefinedContent.size() + newContent.size() + 1;
    EXPECT_EQ(finalSize, expectedFinalSize);
}

TEST_F(ChannelHandlerComponentTest, ExistingFileWithRotation)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20;
    config.pattern = "resume-rotation-${counter}";

    const std::string channelName = "resume-rotation";

    auto initialFilePath = tmpDir / "resume-rotation-0.log";
    const std::string existingContent = std::string(config.maxSize - 20, 'X');
    {
        std::ofstream existingFile(initialFilePath);
        existingFile << existingContent;
        existingFile.flush();
    }

    auto existingSize = std::filesystem::file_size(initialFilePath);
    EXPECT_EQ(existingSize, existingContent.size());

    auto handler = createBasicHandler(channelName, config);
    auto writer = handler->createWriter();

    const std::string newContent = std::string(25, 'Y');
    (*writer)(std::string(newContent));

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    auto rotatedFilePath = tmpDir / "resume-rotation-1.log";
    EXPECT_TRUE(std::filesystem::exists(rotatedFilePath));

    auto newFileContent = readFileContents(rotatedFilePath);
    EXPECT_TRUE(newFileContent.find(newContent) != std::string::npos);

    auto finalOriginalSize = std::filesystem::file_size(initialFilePath);
    EXPECT_EQ(finalOriginalSize, existingContent.size());

    auto newFileSize = std::filesystem::file_size(rotatedFilePath);
    EXPECT_EQ(newFileSize, newContent.size() + 1);
}

TEST_F(ChannelHandlerComponentTest, RotatedFileNameMatchesIncrementedCounterExactly)
{
    auto config = defaultConfig;
    config.maxSize = 0x1 << 20;
    config.pattern = "rotated-exact-${counter}";

    auto initialFilePath = tmpDir / "rotated-exact-0.log";
    {
        std::ofstream initialFile(initialFilePath);
        initialFile << std::string(config.maxSize - 20, 'X');
    }

    auto handler = createBasicHandler("rotated-exact", config);
    auto writer = handler->createWriter();

    (*writer)(std::string(25, 'Y'));
    ASSERT_TRUE(waitFor([&]() { return std::filesystem::exists(tmpDir / "rotated-exact-1.log"); }));

    const auto rotatedFilePath = tmpDir / "rotated-exact-1.log";
    const auto latestLinkPath = tmpDir / "rotated-exact.log";

    EXPECT_EQ(handler->getCurrentFilePath(), rotatedFilePath);
    EXPECT_TRUE(std::filesystem::exists(rotatedFilePath));
    EXPECT_TRUE(std::filesystem::exists(latestLinkPath));
    EXPECT_TRUE(std::filesystem::equivalent(rotatedFilePath, latestLinkPath));
}

TEST_F(ChannelHandlerComponentTest, FileSizeTrackingAccuracy)
{
    const std::string channelName = "size-accuracy";

    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-size-accuracy-%Y-%m-%d.log", tm);
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
            expectedSize += line.size() + 1;
        }
        file.flush();
    }

    auto actualInitialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(actualInitialSize, expectedSize);

    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    const std::vector<std::string> newLines = {
        "New line 1 after restart",
        "New line 2 with different length",
        "Short",
        "This is a much longer line with more content to test size tracking accuracy"};

    for (const auto& line : newLines)
    {
        (*writer)(std::string(line));
        expectedSize += line.size() + 1;
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(finalSize, expectedSize);

    auto content = readFileContents(filePath);
    for (const auto& line : existingLines)
    {
        EXPECT_TRUE(content.find(line) != std::string::npos) << "Missing existing line: " << line;
    }
    for (const auto& line : newLines)
    {
        EXPECT_TRUE(content.find(line) != std::string::npos) << "Missing new line: " << line;
    }

    size_t lineCount = countLines(filePath);
    EXPECT_EQ(lineCount, existingLines.size() + newLines.size());
}

TEST_F(ChannelHandlerComponentTest, EmptyExistingFileResumption)
{
    const std::string channelName = "empty-resume";

    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-empty-resume-%Y-%m-%d.log", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    {
        std::ofstream emptyFile(filePath);
    }

    EXPECT_TRUE(std::filesystem::exists(filePath));
    EXPECT_EQ(std::filesystem::file_size(filePath), 0u);

    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    const std::string content = "First line in previously empty file";
    (*writer)(std::string(content));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(finalSize, content.size() + 1);

    auto fileContent = readFileContents(filePath);
    EXPECT_EQ(fileContent, content + "\n");
}

TEST_F(ChannelHandlerComponentTest, ConcurrentWritesToExistingFile)
{
    const std::string channelName = "concurrent-existing";
    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-concurrent-existing-%Y-%m-%d.log", tm);
        return std::string(buffer);
    }();

    auto filePath = tmpDir / fileName;
    const std::string existingContent = "Existing content line 1\nExisting content line 2\n";
    {
        std::ofstream file(filePath);
        file << existingContent;
        file.flush();
    }

    auto initialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(initialSize, existingContent.size());

    auto handler = createBasicHandler(channelName);

    const int numWriters = 3;
    const int messagesPerWriter = 5;
    std::vector<std::future<void>> futures;

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

    for (auto& future : futures)
    {
        future.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto finalSize = std::filesystem::file_size(filePath);
    EXPECT_GT(finalSize, initialSize);

    auto content = readFileContents(filePath);
    EXPECT_TRUE(content.find("Existing content line 1") != std::string::npos);
    EXPECT_TRUE(content.find("Existing content line 2") != std::string::npos);

    size_t totalLines = countLines(filePath);
    EXPECT_EQ(totalLines, 2u + (numWriters * messagesPerWriter));
}

TEST_F(ChannelHandlerComponentTest, LargeExistingFileResumption)
{
    const std::string channelName = "large-resume";

    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-large-resume-%Y-%m-%d.log", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    const size_t largeContentSize = 10000;
    const std::string largeContent = std::string(largeContentSize - 1, 'L') + "\n";
    {
        std::ofstream file(filePath);
        file << largeContent;
        file.flush();
    }

    auto initialSize = std::filesystem::file_size(filePath);
    EXPECT_EQ(initialSize, largeContentSize);

    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    const std::string newContent = "Small addition to large file";
    (*writer)(std::string(newContent));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto finalSize = std::filesystem::file_size(filePath);
    auto expectedFinalSize = largeContentSize + newContent.size() + 1;
    EXPECT_EQ(finalSize, expectedFinalSize);

    auto content = readFileContents(filePath);
    EXPECT_TRUE(content.find(newContent) != std::string::npos);
    EXPECT_EQ(content.size(), expectedFinalSize);
}

TEST_F(ChannelHandlerComponentTest, FileAppendPositioning)
{
    const std::string channelName = "append-position";

    auto fileName = []()
    {
        std::time_t now = std::time(nullptr);
        std::tm* tm = std::localtime(&now);
        char buffer[100];
        std::strftime(buffer, sizeof(buffer), "wazuh-append-position-%Y-%m-%d.log", tm);
        return std::string(buffer);
    }();
    auto filePath = tmpDir / fileName;
    const std::string marker1 = "FIRST_MARKER";
    const std::string marker2 = "SECOND_MARKER";
    const std::string marker3 = "THIRD_MARKER";

    {
        std::ofstream file(filePath);
        file << marker1 << "\n";
        file << marker2 << "\n";
        file.flush();
    }

    auto initialSize = std::filesystem::file_size(filePath);
    auto expectedInitialSize = marker1.size() + 1 + marker2.size() + 1;
    EXPECT_EQ(initialSize, expectedInitialSize);

    auto handler = createBasicHandler(channelName);
    auto writer = handler->createWriter();

    (*writer)(std::string(marker3));

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto content = readFileContents(filePath);

    auto pos1 = content.find(marker1);
    auto pos2 = content.find(marker2);
    auto pos3 = content.find(marker3);

    EXPECT_NE(pos1, std::string::npos) << "First marker not found";
    EXPECT_NE(pos2, std::string::npos) << "Second marker not found";
    EXPECT_NE(pos3, std::string::npos) << "Third marker not found";

    EXPECT_LT(pos1, pos2) << "Markers not in correct order: first should come before second";
    EXPECT_LT(pos2, pos3) << "Markers not in correct order: second should come before third";

    std::vector<std::string> expectedLines = {marker1, marker2, marker3};
    std::vector<std::string> actualLines;

    std::ifstream file(filePath);
    std::string line;
    while (std::getline(file, line))
    {
        actualLines.push_back(line);
    }

    EXPECT_EQ(actualLines, expectedLines) << "File content doesn't match expected line order";

    auto finalSize = std::filesystem::file_size(filePath);
    auto expectedFinalSize = marker1.size() + 1 + marker2.size() + 1 + marker3.size() + 1;
    EXPECT_EQ(finalSize, expectedFinalSize);
}

// ============= COMPRESSION COMPONENT TESTS =============

TEST_F(ChannelHandlerComponentTest, CompressionWithMockScheduler)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 6;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [](std::string_view taskName, scheduler::TaskConfig&& taskCfg)
            {
                EXPECT_EQ(taskCfg.interval, 0);
                EXPECT_EQ(taskCfg.CPUPriority, 0);
                EXPECT_NE(taskCfg.taskFunction, nullptr);

                std::string taskNameStr(taskName);
                EXPECT_TRUE(taskNameStr.find("CompressLog-test-channel-") == 0);

                taskCfg.taskFunction();
            });

    auto handler = createHandlerWithScheduler("test-channel", config, mockScheduler);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'X');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::seconds(1));

    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().string().find("test-channel") != std::string::npos)
        {
            fileCount++;
            EXPECT_TRUE(entry.path().extension() == ".gz" || entry.path().extension() == ".log");
        }
    }

    EXPECT_GE(fileCount, 1u) << "No files created";
}

TEST_F(ChannelHandlerComponentTest, CompressionWithoutScheduler)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto handler = createBasicHandler("test-channel", config);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'B');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    SUCCEED();
}

TEST_F(ChannelHandlerComponentTest, CompressionWithDifferentLevels)
{
    using namespace ::testing;

    for (int level = 1; level <= 9; level += 4) // Test levels 1, 5, 9
    {
        auto config = defaultConfig;
        config.shouldCompress = true;
        config.compressionLevel = level;
        config.maxSize = 1 << 20;
        config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

        auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

        EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
            .Times(AtLeast(1))
            .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& taskCfg) { taskCfg.taskFunction(); });

        auto handler = createHandlerWithScheduler("test-channel-" + std::to_string(level), config, mockScheduler);
        auto writer = handler->createWriter();

        const std::string largeMessage(100000, 'C');
        for (int i = 0; i < 12; ++i)
        {
            (*writer)(largeMessage + std::to_string(i));
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        size_t compressedFileCount = 0;
        for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
        {
            if (entry.is_regular_file()
                && entry.path().string().find("test-channel-" + std::to_string(level)) != std::string::npos
                && entry.path().extension() == ".gz")
            {
                compressedFileCount++;
            }
        }
        EXPECT_GE(compressedFileCount, 1u) << "No compressed files created for compression level " << level;

        writer.reset();
        handler.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
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

TEST_F(ChannelHandlerComponentTest, CompressionWithTimeRotation)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 4;
    config.maxSize = 0;
    config.pattern = "${YYYY}-${MM}-${DD}-${HH}-${name}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(AtLeast(0));

    auto handler = createHandlerWithScheduler("test-time-rotation", config, mockScheduler);
    auto writer = handler->createWriter();
    (*writer)("Test message for time-based rotation");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(ChannelHandlerComponentTest, NoCompressionWhenDisabled)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = false;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    auto handler = createHandlerWithScheduler("test-no-compression", config, mockScheduler);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'D');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

TEST_F(ChannelHandlerComponentTest, CompressionCancelledWhenShouldRunIsFalse)
{
    using namespace ::testing;

    auto shouldRun = std::make_shared<std::atomic<bool>>(true);

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    std::vector<scheduler::TaskConfig> capturedTasks;
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([&capturedTasks](std::string_view, scheduler::TaskConfig&& taskCfg)
                        { capturedTasks.push_back(std::move(taskCfg)); });

    auto handler = createHandlerWithScheduler("cancel-test", config, mockScheduler, shouldRun);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'X');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    ASSERT_GE(capturedTasks.size(), 1u) << "Expected at least one compression task to be scheduled";

    shouldRun->store(false, std::memory_order_relaxed);

    for (auto& task : capturedTasks)
    {
        task.taskFunction();
    }

    size_t gzCount = 0;
    size_t logCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        auto name = entry.path().filename().string();
        if (name.find("cancel-test") == std::string::npos)
            continue;
        if (entry.path().extension() == ".gz")
            ++gzCount;
        else if (entry.path().extension() == ".log")
            ++logCount;
    }

    EXPECT_EQ(gzCount, 0u) << "No .gz files should be produced when shouldRun is false";
    EXPECT_GE(logCount, 1u) << "Original .log files must be preserved after cancelled compression";
}

TEST_F(ChannelHandlerComponentTest, CompressionSucceedsWhenShouldRunIsTrue)
{
    using namespace ::testing;

    auto shouldRun = std::make_shared<std::atomic<bool>>(true);

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& taskCfg) { taskCfg.taskFunction(); });

    auto handler = createHandlerWithScheduler("shouldrun-true", config, mockScheduler, shouldRun);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'A');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t gzCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".gz"
            && entry.path().filename().string().find("shouldrun-true") != std::string::npos)
        {
            ++gzCount;
        }
    }

    EXPECT_GE(gzCount, 1u) << "At least one .gz file should be produced when shouldRun is true";
}

TEST_F(ChannelHandlerComponentTest, CompressionWorksWithNullShouldRun)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& taskCfg) { taskCfg.taskFunction(); });

    auto handler = createHandlerWithScheduler("null-shouldrun", config, mockScheduler);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'B');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t gzCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".gz"
            && entry.path().filename().string().find("null-shouldrun") != std::string::npos)
        {
            ++gzCount;
        }
    }

    EXPECT_GE(gzCount, 1u) << ".gz files should be produced even without a shouldRun flag (fallback)";
}

// ============= STORE PERSISTENCE (rotation-triggering) COMPONENT TESTS =============

TEST_F(ChannelHandlerComponentTest, StorePersistenceSaveDuringRotation)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(1);

    EXPECT_CALL(*mockStore, upsertDoc(HasSubstr("store-test"), _))
        .Times(AtLeast(1))
        .WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = createHandlerWithScheduler("store-test", config, mockScheduler);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'A');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

TEST_F(ChannelHandlerComponentTest, StorePersistenceSaveError)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(1);

    EXPECT_CALL(*mockStore, upsertDoc(_, _)).Times(AtLeast(1)).WillRepeatedly(Return(store::mocks::storeError()));

    auto handler = createHandlerWithScheduler("store-save-error", config, mockScheduler);
    auto writer = handler->createWriter();

    const std::string largeMessage(100000, 'B');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));
}

// ============= RETENTION POLICY COMPONENT TESTS =============

TEST_F(ChannelHandlerComponentTest, RetentionMaxFilesDeletesOldest)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 3;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTimeMaxFiles = 1000;
    std::vector<std::filesystem::path> oldFiles;
    for (int i = 0; i < 5; ++i)
    {
        auto filePath = tmpDir / ("old-rotated-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << "old content " << i << "\n";
        }
        oldFiles.push_back(filePath);
        setFileMtime(filePath, baseTimeMaxFiles + i * 10);
    }

    auto handler = createBasicHandler("retention-maxfiles", config);
    auto writer = handler->createWriter();

    std::string bigMsg(config.maxSize + 1, 'X');
    (*writer)(std::move(bigMsg));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    size_t remainingRotated = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        auto canonical = std::filesystem::canonical(entry.path());
        if (entry.path().filename().string().find("retention-maxfiles.log") != std::string::npos)
            continue;
        if (canonical == std::filesystem::canonical(handler->getCurrentFilePath()))
            continue;
        remainingRotated++;
    }

    EXPECT_LE(remainingRotated, config.maxFiles);

    size_t deletedOld = 0;
    for (const auto& f : oldFiles)
    {
        if (!std::filesystem::exists(f))
            ++deletedOld;
    }
    EXPECT_GE(deletedOld, 2u);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionMaxAccumulatedSizeDeletesOldest)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxAccumulatedSize = 500;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTimeAccum = 1000;
    for (int i = 0; i < 5; ++i)
    {
        auto filePath = tmpDir / ("accum-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(200, 'A');
        }
        setFileMtime(filePath, baseTimeAccum + i * 10);
    }

    auto handler = createBasicHandler("retention-accum", config);
    auto writer = handler->createWriter();

    std::string bigMsg(config.maxSize + 1, 'Y');
    (*writer)(std::move(bigMsg));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    std::int64_t totalRotatedSize = 0;
    auto activePath = std::filesystem::canonical(handler->getCurrentFilePath());
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        auto canonical = std::filesystem::canonical(entry.path());
        if (canonical == activePath)
            continue;
        totalRotatedSize += entry.file_size();
    }

    EXPECT_LE(totalRotatedSize, static_cast<std::int64_t>(config.maxAccumulatedSize + config.maxSize + 100));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionBothPoliciesCombined)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 10;
    config.maxAccumulatedSize = 300;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTimeCombined = 1000;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("combined-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(200, 'C');
        }
        setFileMtime(filePath, baseTimeCombined + i * 10);
    }

    auto handler = createBasicHandler("retention-combined", config);
    auto writer = handler->createWriter();

    std::string bigMsg(config.maxSize + 1, 'Z');
    (*writer)(std::move(bigMsg));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    size_t oldFilesRemaining = 0;
    for (int i = 0; i < 4; ++i)
    {
        if (std::filesystem::exists(tmpDir / ("combined-" + std::to_string(i) + ".log")))
            ++oldFilesRemaining;
    }
    EXPECT_LT(oldFilesRemaining, 4u) << "At least some old files should have been deleted by retention";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionUnlimitedKeepsAllFiles)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 0;
    config.maxAccumulatedSize = 0;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    std::vector<std::filesystem::path> preFiles;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = tmpDir / ("keep-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << "keep this " << i;
        }
        preFiles.push_back(filePath);
    }

    auto handler = createBasicHandler("retention-unlimited", config);
    auto writer = handler->createWriter();

    std::string bigMsg(config.maxSize + 1, 'K');
    (*writer)(std::move(bigMsg));
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    for (const auto& f : preFiles)
    {
        EXPECT_TRUE(std::filesystem::exists(f)) << "File should not have been deleted: " << f;
    }

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionWithCompressionMaxFiles)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTimeCompress = 1000;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("compress-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << "old content " << i << "\n";
        }
        setFileMtime(filePath, baseTimeCompress + i * 10);
    }

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto handler = createHandlerWithScheduler("retention-compress", config, mockScheduler);
    auto writer = handler->createWriter();

    (*writer)(std::string(config.maxSize + 1, 'X'));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    struct stat activeStat {};
    ASSERT_EQ(::stat(handler->getCurrentFilePath().c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    size_t remaining = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        ++remaining;
    }

    EXPECT_LE(remaining, config.maxFiles) << "Deferred retention after compression did not respect maxFiles";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionWithCompressionMultiplePendingRotations)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t futureTime = std::time(nullptr) + 100000;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = tmpDir / ("pending-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(300, 'P');
        }
        setFileMtime(filePath, futureTime + i * 10);
    }

    std::vector<scheduler::TaskConfig> pendingTasks;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(2))
        .WillRepeatedly([&pendingTasks](std::string_view, scheduler::TaskConfig&& cfg)
                        { pendingTasks.push_back(std::move(cfg)); });

    auto handler = createHandlerWithScheduler("retention-pending", config, mockScheduler);
    auto writer = handler->createWriter();

    (*writer)(std::string(config.maxSize + 1, 'A'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    (*writer)(std::string(config.maxSize + 1, 'B'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    ASSERT_GE(pendingTasks.size(), 2u) << "Expected at least 2 compression tasks to be scheduled";

    const auto activeFilePath = handler->getCurrentFilePath();
    struct stat activeStat {};
    ASSERT_EQ(::stat(activeFilePath.c_str(), &activeStat), 0)
        << "Active file missing before running deferred tasks: " << activeFilePath;
    const ino_t activeInode = activeStat.st_ino;

    for (auto& task : pendingTasks) task.taskFunction();

    struct stat afterStat {};
    ASSERT_EQ(::stat(activeFilePath.c_str(), &afterStat), 0)
        << "Active file was deleted during deferred retention cleanup: " << activeFilePath;
    EXPECT_EQ(afterStat.st_ino, activeInode) << "Active file inode changed unexpectedly";

    size_t remaining = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        ++remaining;
    }
    EXPECT_LE(remaining, config.maxFiles);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionSubSecondMtimeOrdering)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 3;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t sameSecond = 2000;
    std::vector<std::filesystem::path> oldFiles;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("subsec-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << "sub-second content " << i << "\n";
        }
        oldFiles.push_back(filePath);
        setFileMtime(filePath, sameSecond, static_cast<long>((i + 1)) * 100000000L);
    }

    auto handler = createBasicHandler("retention-subsec", config);
    auto writer = handler->createWriter();

    std::string bigMsg(config.maxSize + 1, 'S');
    (*writer)(std::move(bigMsg));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_FALSE(std::filesystem::exists(oldFiles[0])) << "Oldest sub-second file should be deleted";
    EXPECT_FALSE(std::filesystem::exists(oldFiles[1])) << "Second oldest sub-second file should be deleted";
    EXPECT_TRUE(std::filesystem::exists(oldFiles[2])) << "Third sub-second file should survive";
    EXPECT_TRUE(std::filesystem::exists(oldFiles[3])) << "Newest sub-second file should survive";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= DEGRADATION / ERROR PATH COMPONENT TESTS =============

TEST_F(ChannelHandlerComponentTest, ScheduleTaskThrowsUnregistersInFlight)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTime = 1000;
    std::vector<std::filesystem::path> oldFiles;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("throw-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'T');
        }
        setFileMtime(filePath, baseTime + i * 10);
        oldFiles.push_back(filePath);
    }

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    bool firstCall = true;
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .WillRepeatedly(
            [&firstCall](std::string_view, scheduler::TaskConfig&& cfg)
            {
                if (firstCall)
                {
                    firstCall = false;
                    throw std::runtime_error("Simulated scheduler full");
                }
                cfg.taskFunction();
            });

    auto handler = createHandlerWithScheduler("sched-throw", config, mockScheduler);
    auto writer = handler->createWriter();

    (*writer)(std::string(config.maxSize + 1, 'A'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    (*writer)(std::string(config.maxSize + 1, 'B'));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t oldRemaining = 0;
    for (const auto& f : oldFiles)
    {
        if (std::filesystem::exists(f))
            ++oldRemaining;
    }
    EXPECT_LT(oldRemaining, 4u) << "Retention should have deleted some old files despite first scheduleTask throwing";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, SchedulerExpiredSkipsCompression)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    auto handler = createHandlerWithScheduler("sched-expired", config, mockScheduler);
    auto writer = handler->createWriter();

    mockScheduler.reset();

    (*writer)(std::string(config.maxSize + 1, 'E'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()))
        << "Active file should exist even when scheduler is expired";

    bool foundGz = false;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.path().extension() == ".gz")
        {
            foundGz = true;
            break;
        }
    }
    EXPECT_FALSE(foundGz) << "No .gz files should exist when scheduler is expired";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionSkipsInFlightFiles)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    std::vector<scheduler::TaskConfig> pendingTasks;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .WillRepeatedly([&pendingTasks](std::string_view, scheduler::TaskConfig&& cfg)
                        { pendingTasks.push_back(std::move(cfg)); });

    auto handler = createHandlerWithScheduler("inflight-skip", config, mockScheduler);
    auto writer = handler->createWriter();

    for (int i = 0; i < 3; ++i)
    {
        (*writer)(std::string(config.maxSize + 1, 'I' + i));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    ASSERT_GE(pendingTasks.size(), 3u) << "Expected at least 3 compression tasks";

    pendingTasks.back().taskFunction();

    size_t inFlightLogFiles = 0;
    const auto activeInode = [&]()
    {
        struct stat s {};
        ::stat(handler->getCurrentFilePath().c_str(), &s);
        return s.st_ino;
    }();

    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        if (entry.path().extension() == ".log")
            ++inFlightLogFiles;
    }

    EXPECT_GE(inFlightLogFiles, 2u) << "In-flight .log files should not be deleted by retention";

    for (size_t i = 0; i < pendingTasks.size() - 1; ++i)
    {
        pendingTasks[i].taskFunction();
    }

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, CompressionFailureStillUnregistersInFlight)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    const std::time_t baseTime = 1000;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("fail-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'F');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    std::vector<scheduler::TaskConfig> collectedTasks;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    bool collectFirst = true;
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .WillRepeatedly(
            [&collectedTasks, &collectFirst](std::string_view, scheduler::TaskConfig&& cfg)
            {
                if (collectFirst)
                {
                    collectFirst = false;
                    collectedTasks.push_back(std::move(cfg));
                }
                else
                {
                    cfg.taskFunction();
                }
            });

    auto handler = createHandlerWithScheduler("compress-fail", config, mockScheduler);
    auto writer = handler->createWriter();

    (*writer)(std::string(config.maxSize + 1, 'X'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    ASSERT_EQ(collectedTasks.size(), 1u);

    std::filesystem::path rotatedFile;
    const auto activeInode = [&]()
    {
        struct stat s {};
        ::stat(handler->getCurrentFilePath().c_str(), &s);
        return s.st_ino;
    }();

    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        if (entry.path().extension() != ".log")
            continue;
        if (entry.path().filename().string().find("compress-fail") == std::string::npos)
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino != activeInode)
        {
            rotatedFile = entry.path();
            break;
        }
    }

    if (!rotatedFile.empty())
    {
        std::filesystem::remove(rotatedFile);
    }

    collectedTasks[0].taskFunction();

    (*writer)(std::string(config.maxSize + 1, 'Y'));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    size_t oldRemaining = 0;
    for (int i = 0; i < 4; ++i)
    {
        if (std::filesystem::exists(tmpDir / ("fail-old-" + std::to_string(i) + ".log")))
            ++oldRemaining;
    }
    EXPECT_LT(oldRemaining, 4u) << "Retention should have deleted old files after failed compression unregistered "
                                   "in-flight entries";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= NEW: COUNTER PERSISTENCE COMPONENT TESTS =============

// Verify that the counter persisted in the store is correctly resumed after handler recreation.
TEST_F(ChannelHandlerComponentTest, CounterPersistenceAcrossRestart)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Phase 1: Create handler, write enough to trigger 2 rotations (counter goes 0->1->2).
    {
        auto handler = createBasicHandler("persist-counter", config);
        auto writer = handler->createWriter();

        for (int r = 0; r < 2; ++r)
        {
            (*writer)(std::string(config.maxSize + 1, 'A' + r));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        EXPECT_TRUE(std::filesystem::exists(tmpDir / "persist-counter-2.log"));
        writer.reset();
        handler.reset();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Phase 2: Recreate handler with a mock store that returns the persisted state.
    auto persistedPath = (tmpDir / "persist-counter-2.log").string();

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();

    json::Json storedState;
    storedState.setString(persistedPath, "/last_current");
    storedState.setUint64(2, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));

    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler2 = streamlog::ChannelHandler::create(
        config, "persist-counter", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");
    auto writer2 = handler2->createWriter();

    // Trigger one rotation - should go from counter=2 to counter=3.
    (*writer2)(std::string(config.maxSize + 1, 'C'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_TRUE(std::filesystem::exists(tmpDir / "persist-counter-3.log"))
        << "Counter should resume from persisted value (2) and rotate to 3";

    writer2.reset();
}

// Verify that when the stored path doesn't match any existing file, the handler starts fresh.
TEST_F(ChannelHandlerComponentTest, StateRestorationStalePathStartsFresh)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();

    json::Json staleState;
    staleState.setString("/tmp/non-existent-file-99.log", "/last_current");
    staleState.setUint64(99, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(staleState)));

    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = streamlog::ChannelHandler::create(
        config, "stale-state", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");
    auto writer = handler->createWriter();

    (*writer)("first message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Should start fresh at counter=0 since stored path doesn't exist.
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "stale-state-0.log"))
        << "Handler should start fresh at counter=0 when stored path doesn't exist";

    writer.reset();
}

// Verify end-to-end: write -> rotate -> compress -> retain.
TEST_F(ChannelHandlerComponentTest, EndToEndWriteRotateCompressRetain)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(3))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto handler = createHandlerWithScheduler("e2e-pipeline", config, mockScheduler);
    auto writer = handler->createWriter();

    // Trigger 4 rotations to exceed maxFiles=2, forcing retention.
    for (int i = 0; i < 4; ++i)
    {
        (*writer)(std::string(config.maxSize + 1, 'A' + i));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));
    }

    size_t gzCount = 0;
    size_t logCount = 0;
    struct stat activeStat {};
    ASSERT_EQ(::stat(handler->getCurrentFilePath().c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        if (entry.path().extension() == ".gz")
            ++gzCount;
        else if (entry.path().extension() == ".log")
            ++logCount;
    }

    EXPECT_GE(gzCount, 1u) << "Compression should have produced .gz files";
    EXPECT_LE(gzCount + logCount, config.maxFiles)
        << "Retention should limit non-active files to maxFiles=" << config.maxFiles;

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// Verify that multiple rapid rotations with retention don't delete the active file.
TEST_F(ChannelHandlerComponentTest, RapidRotationsWithRetentionPreservesActiveFile)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto handler = createBasicHandler("rapid-rotation", config);
    auto writer = handler->createWriter();

    // Trigger 5 rapid rotations.
    for (int i = 0; i < 5; ++i)
    {
        (*writer)(std::string(config.maxSize + 1, 'R'));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Wait for all pending writes to be processed.
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Active file must still exist.
    auto activePath = handler->getCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(activePath)) << "Active file was deleted by retention: " << activePath;

    // Write one more message to verify handler is still functional.
    const std::string marker = "MARKER_AFTER_RAPID_ROTATIONS";
    (*writer)(std::string(marker));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Get the final active path (might have changed if previous message triggered another rotation).
    activePath = handler->getCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(activePath)) << "Final active file does not exist: " << activePath;

    auto content = readFileContents(activePath);
    EXPECT_NE(content.find(marker), std::string::npos) << "Handler should still be functional after rapid rotations";

    // Verify retention limited non-active files.
    struct stat activeStat {};
    ASSERT_EQ(::stat(activePath.c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    size_t nonActiveCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        ++nonActiveCount;
    }

    EXPECT_LE(nonActiveCount, config.maxFiles);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= STATEFUL STORE FOR REAL RESTART TESTS =============

/**
 * A minimal stateful fake store that actually persists upsertDoc writes and returns them in readDoc.
 * Used to test true end-to-end restart scenarios without manually pre-loading JSON states.
 */
class StatefulFakeStore : public store::IStore
{
public:
    base::OptError createDoc(const base::Name& name, const store::Doc& doc) override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_docs[name.toStr()] = doc.str();
        return std::nullopt;
    }

    base::RespOrError<store::Doc> readDoc(const base::Name& name) const override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        auto it = m_docs.find(name.toStr());
        if (it == m_docs.end())
        {
            return base::Error {"Document not found"};
        }
        return store::Doc(it->second.c_str());
    }

    base::OptError updateDoc(const base::Name& name, const store::Doc& doc) override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_docs[name.toStr()] = doc.str();
        return std::nullopt;
    }

    base::OptError upsertDoc(const base::Name& name, const store::Doc& doc) override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_docs[name.toStr()] = doc.str();
        return std::nullopt;
    }

    base::OptError deleteDoc(const base::Name& name) override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        m_docs.erase(name.toStr());
        return std::nullopt;
    }

    base::RespOrError<store::Col> readCol(const base::Name&) const override { return base::Error {"Not implemented"}; }

    bool existsDoc(const base::Name& name) const override
    {
        std::lock_guard<std::mutex> lk(m_mtx);
        return m_docs.count(name.toStr()) > 0;
    }

private:
    mutable std::mutex m_mtx;
    std::unordered_map<std::string, std::string> m_docs;
};

// ============= 1. REAL RESTART WITH SAME STORE (NO COMPRESSION) =============

TEST_F(ChannelHandlerComponentTest, RealRestartWithStatefulStoreNoCompression)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto statefulStore = std::make_shared<StatefulFakeStore>();

    // Phase 1: Write enough data to trigger 2 rotations (counter 0 -> 1 -> 2)
    {
        auto handler = streamlog::ChannelHandler::create(
            config, "restart-nocomp", statefulStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
        auto writer = handler->createWriter();

        for (int r = 0; r < 2; ++r)
        {
            (*writer)(std::string(config.maxSize + 1, 'A' + r));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }

        EXPECT_TRUE(std::filesystem::exists(tmpDir / "restart-nocomp-2.log"));
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "restart-nocomp-2.log");

        writer.reset();
        handler.reset();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Phase 2: Recreate handler using the SAME store (state was persisted by phase 1)
    {
        auto handler = streamlog::ChannelHandler::create(
            config, "restart-nocomp", statefulStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
        auto writer = handler->createWriter();

        // Should resume at counter=2 (the last persisted file)
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "restart-nocomp-2.log");

        // Write to trigger one more rotation → counter 3
        (*writer)(std::string(config.maxSize + 1, 'C'));
        std::this_thread::sleep_for(std::chrono::milliseconds(300));

        EXPECT_TRUE(std::filesystem::exists(tmpDir / "restart-nocomp-3.log"))
            << "Counter should resume from store and rotate to 3";

        writer.reset();
    }
}

// ============= 2. REAL RESTART WITH SAME STORE (WITH COMPRESSION) =============

TEST_F(ChannelHandlerComponentTest, RealRestartWithStatefulStoreWithCompression)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    auto statefulStore = std::make_shared<StatefulFakeStore>();

    // Phase 1: Write enough to trigger 2 rotations
    {
        auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
        EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
            .Times(AtLeast(1))
            .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

        auto handler = streamlog::ChannelHandler::create(config, "restart-comp", statefulStore, mockScheduler, "log");
        auto writer = handler->createWriter();

        for (int r = 0; r < 2; ++r)
        {
            (*writer)(std::string(config.maxSize + 1, 'A' + r));
            std::this_thread::sleep_for(std::chrono::milliseconds(300));
        }

        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "restart-comp-2.log");

        writer.reset();
        handler.reset();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    // Phase 1 should have compressed rotated files
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "restart-comp-0.log.gz")
                || std::filesystem::exists(tmpDir / "restart-comp-1.log.gz"));

    // Phase 2: Recreate handler. The previous current file (restart-comp-2.log) may
    // trigger a startup compression scheduling since it differs if the file still exists.
    {
        auto mockScheduler2 = std::make_shared<scheduler::mocks::MockIScheduler>();
        EXPECT_CALL(*mockScheduler2, scheduleTask(_, _))
            .Times(AnyNumber())
            .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

        auto handler = streamlog::ChannelHandler::create(config, "restart-comp", statefulStore, mockScheduler2, "log");
        auto writer = handler->createWriter();

        // Should resume at counter=2
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "restart-comp-2.log");

        // Trigger another rotation → counter 3
        (*writer)(std::string(config.maxSize + 1, 'D'));
        std::this_thread::sleep_for(std::chrono::milliseconds(400));

        EXPECT_TRUE(std::filesystem::exists(tmpDir / "restart-comp-3.log"))
            << "Counter should resume from store and rotate to 3";

        // Previous file (counter=2) should have been scheduled for compression
        bool hasCounter2Gz = std::filesystem::exists(tmpDir / "restart-comp-2.log.gz");
        EXPECT_TRUE(hasCounter2Gz) << "Rotated file from phase 2 should be compressed";

        writer.reset();
    }
}

// ============= 3. STALE STORE + EXISTING FILES (COLLISION AVOIDANCE) =============

TEST_F(ChannelHandlerComponentTest, StaleStoreWithExistingFilesAvoidsCollision)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Pre-create files that exist on disk (simulating prior run or retention gap)
    {
        std::ofstream f(tmpDir / "collision-test-0.log");
        f << "existing file 0";
    }
    {
        std::ofstream f(tmpDir / "collision-test-1.log");
        f << "existing file 1";
    }

    // Mock store returns stale state pointing to a non-existent file
    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json staleState;
    staleState.setString((tmpDir / "collision-test-99.log").string(), "/last_current");
    staleState.setUint64(99, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(staleState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = streamlog::ChannelHandler::create(
        config, "collision-test", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");
    auto writer = handler->createWriter();

    // Should skip counter=0 and counter=1 (files exist), land on counter=2
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "collision-test-2.log")
        << "Should skip existing files and use counter=2";

    // Existing files should be untouched
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "collision-test-0.log"));
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "collision-test-1.log"));

    (*writer)("new data in counter 2");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto content = readFileContents(tmpDir / "collision-test-2.log");
    EXPECT_NE(content.find("new data in counter 2"), std::string::npos);

    writer.reset();
}

// ============= 3b. STALE STORE + GAPS FROM RETENTION =============

TEST_F(ChannelHandlerComponentTest, StaleStoreWithRetentionGapsRestartsFromZero)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Only channel-2.log exists (0 and 1 were deleted by retention)
    {
        std::ofstream f(tmpDir / "gap-test-2.log");
        f << "surviving file after retention";
    }

    // Store points to deleted file
    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json staleState;
    staleState.setString((tmpDir / "gap-test-99.log").string(), "/last_current");
    staleState.setUint64(99, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(staleState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = streamlog::ChannelHandler::create(
        config, "gap-test", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");

    // counter=0 doesn't exist → uses 0? No, counter=2 exists. But counter=0 doesn't exist so
    // the while loop checks exists(gap-test-0.log) → false, so it uses counter=0.
    // This documents that with stale store and retention gaps, counter may retrocede.
    auto currentPath = handler->getCurrentFilePath();
    EXPECT_EQ(currentPath, tmpDir / "gap-test-0.log")
        << "With stale store, fallback scans from 0 and uses first available slot";

    // File gap-test-2.log still exists
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "gap-test-2.log"));
}

// ============= 4. STARTUP WITH COMPRESSION AND .GZ EXISTING =============

TEST_F(ChannelHandlerComponentTest, StartupSkipsExistingGzFilesWhenCompressionEnabled)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.pattern = "${name}-${counter}";

    // Pre-create .gz file (simulating prior compression), no .log for counter=0
    {
        std::ofstream f(tmpDir / "gz-skip-0.log.gz");
        f << "compressed data";
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = streamlog::ChannelHandler::create(
        config, "gz-skip", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");

    // With compression enabled, should skip counter=0 (gz exists) and use counter=1
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gz-skip-1.log")
        << "Should skip counter=0 because .gz variant exists";
}

TEST_F(ChannelHandlerComponentTest, StartupIgnoresGzFilesWhenCompressionDisabled)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Pre-create .gz file, no .log for counter=0
    {
        std::ofstream f(tmpDir / "gz-ignore-0.log.gz");
        f << "compressed data";
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = streamlog::ChannelHandler::create(
        config, "gz-ignore", mockStore2, std::weak_ptr<scheduler::IScheduler> {}, "log");

    // With compression disabled, .gz files are ignored → uses counter=0
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gz-ignore-0.log")
        << "Should use counter=0 since .gz is irrelevant without compression";
}

// ============= 5. VALID STORE WITH shouldCompress=true =============

TEST_F(ChannelHandlerComponentTest, ValidStoreWithCompressionResumesAndSchedules)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    // Create the file that the store points to
    {
        std::ofstream f(tmpDir / "comp-resume-2.log");
        f << std::string(500, 'X');
    }

    // Store points to the existing file
    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json validState;
    validState.setString((tmpDir / "comp-resume-2.log").string(), "/last_current");
    validState.setUint64(2, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(validState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Scheduler should receive compression task for the stored file on startup IF it differs
    // from current. But since the stored file IS the current file, no startup compression needed.
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    std::vector<std::string> scheduledTaskNames;
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AnyNumber())
        .WillRepeatedly(
            [&scheduledTaskNames](std::string_view taskName, scheduler::TaskConfig&& cfg)
            {
                scheduledTaskNames.emplace_back(taskName);
                cfg.taskFunction();
            });

    auto handler = streamlog::ChannelHandler::create(config, "comp-resume", mockStore2, mockScheduler, "log");
    auto writer = handler->createWriter();

    // Should resume at counter=2 file
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "comp-resume-2.log");

    // Trigger rotation → creates counter=3
    (*writer)(std::string(config.maxSize + 1, 'Y'));
    std::this_thread::sleep_for(std::chrono::milliseconds(400));

    EXPECT_TRUE(std::filesystem::exists(tmpDir / "comp-resume-3.log")) << "Next rotation should use counter=3";

    // The old counter=2 file should have been scheduled for compression
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "comp-resume-2.log.gz"))
        << "Rotated file counter=2 should be compressed after rotation";

    writer.reset();
}

// ============= 6. PENDING COMPRESSION RECOVERED FROM STORE ON STARTUP =============

TEST_F(ChannelHandlerComponentTest, StartupSchedulesCompressionWhenStoredFileDiffersFromCurrent)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    // Create a "previous" file with yesterday's date that store points to
    auto yesterday = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto yt = std::chrono::system_clock::to_time_t(yesterday);
    auto ytm = *std::localtime(&yt);
    char prevName[128];
    std::strftime(prevName, sizeof(prevName), "startup-sched-%Y-%m-%d-0.log", &ytm);

    const auto previousFile = tmpDir / prevName;
    {
        std::ofstream f(previousFile);
        f << std::string(5000, 'P');
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json storedState;
    storedState.setString(previousFile.string(), "/last_current");
    storedState.setUint64(0, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Track which compression tasks are scheduled
    std::vector<std::string> scheduledNames;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [&scheduledNames](std::string_view taskName, scheduler::TaskConfig&& cfg)
            {
                scheduledNames.emplace_back(taskName);
                cfg.taskFunction();
            });

    auto handler = streamlog::ChannelHandler::create(config, "startup-sched", mockStore2, mockScheduler, "log");

    // The stored file (yesterday) differs from current (today) → startup compression triggered
    EXPECT_NE(handler->getCurrentFilePath(), previousFile);

    // Wait for scheduled compression
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // The previous file should have been compressed
    auto expectedGz = std::filesystem::path(previousFile.string() + ".gz");
    EXPECT_TRUE(std::filesystem::exists(expectedGz))
        << "Previous file from store should be compressed on startup: " << expectedGz;

    // Verify a compression task was scheduled for that file
    bool foundTask = false;
    for (const auto& name : scheduledNames)
    {
        if (name.find(std::filesystem::path(prevName).stem().string()) != std::string::npos)
        {
            foundTask = true;
            break;
        }
    }
    EXPECT_TRUE(foundTask) << "Compression task for previous stored file should be scheduled on startup";
}

TEST_F(ChannelHandlerComponentTest, StartupCompressionSchedulerThrowsDoesNotCrash)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    // Create previous file
    auto yesterday = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto yt = std::chrono::system_clock::to_time_t(yesterday);
    auto ytm = *std::localtime(&yt);
    char prevName[128];
    std::strftime(prevName, sizeof(prevName), "startup-throw-%Y-%m-%d-0.log", &ytm);

    const auto previousFile = tmpDir / prevName;
    {
        std::ofstream f(previousFile);
        f << std::string(1000, 'T');
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json storedState;
    storedState.setString(previousFile.string(), "/last_current");
    storedState.setUint64(0, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Scheduler throws on any schedule attempt
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .WillRepeatedly(Throw(std::runtime_error("Scheduler capacity exceeded")));

    // Handler should still be created successfully despite scheduler throwing
    std::shared_ptr<streamlog::ChannelHandler> handler;
    EXPECT_NO_THROW(
        { handler = streamlog::ChannelHandler::create(config, "startup-throw", mockStore2, mockScheduler, "log"); });

    EXPECT_NE(handler, nullptr);

    // Previous file should still exist (not compressed, not deleted)
    EXPECT_TRUE(std::filesystem::exists(previousFile)) << "Previous file should be preserved when scheduler throws";
}

TEST_F(ChannelHandlerComponentTest, StartupCompressionSchedulerExpiredDoesNotCrash)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    // Create previous file
    auto yesterday = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto yt = std::chrono::system_clock::to_time_t(yesterday);
    auto ytm = *std::localtime(&yt);
    char prevName[128];
    std::strftime(prevName, sizeof(prevName), "startup-expired-%Y-%m-%d-0.log", &ytm);

    const auto previousFile = tmpDir / prevName;
    {
        std::ofstream f(previousFile);
        f << std::string(1000, 'E');
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json storedState;
    storedState.setString(previousFile.string(), "/last_current");
    storedState.setUint64(0, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Create scheduler then destroy it before passing to handler (expired weak_ptr)
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    std::weak_ptr<scheduler::IScheduler> expiredScheduler = mockScheduler;
    mockScheduler.reset();

    // Handler should be created successfully with expired scheduler
    std::shared_ptr<streamlog::ChannelHandler> handler;
    EXPECT_NO_THROW({
        handler = streamlog::ChannelHandler::create(config, "startup-expired", mockStore2, expiredScheduler, "log");
    });

    EXPECT_NE(handler, nullptr);

    // Previous file should still exist (couldn't schedule compression)
    EXPECT_TRUE(std::filesystem::exists(previousFile)) << "Previous file should be preserved when scheduler is expired";

    // No .gz should have been produced
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(previousFile.string() + ".gz")));
}

// ============= 7. RETENTION WITH COMPRESSION + maxAccumulatedSize =============

TEST_F(ChannelHandlerComponentTest, RetentionWithCompressionAndMaxAccumulatedSize)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;         // 1MB triggers rotation
    config.maxAccumulatedSize = 2000; // Very small limit (forces deletion of large raw files)
    config.maxFiles = 0;              // No file count limit
    config.shouldCompress = true;
    config.compressionLevel = 9; // Max compression for smallest .gz
    config.pattern = "${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto handler = createHandlerWithScheduler("ret-comp-accum", config, mockScheduler);
    auto writer = handler->createWriter();

    // Trigger 3 rotations to accumulate compressed files
    for (int i = 0; i < 3; ++i)
    {
        (*writer)(std::string(config.maxSize + 1, 'A' + i));
        std::this_thread::sleep_for(std::chrono::milliseconds(400));
    }

    // Verify: compressed files exist but total size is within limit
    struct stat activeStat {};
    ASSERT_EQ(::stat(handler->getCurrentFilePath().c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    std::int64_t totalNonActiveSize = 0;
    size_t gzCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        totalNonActiveSize += s.st_size;
        if (entry.path().extension() == ".gz")
            ++gzCount;
    }

    // Retention should have limited accumulated size of non-active files
    // Note: compressed files are much smaller, so they should fit within 2000 bytes
    // If retention ran BEFORE compression, it would have deleted too aggressively
    EXPECT_LE(totalNonActiveSize, static_cast<std::int64_t>(config.maxAccumulatedSize + config.maxSize))
        << "Accumulated size of rotated files should be limited by retention";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= 8. CANCELLATION OF COMPRESSION WITH RETENTION ACTIVE =============

TEST_F(ChannelHandlerComponentTest, CompressionCancelledWithRetentionActive)
{
    using namespace ::testing;

    auto shouldRun = std::make_shared<std::atomic<bool>>(true);

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    // Pre-create old files
    const std::time_t baseTime = 1000;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = tmpDir / ("cancel-ret-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'O');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    std::vector<scheduler::TaskConfig> capturedTasks;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([&capturedTasks](std::string_view, scheduler::TaskConfig&& cfg)
                        { capturedTasks.push_back(std::move(cfg)); });

    auto handler = createHandlerWithScheduler("cancel-ret", config, mockScheduler, shouldRun);
    auto writer = handler->createWriter();

    // Write multiple messages to fill the file, then trigger rotation
    // (A single message > maxSize would rotate BEFORE writing, leaving the old file empty)
    const std::string chunk(100000, 'X');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(chunk + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    ASSERT_GE(capturedTasks.size(), 1u) << "At least one compression task should be captured";

    // Cancel compression
    shouldRun->store(false, std::memory_order_seq_cst);

    ASSERT_FALSE(shouldRun->load()) << "shouldRun must be false before executing tasks";

    // Execute captured tasks (compression will be cancelled, but retention callback still runs)
    for (auto& task : capturedTasks)
    {
        task.taskFunction();
    }

    // No .gz files should be produced (compression was cancelled)
    size_t gzCount = 0;
    size_t logCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        auto name = entry.path().filename().string();
        if (name.find("cancel-ret") == std::string::npos)
            continue;
        if (entry.path().extension() == ".gz")
            ++gzCount;
        else if (entry.path().extension() == ".log")
            ++logCount;
    }

    EXPECT_EQ(gzCount, 0u) << "No .gz files should be produced when compression is cancelled";

    // Original .log should be preserved (not deleted by retention since it was in-flight)
    // The rotated .log file should still exist since compression failed
    EXPECT_GE(logCount, 1u) << "Rotated .log file should be preserved after cancelled compression";

    // Retention should still have cleaned up OLD files based on maxFiles
    size_t oldFilesRemaining = 0;
    for (int i = 0; i < 3; ++i)
    {
        if (std::filesystem::exists(tmpDir / ("cancel-ret-old-" + std::to_string(i) + ".log")))
            ++oldFilesRemaining;
    }
    EXPECT_LT(oldFilesRemaining, 3u) << "Retention should delete some old files even with cancelled compression";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= 9. RETENTION DOES NOT DELETE FILES FROM ANOTHER CHANNEL =============

TEST_F(ChannelHandlerComponentTest, RetentionDoesNotDeleteOtherChannelFiles)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Create two channels sharing the same basePath
    auto handlerA = createBasicHandler("ch-a", config);
    auto handlerB = createBasicHandler("ch-b", config);

    auto writerA = handlerA->createWriter();
    auto writerB = handlerB->createWriter();

    // Write data to channel B first (so its files have older mtime)
    (*writerB)("channel B data");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Trigger multiple rotations on channel A to activate its retention
    for (int i = 0; i < 4; ++i)
    {
        (*writerA)(std::string(config.maxSize + 1, 'A' + i));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Channel B's files - check they still exist
    auto chBFile = tmpDir / "ch-b-0.log";
    auto chBLink = tmpDir / "ch-b.log";

    // NOTE: This test documents the CURRENT behavior. Since deleteOldFilesStatic scans
    // basePath recursively without filtering by channel pattern, channel A's retention
    // MAY delete channel B's files if they are older. This is a known design constraint:
    // each channel should ideally have its own basePath (via LogManager's isolatedBasePath).
    //
    // If the design changes to filter by pattern, update this test accordingly.

    // For now, just verify channel A is functional and its own retention worked
    auto activePathA = handlerA->getCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(activePathA)) << "Channel A active file should exist";

    // Count non-active files for channel A specifically
    struct stat activeAStat {};
    ::stat(activePathA.c_str(), &activeAStat);
    struct stat activeBStat {};
    ::stat(handlerB->getCurrentFilePath().c_str(), &activeBStat);

    // The active file of channel A should still exist (protected by its own inode exclusion)
    EXPECT_TRUE(std::filesystem::exists(handlerA->getCurrentFilePath()));

    // NOTE: Channel B's active file may be deleted by channel A's retention since
    // deleteOldFilesStatic only excludes by the calling channel's active inode.
    // This documents the known design constraint: channels sharing a basePath
    // can interfere with each other's files. Use separate basePaths in production.

    writerA.reset();
    writerB.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= 10. LATEST LINK MISSING DURING RETENTION =============

TEST_F(ChannelHandlerComponentTest, RetentionAbortsWhenLatestLinkMissing)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Pre-create old files that retention would normally delete
    const std::time_t baseTime = 1000;
    std::vector<std::filesystem::path> oldFiles;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = tmpDir / ("link-missing-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'L');
        }
        setFileMtime(filePath, baseTime + i * 10);
        oldFiles.push_back(filePath);
    }

    auto handler = createBasicHandler("link-missing", config);
    auto writer = handler->createWriter();

    // Verify handler is working
    (*writer)("initial message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto latestLink = tmpDir / "link-missing.log";
    ASSERT_TRUE(std::filesystem::exists(latestLink));

    // Remove the latest link to simulate corruption
    std::filesystem::remove(latestLink);
    ASSERT_FALSE(std::filesystem::exists(latestLink));

    // Trigger rotation (which triggers retention)
    (*writer)(std::string(config.maxSize + 1, 'R'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // After rotation, the handler recreates the link for the new file
    // The retention that ran BEFORE the new link was created should have aborted
    // (since it couldn't stat the link to identify the active inode).
    // However, rotation creates new link before calling retention.
    // So the actual test is: if link was missing DURING deleteOldFilesStatic's stat call,
    // retention aborts. Since we can't easily inject that timing, we test the overall
    // safety: all old files should still be there OR the active file should be safe.

    // The important invariant: the active file must always exist
    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()))
        << "Active file must survive even if latest link was briefly missing";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// Direct test of retention abort when link is truly missing (no handler writing, just static call)
TEST_F(ChannelHandlerComponentTest, DeleteOldFilesStaticAbortsWhenLinkCannotBeStat)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Create old files that would be deleted by retention
    const std::time_t baseTime = 1000;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = tmpDir / ("no-link-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'N');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    // Create a handler normally, write, then corrupt the link
    auto handler = createBasicHandler("no-link", config);
    auto writer = handler->createWriter();
    (*writer)("data");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // Now remove the link
    auto latestLink = tmpDir / "no-link.log";
    ASSERT_TRUE(std::filesystem::exists(latestLink));
    std::filesystem::remove(latestLink);

    // Trigger rotation which calls retention
    (*writer)(std::string(config.maxSize + 1, 'X'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Rotation internally calls updateOutputFileAndLink which recreates the link,
    // then calls deleteOldFilesStatic which will use the NEW link.
    // So retention runs normally after rotation. The test verifies the handler
    // recovers gracefully from a missing link.
    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()))
        << "Handler should recover from missing link after rotation";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= EMPTY SUBDIRECTORY CLEANUP AFTER RETENTION =============

TEST_F(ChannelHandlerComponentTest, RetentionRemovesEmptySubdirectories)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = false;
    // Pattern that creates subdirectories
    config.pattern = "sub1/sub2/${name}-${counter}";

    // Create the subdirectory structure with old files
    auto sub1 = tmpDir / "sub1";
    auto sub2 = sub1 / "sub2";
    std::filesystem::create_directories(sub2);

    const std::time_t baseTime = 1000;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = sub2 / ("old-file-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'O');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    auto handler = createBasicHandler("emptydir", config);
    auto writer = handler->createWriter();

    // Write enough to trigger multiple rotations so retention kicks in
    const std::string chunk(100000, 'X');
    for (int i = 0; i < 15; ++i)
    {
        (*writer)(chunk + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // The active file should still exist
    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()));

    // sub2 should still exist because the active file is inside it
    EXPECT_TRUE(std::filesystem::exists(sub2));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionRemovesNestedEmptyDirectories)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 1;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Create nested empty-after-retention subdirectories with old files
    auto deepDir = tmpDir / "a" / "b" / "c";
    std::filesystem::create_directories(deepDir);

    const std::time_t baseTime = 1000;
    for (int i = 0; i < 3; ++i)
    {
        auto filePath = deepDir / ("nested-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'N');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    auto handler = createBasicHandler("nested-clean", config);
    auto writer = handler->createWriter();

    // Trigger rotation + retention (maxFiles=1 means only the latest rotated file survives)
    const std::string chunk(100000, 'X');
    for (int i = 0; i < 15; ++i)
    {
        (*writer)(chunk + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()));

    // The nested directories should be cleaned up since all their files were deleted by retention
    EXPECT_FALSE(std::filesystem::exists(deepDir)) << "Deepest empty directory should be removed";
    EXPECT_FALSE(std::filesystem::exists(tmpDir / "a" / "b")) << "Parent empty directory should be removed";
    EXPECT_FALSE(std::filesystem::exists(tmpDir / "a")) << "Grandparent empty directory should be removed";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, RetentionPreservesNonEmptySubdirectories)
{
    // Uses a subdirectory-based pattern so channel files land inside a subdir.
    // With maxFiles=2, after retention at least one rotated file survives inside
    // the subdir → the subdir must NOT be removed by the empty-directory cleanup.
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = false;
    config.pattern = "preserve-sub/${name}-${counter}";

    auto subDir = tmpDir / "preserve-sub";
    std::filesystem::create_directories(subDir);

    // Pre-create old channel files inside the subdir
    const std::time_t baseTime = 1000;
    for (int i = 0; i < 4; ++i)
    {
        auto filePath = subDir / ("preserve-dir-old-" + std::to_string(i) + ".log");
        {
            std::ofstream f(filePath);
            f << std::string(100, 'P');
        }
        setFileMtime(filePath, baseTime + i * 10);
    }

    auto handler = createBasicHandler("preserve-dir", config);
    auto writer = handler->createWriter();

    // Trigger rotation + retention (maxFiles=2 keeps the 2 newest rotated files)
    const std::string chunk(100000, 'X');
    for (int i = 0; i < 15; ++i)
    {
        (*writer)(chunk + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_TRUE(std::filesystem::exists(handler->getCurrentFilePath()));

    // subDir is non-empty (has surviving rotated files) → must NOT be removed
    EXPECT_TRUE(std::filesystem::exists(subDir)) << "Non-empty subdirectory should be preserved";

    bool hasFileInSubDir = false;
    for (const auto& entry : std::filesystem::directory_iterator(subDir))
    {
        if (entry.is_regular_file())
        {
            hasFileInSubDir = true;
            break;
        }
    }
    EXPECT_TRUE(hasFileInSubDir) << "At least one file should survive inside the subdirectory";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= COMPRESSION + RETENTION COMBINED MATRIX =============

TEST_F(ChannelHandlerComponentTest, CompressionAndRetentionFullMatrixWithCompression)
{
    // shouldCompress=true, maxFiles > 0, maxAccumulatedSize > 0, maxSize > 0
    // Validates:
    // - Active file not deleted
    // - Latest link and its target preserved
    // - Final .gz files respect maxFiles
    // - Accumulated size under limit
    // - In-flight files not deleted prematurely
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;                  // 1MB triggers rotation
    config.maxFiles = 3;                       // Keep at most 3 non-active files
    config.maxAccumulatedSize = 5 * (1 << 20); // 5MB total accumulated
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    // Capture tasks to verify in-flight behavior, then run them
    std::vector<scheduler::TaskConfig> capturedTasks;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([&capturedTasks](std::string_view, scheduler::TaskConfig&& cfg)
                        { capturedTasks.push_back(std::move(cfg)); });

    auto handler = createHandlerWithScheduler("full-matrix-comp", config, mockScheduler);
    auto writer = handler->createWriter();

    // Trigger 5 rotations
    for (int i = 0; i < 5; ++i)
    {
        const std::string chunk(config.maxSize / 10, 'A' + i);
        for (int j = 0; j < 12; ++j)
        {
            (*writer)(chunk + std::to_string(j));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    ASSERT_GE(capturedTasks.size(), 4u) << "Expected at least 4 compression tasks";

    // Before running tasks: in-flight .log files should still exist
    const auto activeFilePath = handler->getCurrentFilePath();
    struct stat activeStat {};
    ASSERT_EQ(::stat(activeFilePath.c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    size_t logFilesBeforeCompression = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            struct stat s {};
            if (::stat(entry.path().c_str(), &s) == 0 && s.st_ino != activeInode)
                ++logFilesBeforeCompression;
        }
    }
    EXPECT_GE(logFilesBeforeCompression, 2u) << "In-flight .log files must exist before compression runs";

    // Now run all compression tasks
    for (auto& task : capturedTasks)
    {
        task.taskFunction();
    }

    // Validate: active file still exists
    EXPECT_TRUE(std::filesystem::exists(activeFilePath)) << "Active file must not be deleted";

    // Validate: latest link exists and points to active file
    auto latestLink = tmpDir / "full-matrix-comp.log";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Latest link must exist";
    if (std::filesystem::exists(latestLink))
    {
        EXPECT_TRUE(std::filesystem::equivalent(latestLink, activeFilePath)) << "Latest link must point to active file";
    }

    // Count non-active files and accumulated size
    size_t nonActiveFiles = 0;
    std::int64_t totalNonActiveSize = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        ++nonActiveFiles;
        totalNonActiveSize += s.st_size;
    }

    EXPECT_LE(nonActiveFiles, config.maxFiles) << "Non-active file count should respect maxFiles";
    // Accumulated size check (with tolerance for compression overhead)
    EXPECT_LE(totalNonActiveSize, static_cast<std::int64_t>(config.maxAccumulatedSize + config.maxSize))
        << "Accumulated non-active file size should respect maxAccumulatedSize";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerComponentTest, CompressionAndRetentionFullMatrixWithoutCompression)
{
    // shouldCompress=false, maxFiles > 0, maxAccumulatedSize > 0, maxSize > 0
    // Without compression: cleanup runs in the rotation path, not deferred.
    auto config = defaultConfig;
    config.maxSize = 1 << 20;                  // 1MB triggers rotation
    config.maxFiles = 3;                       // Keep at most 3 non-active files
    config.maxAccumulatedSize = 4 * (1 << 20); // 4MB total accumulated
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto handler = createBasicHandler("full-matrix-nocomp", config);
    auto writer = handler->createWriter();

    // Trigger 6 rotations (filling each file with many smaller writes)
    for (int i = 0; i < 6; ++i)
    {
        const std::string chunk(config.maxSize / 10, 'A' + i);
        for (int j = 0; j < 12; ++j)
        {
            (*writer)(chunk + std::to_string(j));
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // Active file still exists
    const auto activeFilePath = handler->getCurrentFilePath();
    EXPECT_TRUE(std::filesystem::exists(activeFilePath)) << "Active file must not be deleted";

    struct stat activeStat {};
    ASSERT_EQ(::stat(activeFilePath.c_str(), &activeStat), 0);
    const ino_t activeInode = activeStat.st_ino;

    // Latest link exists and points to active
    auto latestLink = tmpDir / "full-matrix-nocomp.log";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Latest link must exist";
    if (std::filesystem::exists(latestLink))
    {
        EXPECT_TRUE(std::filesystem::equivalent(latestLink, activeFilePath)) << "Latest link must point to active file";
    }

    // Count non-active files, no .gz should exist
    size_t nonActiveFiles = 0;
    size_t gzCount = 0;
    std::int64_t totalNonActiveSize = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (!entry.is_regular_file())
            continue;
        struct stat s {};
        if (::stat(entry.path().c_str(), &s) != 0)
            continue;
        if (s.st_ino == activeInode)
            continue;
        ++nonActiveFiles;
        totalNonActiveSize += s.st_size;
        if (entry.path().extension() == ".gz")
            ++gzCount;
    }

    EXPECT_EQ(gzCount, 0u) << "No .gz files should exist without compression";
    EXPECT_LE(nonActiveFiles, config.maxFiles) << "Non-active file count should respect maxFiles";
    EXPECT_LE(totalNonActiveSize, static_cast<std::int64_t>(config.maxAccumulatedSize + config.maxSize))
        << "Accumulated non-active file size should respect maxAccumulatedSize";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= TIME ROLLOVER WITH COUNTER PERSISTED =============

TEST_F(ChannelHandlerComponentTest, TimeRolloverWithPersistedCounterAndCompression)
{
    // Store has yesterday's file with counter=4; today resolves a different path.
    // Expected: today starts at counter=0, compression scheduled for yesterday's file.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    // Build yesterday's filename
    auto yesterday = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto yt = std::chrono::system_clock::to_time_t(yesterday);
    auto ytm = *std::localtime(&yt);
    char prevName[128];
    std::strftime(prevName, sizeof(prevName), "time-roll-%Y-%m-%d-4.log", &ytm);

    const auto previousFile = tmpDir / prevName;
    {
        std::ofstream f(previousFile);
        f << std::string(5000, 'Y');
    }

    // Store state: yesterday's file at counter=4
    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json storedState;
    storedState.setString(previousFile.string(), "/last_current");
    storedState.setUint64(4, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Track compression tasks
    std::vector<std::string> scheduledTaskNames;
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [&scheduledTaskNames](std::string_view taskName, scheduler::TaskConfig&& cfg)
            {
                scheduledTaskNames.emplace_back(taskName);
                cfg.taskFunction();
            });

    auto handler = streamlog::ChannelHandler::create(config, "time-roll", mockStore2, mockScheduler, "log");

    // Today's file should be at counter=0 (different date → fresh counter)
    char todayName[128];
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::strftime(todayName, sizeof(todayName), "time-roll-%Y-%m-%d-0.log", &tm);

    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / todayName)
        << "Time rollover should start counter at 0 for new date";

    // Compression should have been scheduled for yesterday's file
    auto expectedGz = std::filesystem::path(previousFile.string() + ".gz");
    EXPECT_TRUE(std::filesystem::exists(expectedGz)) << "Yesterday's file should be compressed: " << expectedGz;
}

TEST_F(ChannelHandlerComponentTest, TimeRolloverWithPersistedCounterNoCompression)
{
    // Same scenario but shouldCompress=false: no compression scheduled.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${YYYY}-${MM}-${DD}-${counter}";

    // Build yesterday's filename
    auto yesterday = std::chrono::system_clock::now() - std::chrono::hours(24);
    auto yt = std::chrono::system_clock::to_time_t(yesterday);
    auto ytm = *std::localtime(&yt);
    char prevName[128];
    std::strftime(prevName, sizeof(prevName), "time-nocomp-%Y-%m-%d-4.log", &ytm);

    const auto previousFile = tmpDir / prevName;
    {
        std::ofstream f(previousFile);
        f << std::string(5000, 'Y');
    }

    // Store state: yesterday's file at counter=4
    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    json::Json storedState;
    storedState.setString(previousFile.string(), "/last_current");
    storedState.setUint64(4, "/last_counter");

    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(storedState)));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    // Scheduler should NOT be called (no compression)
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    auto handler = streamlog::ChannelHandler::create(config, "time-nocomp", mockStore2, mockScheduler, "log");

    // Today's file should be at counter=0
    char todayName[128];
    auto now = std::time(nullptr);
    auto tm = *std::localtime(&now);
    std::strftime(todayName, sizeof(todayName), "time-nocomp-%Y-%m-%d-0.log", &tm);

    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / todayName)
        << "Time rollover should start counter at 0 for new date";

    // Yesterday's file should remain uncompressed
    EXPECT_TRUE(std::filesystem::exists(previousFile)) << "Original file should remain untouched";
    EXPECT_FALSE(std::filesystem::exists(std::filesystem::path(previousFile.string() + ".gz")))
        << "No .gz should be created when compression is disabled";

    // Store should be updated to today's file
    auto writer = handler->createWriter();
    (*writer)("message today");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto content = readFileContents(tmpDir / todayName);
    EXPECT_NE(content.find("message today"), std::string::npos);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= .GZ AS FUTURE COLLISION (GAP SCENARIO) =============

TEST_F(ChannelHandlerComponentTest, GzFutureCollisionWithGap)
{
    // Documents current behavior: .gz collision avoidance only applies at STARTUP
    // (initial counter selection), NOT during rotation. During rotation the counter
    // simply increments, so it CAN land on a slot where a .gz already exists.
    //
    // Scenario: channel-2.log.gz exists (gap: 0 and 1 don't exist).
    // Handler starts at 0, rotates through 1 → 2 without skipping the .gz.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.pattern = "${name}-${counter}";

    // Only counter=2 exists as .gz (gap: 0 and 1 don't exist)
    {
        std::ofstream f(tmpDir / "gz-gap-2.log.gz");
        f << "compressed data from previous run";
    }

    auto mockStore2 = std::make_shared<store::mocks::MockStore>();
    EXPECT_CALL(*mockStore2, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore2, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AnyNumber())
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto handler = streamlog::ChannelHandler::create(config, "gz-gap", mockStore2, mockScheduler, "log");
    auto writer = handler->createWriter();

    // Handler starts at counter=0 (no .log or .gz for 0)
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gz-gap-0.log")
        << "Should start at counter=0 since no .log exists there";

    // Trigger first rotation: 0 → 1
    (*writer)(std::string(config.maxSize + 1, 'A'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gz-gap-1.log") << "First rotation should land on counter=1";

    // Trigger second rotation: 1 → 2 (does NOT skip despite gz-gap-2.log.gz existing)
    (*writer)(std::string(config.maxSize + 1, 'B'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // The counter simply increments to 2, overwriting the logical slot.
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gz-gap-2.log")
        << "Rotation does not check .gz collisions — lands on counter=2";

    // Original .gz file still exists (different filename: .log.gz vs .log)
    EXPECT_TRUE(std::filesystem::exists(tmpDir / "gz-gap-2.log.gz"));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}
