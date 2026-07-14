#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <set>
#include <string>
#include <sys/stat.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <base/logging.hpp>
#include <fastqueue/iqueue.hpp>
#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

#include <streamlog/logger.hpp>

namespace
{

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

std::string readFileContents(const std::filesystem::path& filePath)
{
    std::ifstream file(filePath);
    if (!file.is_open())
    {
        return "";
    }
    return std::string((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
}

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

/// Count lines across all regular files matching an extension under a directory (deduplicating hard links).
size_t countLinesInDir(const std::filesystem::path& dir, const std::string& ext)
{
    std::set<std::uintmax_t> seenInodes;
    size_t total = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ext)
        {
            struct stat st {};
            if (::stat(entry.path().c_str(), &st) != 0)
                continue;
            if (seenInodes.count(st.st_ino))
                continue;
            seenInodes.insert(st.st_ino);
            total += countLines(entry.path());
        }
    }
    return total;
}

/// Find any regular file matching extension under dir and return its content.
std::string findAndReadFirstFile(const std::filesystem::path& dir, const std::string& ext)
{
    for (const auto& entry : std::filesystem::recursive_directory_iterator(dir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ext)
        {
            return readFileContents(entry.path());
        }
    }
    return "";
}

} // namespace

/**
 * LogManager component tests exercise the public API of LogManager with real I/O.
 *
 * Key behaviour:
 * - ensureAndGetWriter() for a channel calls isolatedBasePath() which
 *   creates <basePath>/<channelName>/ and updates config.basePath to that subdirectory.
 *   For an ALREADY REGISTERED channel it just returns a writer from the existing handler.
 *
 * Because of this, tests that use ensureAndGetWriter() expect files in tmpDir/<name>/.
 */
class LogManagerComponentTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        tmpDir = getTempDir();

        defaultConfig = {
            tmpDir,                              // basePath
            "wazuh-${name}-${YYYY}-${MM}-${DD}", // pattern (extension from ext parameter)
            0,                                   // maxSize (no limit)
            fastqueue::MIN_QUEUE_CAPACITY,       // bufferSize
        };

        mockStore = std::make_shared<store::mocks::MockStore>();
        mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

        using ::testing::_;
        using ::testing::AnyNumber;
        using ::testing::Return;

        EXPECT_CALL(*mockStore, readDoc(_))
            .Times(AnyNumber())
            .WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));

        EXPECT_CALL(*mockStore, upsertDoc(_, _)).Times(AnyNumber()).WillRepeatedly(Return(store::mocks::storeOk()));
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }

    std::unique_ptr<streamlog::LogManager> createLogManager()
    {
        return std::make_unique<streamlog::LogManager>(mockStore, mockScheduler);
    }

    std::filesystem::path tmpDir;
    streamlog::RotationConfig defaultConfig;
    std::shared_ptr<store::mocks::MockStore> mockStore;
    std::shared_ptr<scheduler::mocks::MockIScheduler> mockScheduler;
};

// ============= BASIC REGISTRATION AND FILE CREATION =============

TEST_F(LogManagerComponentTest, RegisterAndWriteCreatesFile)
{
    auto logManager = createLogManager();

    auto writer = logManager->ensureAndGetWriter("events", defaultConfig, "json");
    ASSERT_NE(writer, nullptr);

    (*writer)("first log message");
    (*writer)("second log message");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ensureAndGetWriter uses isolatedBasePath: files in tmpDir/events/
    auto channelDir = tmpDir / "events";
    auto content = findAndReadFirstFile(channelDir, ".json");
    ASSERT_FALSE(content.empty()) << "No log file created";
    EXPECT_NE(content.find("first log message"), std::string::npos);
    EXPECT_NE(content.find("second log message"), std::string::npos);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, HardLinkCreatedForChannel)
{
    auto logManager = createLogManager();

    auto writer = logManager->ensureAndGetWriter("audit", defaultConfig, "json");
    (*writer)("audit event");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // ensureAndGetWriter uses isolatedBasePath: hard link is <basePath>/<name>/<name>.<ext>
    auto channelDir = tmpDir / "audit";
    auto latestLink = channelDir / "audit.json";
    EXPECT_TRUE(std::filesystem::exists(latestLink)) << "Hard link 'audit.json' not found at: " << latestLink;

    auto content = readFileContents(latestLink);
    EXPECT_NE(content.find("audit event"), std::string::npos);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, EnsureAndGetWriterAutoRegisters)
{
    auto logManager = createLogManager();

    EXPECT_FALSE(logManager->hasChannel("auto-channel"));

    // ensureAndGetWriter on unregistered channel uses isolatedBasePath: tmpDir/auto-channel/
    auto writer = logManager->ensureAndGetWriter("auto-channel", defaultConfig, "log");
    ASSERT_NE(writer, nullptr);

    EXPECT_TRUE(logManager->hasChannel("auto-channel"));

    (*writer)("auto-registered message");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto channelDir = tmpDir / "auto-channel";
    EXPECT_TRUE(std::filesystem::exists(channelDir));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= MULTI-CHANNEL I/O =============

TEST_F(LogManagerComponentTest, MultipleChannelsWriteIndependently)
{
    auto logManager = createLogManager();

    // Use ensureAndGetWriter for auto-registration (creates subdirectories per channel)
    const int messagesPerChannel = 10;
    auto writerA = logManager->ensureAndGetWriter("channel-a", defaultConfig, "json");
    auto writerB = logManager->ensureAndGetWriter("channel-b", defaultConfig, "json");
    auto writerC = logManager->ensureAndGetWriter("channel-c", defaultConfig, "json");

    for (int i = 0; i < messagesPerChannel; ++i)
    {
        (*writerA)("channel-a message " + std::to_string(i));
        (*writerB)("channel-b message " + std::to_string(i));
        (*writerC)("channel-c message " + std::to_string(i));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (const auto& name : {"channel-a", "channel-b", "channel-c"})
    {
        auto channelDir = tmpDir / name;
        EXPECT_TRUE(std::filesystem::exists(channelDir)) << "Channel dir missing: " << channelDir;

        auto lines = countLinesInDir(channelDir, ".json");
        EXPECT_EQ(lines, static_cast<size_t>(messagesPerChannel)) << "Channel " << name << " has wrong line count";
    }

    writerA.reset();
    writerB.reset();
    writerC.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, ConcurrentWritersOnSameChannel)
{
    auto logManager = createLogManager();

    // Auto-register via ensureAndGetWriter (creates subdirectory)
    const int numWriters = 5;
    const int messagesPerWriter = 20;
    std::vector<std::future<void>> futures;

    for (int w = 0; w < numWriters; ++w)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&logManager, this, w, messagesPerWriter]()
                                     {
                                         auto writer =
                                             logManager->ensureAndGetWriter("shared-channel", defaultConfig, "json");
                                         for (int m = 0; m < messagesPerWriter; ++m)
                                         {
                                             (*writer)("w" + std::to_string(w) + "_m" + std::to_string(m));
                                             std::this_thread::sleep_for(std::chrono::milliseconds(1));
                                         }
                                     }));
    }

    for (auto& f : futures)
    {
        f.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto channelDir = tmpDir / "shared-channel";
    auto totalLines = countLinesInDir(channelDir, ".json");

    EXPECT_EQ(totalLines, static_cast<size_t>(numWriters * messagesPerWriter));
}

TEST_F(LogManagerComponentTest, ConcurrentMultiChannelWriters)
{
    auto logManager = createLogManager();

    const int numChannels = 5;
    const int messagesPerChannel = 15;
    std::vector<std::future<void>> futures;

    for (int c = 0; c < numChannels; ++c)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&logManager, this, c, messagesPerChannel]()
                                     {
                                         std::string name = "concurrent-ch-" + std::to_string(c);
                                         auto writer = logManager->ensureAndGetWriter(name, defaultConfig, "json");
                                         for (int m = 0; m < messagesPerChannel; ++m)
                                         {
                                             (*writer)("msg-" + std::to_string(m));
                                             std::this_thread::sleep_for(std::chrono::milliseconds(2));
                                         }
                                     }));
    }

    for (auto& f : futures)
    {
        f.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    for (int c = 0; c < numChannels; ++c)
    {
        std::string name = "concurrent-ch-" + std::to_string(c);
        EXPECT_TRUE(logManager->hasChannel(name));
        auto channelDir = tmpDir / name;
        EXPECT_TRUE(std::filesystem::exists(channelDir)) << "Channel dir missing: " << channelDir;
    }
}

TEST_F(LogManagerComponentTest, ConcurrentChannelAccess)
{
    auto logManager = createLogManager();

    const int numThreads = 5;
    const int writersPerThread = 3;
    std::vector<std::thread> threads;
    std::vector<std::vector<std::shared_ptr<streamlog::WriterEvent>>> writers(numThreads);

    for (int i = 0; i < numThreads; ++i)
    {
        threads.emplace_back(
            [&, i]()
            {
                for (int j = 0; j < writersPerThread; ++j)
                {
                    writers[i].push_back(logManager->ensureAndGetWriter("concurrent-channel", defaultConfig, "json"));
                    std::this_thread::sleep_for(std::chrono::milliseconds(1));
                }
            });
    }

    for (auto& thread : threads)
    {
        thread.join();
    }

    EXPECT_EQ(logManager->getActiveWritersCount("concurrent-channel"), numThreads * writersPerThread);

    for (auto& threadWriters : writers)
    {
        threadWriters.clear();
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_EQ(logManager->getActiveWritersCount("concurrent-channel"), 0);
}

// ============= ROTATION THROUGH LOGMANAGER =============

TEST_F(LogManagerComponentTest, SizeBasedRotationThroughManager)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20; // 1MB
    config.pattern = "${name}-${counter}";

    auto logManager = createLogManager();

    // Use ensureAndGetWriter for isolated path
    auto writer = logManager->ensureAndGetWriter("rotating", config, "log");

    const std::string largeMessage(50 * 1024, 'X');
    for (int i = 0; i < 30; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto channelDir = tmpDir / "rotating";
    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(channelDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            fileCount++;
        }
    }

    EXPECT_GT(fileCount, 1u) << "Rotation should have created multiple files";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, CompressionThroughManager)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("compress-ch", config, "log");

    const std::string largeMessage(100000, 'Z');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    auto channelDir = tmpDir / "compress-ch";
    size_t gzCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(channelDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".gz")
        {
            gzCount++;
        }
    }

    EXPECT_GE(gzCount, 1u) << "Compression should have created .gz files";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= LIFECYCLE: DESTROY AND UPDATE =============

TEST_F(LogManagerComponentTest, DestroyChannelRemovesFromManager)
{
    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("to-destroy", defaultConfig, "json");
    (*writer)("message before destroy");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    EXPECT_TRUE(logManager->hasChannel("to-destroy"));
    EXPECT_EQ(logManager->getActiveWritersCount("to-destroy"), 1);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    EXPECT_EQ(logManager->getActiveWritersCount("to-destroy"), 0);
    EXPECT_NO_THROW(logManager->destroyChannel("to-destroy"));
    EXPECT_FALSE(logManager->hasChannel("to-destroy"));

    // Files should still exist on disk after destroy
    auto channelDir = tmpDir / "to-destroy";
    EXPECT_TRUE(std::filesystem::exists(channelDir));
}

// ============= WRITER LIFECYCLE =============

TEST_F(LogManagerComponentTest, WriterStillFunctionalAfterOtherWritersDestroyed)
{
    auto logManager = createLogManager();

    // Use ensureAndGetWriter (isolated path: files in tmpDir/survivor/)
    auto w1 = logManager->ensureAndGetWriter("survivor", defaultConfig, "json");
    auto w2 = logManager->ensureAndGetWriter("survivor", defaultConfig, "json");

    (*w1)("from writer 1 - before");
    (*w2)("from writer 2");

    w2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    (*w1)("from writer 1 - after");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto channelDir = tmpDir / "survivor";
    auto content = findAndReadFirstFile(channelDir, ".json");
    ASSERT_FALSE(content.empty()) << "Log file not found in channel dir";
    EXPECT_NE(content.find("from writer 1 - before"), std::string::npos);
    EXPECT_NE(content.find("from writer 2"), std::string::npos);
    EXPECT_NE(content.find("from writer 1 - after"), std::string::npos);

    w1.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= SHUTDOWN =============

TEST_F(LogManagerComponentTest, RequestShutdownStopsAllChannels)
{
    auto logManager = createLogManager();

    auto w1 = logManager->ensureAndGetWriter("shutdown-1", defaultConfig, "json");
    auto w2 = logManager->ensureAndGetWriter("shutdown-2", defaultConfig, "json");

    (*w1)("msg before shutdown");
    (*w2)("msg before shutdown");

    w1.reset();
    w2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(100));

    EXPECT_NO_THROW(logManager->requestShutdown());
}

TEST_F(LogManagerComponentTest, ShutdownCancelsInFlightCompression)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    std::vector<scheduler::TaskConfig> pendingTasks;
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly([&pendingTasks](std::string_view, scheduler::TaskConfig&& cfg)
                        { pendingTasks.push_back(std::move(cfg)); });

    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("shutdown-compress", config, "log");

    const std::string largeMessage(100000, 'S');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    ASSERT_GE(pendingTasks.size(), 1u);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logManager->requestShutdown();

    // Execute pending tasks after shutdown - compressions should be cancelled
    for (auto& task : pendingTasks)
    {
        task.taskFunction();
    }

    auto channelDir = tmpDir / "shutdown-compress";
    size_t gzCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(channelDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".gz")
        {
            gzCount++;
        }
    }

    EXPECT_EQ(gzCount, 0u) << "No .gz files should be produced after shutdown cancellation";
}

// ============= ISOLATED BASE PATH =============

TEST_F(LogManagerComponentTest, IsolatedBasePathCreatesSubdirectory)
{
    auto logManager = createLogManager();

    // ensureAndGetWriter on unregistered channel triggers isolatedBasePath
    auto writer = logManager->ensureAndGetWriter("isolated-ch", defaultConfig, "json");

    auto channelDir = tmpDir / "isolated-ch";
    EXPECT_TRUE(std::filesystem::is_directory(channelDir))
        << "ensureAndGetWriter should create <basePath>/<channelName>/ subdirectory";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, MultipleChannelsDontInterfere)
{
    auto logManager = createLogManager();

    // ensureAndGetWriter creates isolated paths
    auto writerA = logManager->ensureAndGetWriter("alpha", defaultConfig, "json");
    auto writerB = logManager->ensureAndGetWriter("beta", defaultConfig, "json");

    (*writerA)("ALPHA_MARKER");
    (*writerB)("BETA_MARKER");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto alphaDir = tmpDir / "alpha";
    auto betaDir = tmpDir / "beta";

    auto alphaContent = findAndReadFirstFile(alphaDir, ".json");
    auto betaContent = findAndReadFirstFile(betaDir, ".json");

    EXPECT_NE(alphaContent.find("ALPHA_MARKER"), std::string::npos);
    EXPECT_EQ(alphaContent.find("BETA_MARKER"), std::string::npos) << "Beta content leaked into alpha directory";

    EXPECT_NE(betaContent.find("BETA_MARKER"), std::string::npos);
    EXPECT_EQ(betaContent.find("ALPHA_MARKER"), std::string::npos) << "Alpha content leaked into beta directory";

    writerA.reset();
    writerB.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= RE-REGISTRATION =============

TEST_F(LogManagerComponentTest, ReRegisterAfterDestroyCreatesNewChannel)
{
    auto logManager = createLogManager();

    // Use ensureAndGetWriter for isolated path
    auto writer = logManager->ensureAndGetWriter("reuse", defaultConfig, "json");
    (*writer)("first generation");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    logManager->destroyChannel("reuse");
    EXPECT_FALSE(logManager->hasChannel("reuse"));

    // Re-register via ensureAndGetWriter again
    auto writer2 = logManager->ensureAndGetWriter("reuse", defaultConfig, "json");
    EXPECT_TRUE(logManager->hasChannel("reuse"));

    (*writer2)("second generation");
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto channelDir = tmpDir / "reuse";
    auto content = findAndReadFirstFile(channelDir, ".json");
    ASSERT_FALSE(content.empty());
    // Both messages should exist (appending to same date-based file)
    EXPECT_NE(content.find("first generation"), std::string::npos);
    EXPECT_NE(content.find("second generation"), std::string::npos);

    writer2.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= RETENTION THROUGH LOGMANAGER =============

TEST_F(LogManagerComponentTest, RetentionWorksFromManager)
{
    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.maxFiles = 2;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("retention-ch", config, "log");

    // Trigger multiple rotations
    for (int i = 0; i < 5; ++i)
    {
        (*writer)(std::string(config.maxSize + 1, 'A' + i));
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    auto channelDir = tmpDir / "retention-ch";
    // Count unique files by inode (excluding duplicates from hard links)
    std::set<ino_t> seenInodes;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(channelDir))
    {
        if (entry.is_regular_file() && entry.path().extension() == ".log")
        {
            struct stat st {};
            if (::stat(entry.path().c_str(), &st) == 0)
            {
                seenInodes.insert(st.st_ino);
            }
        }
    }

    // Active file + at most maxFiles rotated = 3 max
    EXPECT_LE(seenInodes.size(), config.maxFiles + 1) << "Retention should limit total unique files";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= HIGH THROUGHPUT =============

TEST_F(LogManagerComponentTest, HighThroughputMultiChannel)
{
    auto logManager = createLogManager();

    const int numChannels = 3;
    const int messagesPerChannel = 200;
    std::vector<std::future<void>> futures;

    for (int c = 0; c < numChannels; ++c)
    {
        futures.push_back(std::async(std::launch::async,
                                     [&logManager, this, c, messagesPerChannel]()
                                     {
                                         std::string name = "throughput-" + std::to_string(c);
                                         auto writer = logManager->ensureAndGetWriter(name, defaultConfig, "json");
                                         for (int m = 0; m < messagesPerChannel; ++m)
                                         {
                                             (*writer)("{\"channel\":" + std::to_string(c)
                                                       + ",\"msg\":" + std::to_string(m) + "}");
                                             if (m % 50 == 49)
                                                 std::this_thread::sleep_for(std::chrono::milliseconds(5));
                                         }
                                     }));
    }

    for (auto& f : futures)
    {
        f.wait();
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(1000));

    for (int c = 0; c < numChannels; ++c)
    {
        std::string name = "throughput-" + std::to_string(c);
        auto channelDir = tmpDir / name;

        auto totalLines = countLinesInDir(channelDir, ".json");
        EXPECT_EQ(totalLines, static_cast<size_t>(messagesPerChannel)) << "Channel " << name << " lost messages";
    }
}

// ============= LOGMANAGER DESTRUCTOR =============

TEST_F(LogManagerComponentTest, DestructorCleansUpGracefully)
{
    {
        auto logManager = createLogManager();

        auto w1 = logManager->ensureAndGetWriter("cleanup-1", defaultConfig, "json");
        auto w2 = logManager->ensureAndGetWriter("cleanup-2", defaultConfig, "json");

        (*w1)("message for cleanup 1");
        (*w2)("message for cleanup 2");

        w1.reset();
        w2.reset();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));

        // logManager goes out of scope here
    }

    // Verify files were still written
    auto ch1Dir = tmpDir / "cleanup-1";
    auto ch2Dir = tmpDir / "cleanup-2";
    EXPECT_TRUE(std::filesystem::exists(ch1Dir));
    EXPECT_TRUE(std::filesystem::exists(ch2Dir));
}

// ============= ENSURE-AND-GET IDEMPOTENCY =============

TEST_F(LogManagerComponentTest, EnsureAndGetWriterIdempotent)
{
    auto logManager = createLogManager();

    // Multiple calls with same name reuse the channel (isolated path created once)
    auto w1 = logManager->ensureAndGetWriter("idempotent", defaultConfig, "json");
    auto w2 = logManager->ensureAndGetWriter("idempotent", defaultConfig, "json");
    auto w3 = logManager->ensureAndGetWriter("idempotent", defaultConfig, "json");

    EXPECT_EQ(logManager->getActiveWritersCount("idempotent"), 3);

    (*w1)("from w1");
    (*w2)("from w2");
    (*w3)("from w3");

    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    auto channelDir = tmpDir / "idempotent";
    auto content = findAndReadFirstFile(channelDir, ".json");
    ASSERT_FALSE(content.empty());
    EXPECT_NE(content.find("from w1"), std::string::npos);
    EXPECT_NE(content.find("from w2"), std::string::npos);
    EXPECT_NE(content.find("from w3"), std::string::npos);
    EXPECT_EQ(countLinesInDir(channelDir, ".json"), 3u);

    w1.reset();
    w2.reset();
    w3.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= WIRING VERIFICATION =============

TEST_F(LogManagerComponentTest, SchedulerIsWiredToChannelHandler)
{
    // Verifies that the scheduler injected into LogManager is actually forwarded
    // to ChannelHandler: a rotation with shouldCompress=true must call scheduleTask.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(AtLeast(1));

    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("sched-wired", config, "log");

    const std::string largeMessage(100000, 'X');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(LogManagerComponentTest, StoreIsWiredToChannelHandler)
{
    // Verifies that the store injected into LogManager reaches ChannelHandler:
    // after a rotation with compression, the handler must persist state via upsertDoc.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    std::atomic<int> upsertCount {0};
    EXPECT_CALL(*mockStore, upsertDoc(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [&upsertCount](const base::Name&, const store::Doc&) -> base::OptError
            {
                ++upsertCount;
                return store::mocks::storeOk();
            });

    // Let the scheduler execute tasks inline so compression (and its store write) happens synchronously
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AnyNumber())
        .WillRepeatedly([](std::string_view, scheduler::TaskConfig&& cfg) { cfg.taskFunction(); });

    auto logManager = createLogManager();
    auto writer = logManager->ensureAndGetWriter("store-wired", config, "log");

    const std::string largeMessage(100000, 'Y');
    for (int i = 0; i < 12; ++i)
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    EXPECT_GT(upsertCount.load(), 0) << "Store upsertDoc should have been called after rotation";

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}
