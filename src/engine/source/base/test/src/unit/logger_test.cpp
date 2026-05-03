#include <cstdio>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <thread>
#include <unistd.h>

#include <base/dailyRotatingFileSink.hpp>
#include <base/logging.hpp>
#include <spdlog/spdlog.h>

std::string readFileContents(const std::string& filePath)
{
    std::ifstream fileStream(filePath);
    if (!fileStream.is_open())
    {
        std::cerr << "Error to open the file " << filePath << std::endl;
        return "";
    }

    std::stringstream buffer;
    buffer << fileStream.rdbuf();
    return buffer.str();
}

class LoggerTest : public testing::Test
{
public:
    std::string m_tmpPath;
    void SetUp() override
    {
        char tempFileName[] = "/tmp/temp_log_XXXXXX";
        auto tempFileDescriptor = mkstemp(tempFileName);
        m_tmpPath = tempFileName;
        ASSERT_NE(tempFileDescriptor, -1);
    }

    void TearDown() override
    {
        logging::stop();
        std::filesystem::remove(m_tmpPath); // Remove temporary log file
    }
};

std::string testFunc(std::string lamdaName)
{
    auto lambda = [functionName = logging::getLambdaName(__FUNCTION__, lamdaName)]()
    {
        return functionName;
    };

    return lambda();
}

TEST(LoggerUtilTest, getLambdaName)
{
    std::string expectedFunctionName =
        std::string("testFunc") + std::string(LAMBDA_SEPARATOR) + std::string("lambdaName");
    std::string actualFunctionName = testFunc("lambdaName");
    EXPECT_EQ(expectedFunctionName, actualFunctionName);
}

TEST_F(LoggerTest, LogNonExist)
{
    ASSERT_ANY_THROW(logging::setLevel(logging::Level::Info));
}

TEST_F(LoggerTest, LogSuccessStart)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath, .level = logging::Level::Info}));
}

TEST_F(LoggerTest, LogRepeatedStart)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath}));
    ASSERT_ANY_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath}));
}

TEST_F(LoggerTest, LogGetSomeInstance)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath}));
    auto logger = logging::getDefaultLogger();
    auto someLogger = logging::getDefaultLogger();
    ASSERT_NE(logger, nullptr);
    ASSERT_EQ(logger, someLogger);
}

class LoggerTestLevels : public ::testing::TestWithParam<logging::Level>
{
public:
    std::string m_tmpPath;
    void SetUp() override
    {
        char tempFileName[] = "/tmp/temp_log_XXXXXX";
        auto tempFileDescriptor = mkstemp(tempFileName);
        m_tmpPath = tempFileName;
        ASSERT_NE(tempFileDescriptor, -1);
        // Set the environment variable
        setenv(base::process::ENV_ENGINE_STANDALONE, "true", 1);
    }

    void checkLogFileContent(const std::string& message, bool shouldContain)
    {
        std::string fileContent = readFileContents(m_tmpPath);
        if (shouldContain)
        {
            EXPECT_NE(fileContent.find(message), std::string::npos);
        }
        else
        {
            EXPECT_EQ(fileContent.find(message), std::string::npos);
        }
    }

    bool shouldContainMessage(logging::Level currentLevel, logging::Level messageLevel)
    {
        return static_cast<int>(messageLevel) >= static_cast<int>(currentLevel);
    }

    void TearDown() override
    {
        // Unset the environment variable
        unsetenv(base::process::ENV_ENGINE_STANDALONE);
        logging::stop();
        std::filesystem::remove(m_tmpPath); // Remove temporary log file
    }
};

TEST_P(LoggerTestLevels, LogChangeLevel)
{
    auto level = GetParam();

    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath, .level = level}));

    auto l = [functionName = logging::getLambdaName(__FUNCTION__, "lambdaName")]()
    {
        return functionName;
    };

    LOG_TRACE("TRACE message");
    LOG_TRACE_L(l().c_str(), "L_TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_DEBUG_L(l().c_str(), "L_DEBUG message");
    LOG_INFO("INFO message");
    LOG_INFO_L(l().c_str(), "L_INFO message");
    LOG_WARNING("WARNING message");
    LOG_WARNING_L(l().c_str(), "L_WARNING message");
    LOG_ERROR("ERROR message");
    LOG_ERROR_L(l().c_str(), "L_ERROR message");
    LOG_CRITICAL("CRITICAL message");
    LOG_CRITICAL_L(l().c_str(), "L_CRITICAL message");

    checkLogFileContent("TRACE message", shouldContainMessage(level, logging::Level::Trace));
    checkLogFileContent("L_TRACE message", shouldContainMessage(level, logging::Level::Trace));
    checkLogFileContent("DEBUG message", shouldContainMessage(level, logging::Level::Debug));
    checkLogFileContent("L_DEBUG message", shouldContainMessage(level, logging::Level::Debug));
    checkLogFileContent("INFO message", shouldContainMessage(level, logging::Level::Info));
    checkLogFileContent("L_INFO message", shouldContainMessage(level, logging::Level::Info));
    checkLogFileContent("WARNING message", shouldContainMessage(level, logging::Level::Warn));
    checkLogFileContent("L_WARNING message", shouldContainMessage(level, logging::Level::Warn));
    checkLogFileContent("ERROR message", shouldContainMessage(level, logging::Level::Err));
    checkLogFileContent("L_ERROR message", shouldContainMessage(level, logging::Level::Err));
    checkLogFileContent("CRITICAL message", shouldContainMessage(level, logging::Level::Critical));
    checkLogFileContent("L_CRITICAL message", shouldContainMessage(level, logging::Level::Critical));
}

INSTANTIATE_TEST_CASE_P(Levels,
                        LoggerTestLevels,
                        ::testing::Values(logging::Level::Trace,
                                          logging::Level::Debug,
                                          logging::Level::Info,
                                          logging::Level::Warn,
                                          logging::Level::Err,
                                          logging::Level::Critical));

TEST(LoggerTestLevels, ChengeInRuntime)
{
    // Generate temporary log file name
    char tempFileName[] = "/tmp/temp_log_XXXXXX";
    auto tempFileDescriptor = mkstemp(tempFileName);
    ASSERT_NE(tempFileDescriptor, -1);
    // Set the environment variable
    setenv(base::process::ENV_ENGINE_STANDALONE, "true", 1);
    std::string tmpPath = tempFileName;

    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = tmpPath, .level = logging::Level::Off}));

    auto l = [functionName = logging::getLambdaName(__FUNCTION__, "lambdaName")]()
    {
        return functionName;
    };

    LOG_TRACE("TRACE message");
    LOG_TRACE_L(l().c_str(), "L_TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_DEBUG_L(l().c_str(), "L_DEBUG message");
    LOG_INFO("INFO message");
    LOG_INFO_L(l().c_str(), "L_INFO message");
    LOG_WARNING("WARNING message");
    LOG_WARNING_L(l().c_str(), "L_WARNING message");
    LOG_ERROR("ERROR message");
    LOG_ERROR_L(l().c_str(), "L_ERROR message");
    LOG_CRITICAL("CRITICAL message");
    LOG_CRITICAL_L(l().c_str(), "L_CRITICAL message");

    std::string fileContent = readFileContents(tmpPath);
    EXPECT_EQ(fileContent.size(), 0);

    ASSERT_NO_THROW(logging::setLevel(logging::Level::Info));
    ASSERT_EQ(logging::getLevel(), logging::Level::Info);

    LOG_TRACE("TRACE message");
    LOG_TRACE_L(l().c_str(), "L_TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_DEBUG_L(l().c_str(), "L_DEBUG message");
    LOG_INFO("INFO message");
    LOG_INFO_L(l().c_str(), "L_INFO message");
    LOG_WARNING("WARNING message");
    LOG_WARNING_L(l().c_str(), "L_WARNING message");
    LOG_ERROR("ERROR message");
    LOG_ERROR_L(l().c_str(), "L_ERROR message");
    LOG_CRITICAL("CRITICAL message");
    LOG_CRITICAL_L(l().c_str(), "L_CRITICAL message");

    fileContent = readFileContents(tmpPath);
    EXPECT_NE(fileContent.find("INFO message"), std::string::npos);
    EXPECT_NE(fileContent.find("L_INFO message"), std::string::npos);
    EXPECT_NE(fileContent.find("WARNING message"), std::string::npos);
    EXPECT_NE(fileContent.find("L_WARNING message"), std::string::npos);
    EXPECT_NE(fileContent.find("ERROR message"), std::string::npos);
    EXPECT_NE(fileContent.find("L_ERROR message"), std::string::npos);
    EXPECT_NE(fileContent.find("CRITICAL message"), std::string::npos);
    EXPECT_NE(fileContent.find("L_CRITICAL message"), std::string::npos);

    EXPECT_EQ(fileContent.find("TRACE message"), std::string::npos);
    EXPECT_EQ(fileContent.find("L_TRACE message"), std::string::npos);
    EXPECT_EQ(fileContent.find("DEBUG message"), std::string::npos);
    EXPECT_EQ(fileContent.find("L_DEBUG message"), std::string::npos);

    ASSERT_NO_THROW(logging::stop());

    // Unset the environment variable
    unsetenv(base::process::ENV_ENGINE_STANDALONE);

    std::filesystem::remove(tmpPath); // Remove temporary log file
}

class LoggerTestExtraInfo : public ::testing::TestWithParam<std::tuple<logging::Level, std::regex>>
{
public:
    std::string m_tmpPath;
    void SetUp() override
    {
        char tempFileName[] = "/tmp/temp_log_XXXXXX";
        auto tempFileDescriptor = mkstemp(tempFileName);
        m_tmpPath = tempFileName;
        ASSERT_NE(tempFileDescriptor, -1);
    }

    void TearDown() override
    {
        logging::stop();
        std::filesystem::remove(m_tmpPath); // Remove temporary log file
    }
};

TEST_P(LoggerTestExtraInfo, LogPatternMatching)
{
    auto [level, pattern] = GetParam();

    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = m_tmpPath, .level = level}));

    auto l = [functionName = logging::getLambdaName(__FUNCTION__, "lambdaName")]()
    {
        return functionName;
    };

    LOG_TRACE("TRACE message");
    LOG_TRACE_L(l().c_str(), "L_TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_DEBUG_L(l().c_str(), "L_DEBUG message");
    LOG_INFO("INFO message");
    LOG_INFO_L(l().c_str(), "L_INFO message");
    LOG_WARNING("WARNING message");
    LOG_WARNING_L(l().c_str(), "L_WARNING message");
    LOG_ERROR("ERROR message");
    LOG_ERROR_L(l().c_str(), "L_ERROR message");
    LOG_CRITICAL("CRITICAL message");
    LOG_CRITICAL_L(l().c_str(), "L_CRITICAL message");

    std::istringstream iss(readFileContents(m_tmpPath));
    std::string line;
    while (std::getline(iss, line))
    {
        EXPECT_TRUE(std::regex_match(line, pattern));
    }
}

INSTANTIATE_TEST_CASE_P(
    LevelsWithRegex,
    LoggerTestExtraInfo,
    ::testing::Values(std::make_tuple(logging::Level::Trace,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ .*: (\w+): .*)")),
                      std::make_tuple(logging::Level::Debug,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ .*: (\w+): .*)")),
                      std::make_tuple(logging::Level::Info,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+): .*)")),
                      std::make_tuple(logging::Level::Warn,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+): .*)")),
                      std::make_tuple(logging::Level::Err,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+): .*)")),
                      std::make_tuple(logging::Level::Critical,
                                      std::regex(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+): .*)"))));

class LoggerTestLevelsParam
    : public ::testing::TestWithParam<std::tuple<logging::Level, std::vector<std::string>, std::vector<std::string>>>
{
public:
    void TearDown() override
    {
        // Unset the environment variable
        unsetenv(base::process::ENV_ENGINE_STANDALONE);
        logging::stop();
    }
};

TEST_P(LoggerTestLevelsParam, LogLevelTest)
{
    auto [level, expectedMessages, unexpectedMessages] = GetParam();
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.level = level}));

    if (level >= logging::Level::Warn)
    {
        testing::internal::CaptureStderr();
    }
    else
    {
        testing::internal::CaptureStdout();
    }

    // Set the environment variable
    setenv(base::process::ENV_ENGINE_STANDALONE, "true", 1);

    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::string output;
    if (level >= logging::Level::Warn)
    {
        output = testing::internal::GetCapturedStderr();
    }
    else
    {
        output = testing::internal::GetCapturedStdout();
    }

    for (const auto& message : expectedMessages)
    {
        EXPECT_NE(output.find(message), std::string::npos) << "Expected to find: " << message;
    }

    for (const auto& message : unexpectedMessages)
    {
        EXPECT_EQ(output.find(message), std::string::npos) << "Did not expect to find: " << message;
    }
}

INSTANTIATE_TEST_CASE_P(
    LevelsTest,
    LoggerTestLevelsParam,
    ::testing::Values(
        // Level Trace: Only Trace, Debug and Info are logged to stdout
        std::make_tuple(logging::Level::Trace,
                        std::vector<std::string> {"TRACE message", "DEBUG message", "INFO message"},
                        std::vector<std::string> {"WARNING message", "ERROR message", "CRITICAL message"}),

        // Level Debug: Only Debug and Info are logged to stdout
        std::make_tuple(logging::Level::Debug,
                        std::vector<std::string> {"DEBUG message", "INFO message"},
                        std::vector<std::string> {
                            "TRACE message", "WARNING message", "ERROR message", "CRITICAL message"}),

        // Level Info: Only Info is logged to stdout
        std::make_tuple(logging::Level::Info,
                        std::vector<std::string> {"INFO message"},
                        std::vector<std::string> {
                            "TRACE message", "DEBUG message", "WARNING message", "ERROR message", "CRITICAL message"}),

        // Level Warn: Only Warn, Err and Critical are logged to stderr
        std::make_tuple(logging::Level::Warn,
                        std::vector<std::string> {"WARNING message", "ERROR message", "CRITICAL message"},
                        std::vector<std::string> {"INFO message", "DEBUG message", "TRACE message"}),

        // Level Err: Only Err and Critical are logged to stderr
        std::make_tuple(logging::Level::Err,
                        std::vector<std::string> {"ERROR message", "CRITICAL message"},
                        std::vector<std::string> {"INFO message", "DEBUG message", "TRACE message", "WARNING message"}),

        // Level Critical: Only Critical is logged to stderr
        std::make_tuple(logging::Level::Critical,
                        std::vector<std::string> {"CRITICAL message"},
                        std::vector<std::string> {
                            "INFO message",
                            "DEBUG message",
                            "TRACE message",
                            "WARNING message",
                            "ERROR message",
                        })));

// ============================================================================
// Daily Rotating File Sink Tests
// ============================================================================

class DailyRotatingFileSinkTest : public ::testing::Test
{
protected:
    std::string m_tmpDir;
    std::string m_logFile;

    void SetUp() override
    {
        // Create temporary directory for test logs
        char tmpDirTemplate[] = "/tmp/log_rotation_test_XXXXXX";
        m_tmpDir = mkdtemp(tmpDirTemplate);
        ASSERT_FALSE(m_tmpDir.empty());
        m_logFile = m_tmpDir + "/test.log";
    }

    void TearDown() override
    {
        // Clean up temporary directory
        std::filesystem::remove_all(m_tmpDir);
    }

    std::vector<std::string> getRotatedFiles()
    {
        std::vector<std::string> files;
        for (const auto& entry : std::filesystem::directory_iterator(m_tmpDir))
        {
            auto filename = entry.path().filename().string();
            if (filename != "test.log" && filename.find("test-") == 0)
            {
                files.push_back(filename);
            }
        }
        std::sort(files.begin(), files.end());
        return files;
    }

    std::size_t getTotalRotatedSize()
    {
        std::size_t total = 0;
        for (const auto& entry : std::filesystem::directory_iterator(m_tmpDir))
        {
            auto filename = entry.path().filename().string();
            if (filename != "test.log" && filename.find("test-") == 0)
            {
                total += std::filesystem::file_size(entry.path());
            }
        }
        return total;
    }

    void writeLogsUntilRotation(std::shared_ptr<spdlog::logger> logger, std::size_t targetSize)
    {
        std::string message(1000, 'A'); // 1KB message
        std::size_t written = 0;
        while (written < targetSize)
        {
            logger->info(message);
            written += message.size();
        }
        logger->flush();
    }
};

TEST_F(DailyRotatingFileSinkTest, RotatesBySize)
{
    // Create sink with 10KB max size, compression disabled for deterministic checks
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 10 * 1024, // 10KB
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);
    spdlog::set_default_logger(logger);

    // Write 15KB of logs (should trigger rotation)
    writeLogsUntilRotation(logger, 15 * 1024);

    // Check that rotation occurred
    auto rotatedFiles = getRotatedFiles();
    EXPECT_GE(rotatedFiles.size(), 1) << "Expected at least one rotated file";

    for (const auto& file : rotatedFiles)
    {
        std::string suffix = ".log";
        bool ends_with_log =
            file.size() >= suffix.size() && file.compare(file.size() - suffix.size(), suffix.size(), suffix) == 0;
        EXPECT_TRUE(ends_with_log) << "Rotated file should end with .log (compression disabled): " << file;
    }
}

TEST_F(DailyRotatingFileSinkTest, RotatesByTime)
{
    // Create sink with time-based rotation using interval mode (2 seconds)
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 1024 * 1024,   // 1MB (large enough to not trigger size rotation)
        .rotationIntervalSeconds = 2, // Rotate every 2 seconds (testing mode)
        .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Write some logs before rotation time
    for (int i = 0; i < 10; ++i)
    {
        logger->info("Test message {}", i);
    }
    logger->flush();

    // Wait for rotation interval plus a small buffer
    std::this_thread::sleep_for(std::chrono::milliseconds(2100));

    // Trigger rotation by writing another message
    logger->info("After rotation time");
    logger->flush();

    // Check that rotation occurred
    auto rotatedFiles = getRotatedFiles();
    EXPECT_GE(rotatedFiles.size(), 1) << "Expected time-based rotation to occur";
}

TEST_F(DailyRotatingFileSinkTest, SingleRotationWhenTimeAndSizeCoincide)
{
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 5 * 1024,     // 5KB
        .rotationIntervalSeconds = 1 // Deterministic test-only time rotation
    });

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Stay below the size threshold so no rotation happens yet.
    logger->info(std::string(4 * 1024, 'A'));
    logger->flush();

    // Wait until the time condition is met.
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));

    // This write should trigger both time and size conditions in a single rotation.
    logger->info(std::string(2 * 1024, 'B'));
    logger->flush();

    // Should have only 1 rotation (not 2)
    auto rotatedFiles = getRotatedFiles();
    EXPECT_EQ(rotatedFiles.size(), 1) << "Expected only ONE rotation when both conditions met";
}

TEST_F(DailyRotatingFileSinkTest, ContinuesIndexingAfterRestart)
{
    // First run: create rotated files
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = m_logFile, .maxFileSize = 5 * 1024, .compressionEnabled = false});
        auto logger = std::make_shared<spdlog::logger>("test", sink);

        writeLogsUntilRotation(logger, 6 * 1024);
        logger->flush();
    }

    auto filesAfterFirstRun = getRotatedFiles();
    ASSERT_GE(filesAfterFirstRun.size(), 1);

    // Second run: should not overwrite existing files
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = m_logFile, .maxFileSize = 5 * 1024, .compressionEnabled = false});
        auto logger = std::make_shared<spdlog::logger>("test", sink);

        writeLogsUntilRotation(logger, 6 * 1024);
        logger->flush();
    }

    auto filesAfterSecondRun = getRotatedFiles();
    EXPECT_GT(filesAfterSecondRun.size(), filesAfterFirstRun.size())
        << "Second run should create new rotated files, not overwrite";

    // Verify all files are unique
    std::set<std::string> uniqueFiles(filesAfterSecondRun.begin(), filesAfterSecondRun.end());
    EXPECT_EQ(uniqueFiles.size(), filesAfterSecondRun.size()) << "All rotated files should be unique";
}

TEST_F(DailyRotatingFileSinkTest, CleanupByMaxFiles)
{
    // Create sink with max 3 files
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 5 * 1024, // 5KB
                                                   .maxFiles = 3,
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create 5 rotations
    for (int i = 0; i < 5; ++i)
    {
        writeLogsUntilRotation(logger, 6 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Ensure different mtimes
    }
    logger->flush();

    // Should only have 3 rotated files (oldest deleted)
    auto rotatedFiles = getRotatedFiles();
    EXPECT_LE(rotatedFiles.size(), 3) << "Should keep max 3 rotated files";
}

TEST_F(DailyRotatingFileSinkTest, CleanupByMaxAccumulatedSize)
{
    // Create sink with 20KB accumulated size limit
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 5 * 1024,         // 5KB per file
                                                   .maxAccumulatedSize = 20 * 1024, // max 20KB total
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create multiple rotations (each ~5KB, uncompressed)
    for (int i = 0; i < 10; ++i)
    {
        writeLogsUntilRotation(logger, 6 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logger->flush();

    auto totalSize = getTotalRotatedSize();
    EXPECT_LE(totalSize, 30 * 1024) << "Total size should be near limit";
}

TEST_F(DailyRotatingFileSinkTest, CleanupDeletesOldestFiles)
{
    // Create sink with max 3 files
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 5 * 1024, // 5KB per file
                                                   .maxFiles = 3,           // max 3 files
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);
    std::vector<std::string> allCreatedFiles;

    // Create rotations, tracking all created files (may create multiple files per iteration)
    for (int i = 0; i < 6; ++i)
    {
        auto beforeFiles = getRotatedFiles();
        writeLogsUntilRotation(logger, 6 * 1024);
        logger->flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Ensure different mtimes

        auto afterFiles = getRotatedFiles();
        // Find ALL newly created files in this iteration
        for (const auto& file : afterFiles)
        {
            if (std::find(beforeFiles.begin(), beforeFiles.end(), file) == beforeFiles.end())
            {
                allCreatedFiles.push_back(file);
            }
        }
    }

    logger->flush();
    auto finalFiles = getRotatedFiles();

    // Should only have 3 files
    EXPECT_EQ(finalFiles.size(), 3) << "Should keep exactly 3 rotated files";

    // Verify we created more than 3 files total
    ASSERT_GT(allCreatedFiles.size(), 3) << "Should have created more than 3 files to test cleanup";

    // Verify that the OLDEST files were deleted
    size_t numToDelete = allCreatedFiles.size() - 3;
    for (size_t i = 0; i < numToDelete; ++i)
    {
        EXPECT_TRUE(std::find(finalFiles.begin(), finalFiles.end(), allCreatedFiles[i]) == finalFiles.end())
            << "Oldest file should be deleted: " << allCreatedFiles[i];
    }

    // Verify that the NEWEST 3 files were kept
    for (size_t i = numToDelete; i < allCreatedFiles.size(); ++i)
    {
        EXPECT_TRUE(std::find(finalFiles.begin(), finalFiles.end(), allCreatedFiles[i]) != finalFiles.end())
            << "Newest file should be kept: " << allCreatedFiles[i];
    }
}

TEST_F(DailyRotatingFileSinkTest, CleanupWithBothPolicies)
{
    // Create sink with both policies
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 5 * 1024,         // 5KB per file
        .maxFiles = 5,                   // max 5 files
        .maxAccumulatedSize = 15 * 1024, // max 15KB total (stricter than max_files)
        .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create 8 rotations
    for (int i = 0; i < 8; ++i)
    {
        writeLogsUntilRotation(logger, 6 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logger->flush();

    auto rotatedFiles = getRotatedFiles();
    auto totalSize = getTotalRotatedSize();

    // Should be limited by whichever policy is stricter
    EXPECT_LE(rotatedFiles.size(), 5) << "File count should respect max_files";
    EXPECT_LE(totalSize, 20 * 1024) << "Total size should respect max_accumulated_size (with margin)";
}

TEST_F(DailyRotatingFileSinkTest, CleanupBySizeDeletesOldestFiles)
{
    // Create sink with 15KB accumulated size limit (each file ~6KB uncompressed)
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 5 * 1024,         // 5KB per file
        .maxAccumulatedSize = 15 * 1024, // max 15KB total (should keep ~2-3 files)
        .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);
    std::vector<std::string> allCreatedFiles;

    // Create rotations, tracking all created files (may create multiple files per iteration)
    for (int i = 0; i < 6; ++i)
    {
        auto beforeFiles = getRotatedFiles();
        writeLogsUntilRotation(logger, 6 * 1024);
        logger->flush();
        std::this_thread::sleep_for(std::chrono::milliseconds(100)); // Ensure different mtimes

        auto afterFiles = getRotatedFiles();
        // Find ALL newly created files in this iteration
        for (const auto& file : afterFiles)
        {
            if (std::find(beforeFiles.begin(), beforeFiles.end(), file) == beforeFiles.end())
            {
                allCreatedFiles.push_back(file);
            }
        }
    }

    logger->flush();
    auto finalFiles = getRotatedFiles();
    auto totalSize = getTotalRotatedSize();

    // Verify size limit is respected
    EXPECT_LE(totalSize, 18 * 1024) << "Total size should respect max_accumulated_size";
    EXPECT_GE(finalFiles.size(), 2) << "Should have at least 2 files";

    // Verify we created more files than we kept
    ASSERT_GT(allCreatedFiles.size(), finalFiles.size()) << "Should have created more files than kept to test cleanup";

    // Verify that the first created files (oldest) were deleted
    size_t numDeleted = allCreatedFiles.size() - finalFiles.size();
    for (size_t i = 0; i < numDeleted; ++i)
    {
        EXPECT_TRUE(std::find(finalFiles.begin(), finalFiles.end(), allCreatedFiles[i]) == finalFiles.end())
            << "Oldest file should be deleted: " << allCreatedFiles[i];
    }

    // Verify that the last created files (newest) were kept
    for (size_t i = numDeleted; i < allCreatedFiles.size(); ++i)
    {
        EXPECT_TRUE(std::find(finalFiles.begin(), finalFiles.end(), allCreatedFiles[i]) != finalFiles.end())
            << "Newest file should be kept: " << allCreatedFiles[i];
    }
}

TEST_F(DailyRotatingFileSinkTest, HandlesNonexistentBaseDirectory)
{
    std::string nonExistentPath = m_tmpDir + "/nonexistent/test.log";

    // Should throw because directory doesn't exist
    EXPECT_ANY_THROW({
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = nonExistentPath, .maxFileSize = 10 * 1024, .compressionEnabled = false});
    });
}

TEST_F(DailyRotatingFileSinkTest, MultipleRotationsSameDay)
{
    // Create sink with small size to trigger multiple rotations, compression disabled
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 3 * 1024, // 3KB
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create 5 rotations within same day
    for (int i = 0; i < 5; ++i)
    {
        writeLogsUntilRotation(logger, 4 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    logger->flush();

    auto rotatedFiles = getRotatedFiles();
    EXPECT_GE(rotatedFiles.size(), 5) << "Should create multiple rotations same day";

    // Verify all have same date but different indices (compression disabled, no .gz)
    std::regex pattern(R"(test-\d{4}-\d{2}-\d{2}-(\d+)\.log)");
    std::set<int> indices;
    for (const auto& file : rotatedFiles)
    {
        std::smatch match;
        EXPECT_TRUE(std::regex_match(file, match, pattern)) << "File doesn't match pattern: " << file;
        if (match.size() > 1)
        {
            indices.insert(std::stoi(match[1].str()));
        }
    }

    // Indices should be sequential and unique
    EXPECT_EQ(indices.size(), rotatedFiles.size()) << "All indices should be unique";
}

TEST_F(DailyRotatingFileSinkTest, IndexOrderingCorrectBeyond9)
{
    // Create sink that will generate many rotations, compression disabled
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 2 * 1024, // 2KB
                                                   .compressionEnabled = false});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create 12 rotations to test double-digit indices
    for (int i = 0; i < 12; ++i)
    {
        writeLogsUntilRotation(logger, 3 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    logger->flush();

    auto rotatedFiles = getRotatedFiles();
    EXPECT_GE(rotatedFiles.size(), 10) << "Should have at least 10 files to test ordering";

    // Verify ordering is correct (2 < 10, not "10" < "2" lexicographically)
    bool foundDoubleDigit = false;
    for (const auto& file : rotatedFiles)
    {
        if (file.find("-10.") != std::string::npos || file.find("-11.") != std::string::npos)
        {
            foundDoubleDigit = true;
            break;
        }
    }
    EXPECT_TRUE(foundDoubleDigit) << "Should have double-digit indices for proper ordering test";
}

// ============================================================================
// Compression Tests
// ============================================================================

TEST_F(DailyRotatingFileSinkTest, CompressionProducesGzFiles)
{
    // Compression enabled by default - verify .gz files are produced after sink destruction
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = m_logFile,
            .maxFileSize = 5 * 1024 // 5KB
        });

        auto logger = std::make_shared<spdlog::logger>("test", sink);

        writeLogsUntilRotation(logger, 12 * 1024);
        logger->flush();
        // Sink destruction joins the compression thread, ensuring all files are compressed.
    }

    auto rotatedFiles = getRotatedFiles();
    ASSERT_GE(rotatedFiles.size(), 1) << "Expected at least one rotated file";

    for (const auto& file : rotatedFiles)
    {
        std::string suffix = ".log.gz";
        bool ends_with_gz =
            file.size() >= suffix.size() && file.compare(file.size() - suffix.size(), suffix.size(), suffix) == 0;
        EXPECT_TRUE(ends_with_gz) << "Rotated file should end with .log.gz: " << file;
    }
}

TEST_F(DailyRotatingFileSinkTest, CompressionNeverCompressesActiveFile)
{
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = m_logFile,
            .maxFileSize = 5 * 1024 // 5KB
        });

        auto logger = std::make_shared<spdlog::logger>("test", sink);
        writeLogsUntilRotation(logger, 12 * 1024);
        logger->flush();

        // While the sink is alive, the active file must exist and NOT have a .gz version
        EXPECT_TRUE(std::filesystem::exists(m_logFile)) << "Active file must exist";
        EXPECT_FALSE(std::filesystem::exists(m_logFile + ".gz")) << "Active file must never be compressed";
    }

    // After destruction, active file still exists uncompressed
    EXPECT_TRUE(std::filesystem::exists(m_logFile)) << "Active file must persist after sink destruction";
    EXPECT_FALSE(std::filesystem::exists(m_logFile + ".gz")) << "Active file must remain uncompressed";
}

TEST_F(DailyRotatingFileSinkTest, CompressionPreservesFileOnFailure)
{
    // Verify that compress_file_() preserves the uncompressed rotated file when
    // gzipCompress() throws (i.e. it must not silently discard log data).
    //
    // Strategy – broken symlink obstacle (race-free):
    //
    //   The sink names the first rotation test-DATE-1.log and enqueues it for
    //   compression, intending to produce test-DATE-1.log.gz.
    //
    //   We pre-create test-DATE-1.log.gz as a BROKEN SYMLINK:
    //
    //     test-DATE-1.log.gz  →  /tmp/__nonexistent_dir__/file.gz
    //
    //   Why this works:
    //
    //   1) spdlog's path_exists() calls stat(), which FOLLOWS symlinks.
    //      stat() on a broken symlink returns ENOENT → path_exists = false.
    //      The sink therefore does NOT skip index 1 during the index search
    //      in rotate_().  It renames test.log → test-DATE-1.log and enqueues
    //      test-DATE-1.log for compression.
    //
    //   2) gzopen("test-DATE-1.log.gz", "wb") also follows the symlink and
    //      tries to open /tmp/__nonexistent_dir__/file.gz for writing.
    //      The parent directory does not exist → gzopen returns NULL →
    //      gzipCompress throws → compress_file_() catches the exception,
    //      skips std::filesystem::remove, and leaves test-DATE-1.log intact.
    //
    //   The obstacle is created before the sink is constructed, so there is
    //   no timing race whatsoever.

    // Derive today's date string (YYYY-MM-DD) — same format used by the sink.
    const auto todayStr = []() -> std::string
    {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm {};
        localtime_r(&t, &tm);
        char buf[16];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm);
        return std::string(buf);
    }();

    const std::string rotatedLog = m_tmpDir + "/test-" + todayStr + "-1.log";
    const std::string gzObstacle = rotatedLog + ".gz";

    // Place a broken symlink at the exact path gzipCompress would write to.
    //   stat()   → follows symlink → ENOENT → path_exists = false  (index NOT skipped)
    //   gzopen() → follows symlink → can't create in non-existent dir → returns NULL → throws
    ASSERT_EQ(symlink("/tmp/__nonexistent_compression_test_dir__/file.gz", gzObstacle.c_str()), 0)
        << "symlink() failed: " << strerror(errno);

    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(
            logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = 2 * 1024});
        auto logger = std::make_shared<spdlog::logger>("test", sink);

        // Trigger exactly one size-based rotation.
        logger->info(std::string(1500, 'A')); // fills file to ~1.5 KB (below 2 KB limit)
        logger->flush();
        logger->info(std::string(700, 'B')); // total > 2 KB → rotation before this write
        logger->flush();

        // Sink destructor drains the compression thread: by the time we leave
        // this scope, compress_file_() has already attempted – and failed – to
        // create the .gz file through the broken symlink.
    }

    // The rotated file must still exist uncompressed because gzopen() failed.
    EXPECT_TRUE(std::filesystem::exists(rotatedLog))
        << "compress_file_() must preserve the uncompressed rotated file when gzopen() fails";
    EXPECT_GT(std::filesystem::file_size(rotatedLog), 0) << "Preserved rotated file must not be empty";

    // The broken symlink must remain: gzopen() could not write through it,
    // so compress_file_() must not have replaced it with a real .gz file.
    EXPECT_TRUE(std::filesystem::is_symlink(gzObstacle))
        << "The .gz obstacle symlink must remain intact after a failed compression";
}

TEST_F(DailyRotatingFileSinkTest, CompressionWritingDuringCompression)
{
    // Verify that the background compression thread does NOT hold the sink mutex
    // (i.e. writing to the logger is not serialised behind gzip I/O).
    //
    // Design:
    //   A "writer" thread continuously logs small messages and tracks both the
    //   total number of completed writes and the worst-case latency of a single
    //   write.  Concurrently, the main thread triggers several back-to-back
    //   rotations, each enqueuing a file for async compression.
    //
    // With ASYNC compression (correct):
    //   - compress_file_() runs in its own thread without holding the sink mutex.
    //   - The writer thread acquires the sink mutex freely between rotations.
    //   - Many hundreds of writes complete in the measurement window.
    //   - No single write stalls longer than a brief rename+open inside rotate_().
    //
    // With SYNCHRONOUS compression (regression – compress inside rotate_()):
    //   - Every rotation holds the sink mutex for the full gzip duration.
    //   - The writer thread is blocked once per rotation, stalling for gzip time.
    //   - Far fewer writes complete; max per-write latency spikes to gzip time.
    //
    // To make rotations detectable we generate pseudo-random (low-compressibility)
    // content so that even fast hardware takes measurable time to compress each
    // rotated file in the synchronous scenario.

    constexpr std::size_t ROT_SIZE = 256 * 1024; // 256 KB per rotated file
    constexpr int NUM_ROTATIONS = 5;
    constexpr auto MEASURE_WINDOW = std::chrono::milliseconds(600);

    // Pseudo-random payload: defeats zlib's LZ77 match-finder, producing output
    // almost as large as the input and forcing full compression work per byte.
    std::string incompressible(ROT_SIZE - 16 * 1024, '\0');
    for (std::size_t i = 0; i < incompressible.size(); ++i)
        incompressible[i] = static_cast<char>((i * 6364136223846793005ULL) >> 56);

    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = ROT_SIZE});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    std::atomic<bool> stop {false};
    std::atomic<int> writesCompleted {0};
    std::atomic<int64_t> maxSingleWriteMs {0};

    // Writer thread: tight-loop of small writes with per-write latency tracking.
    std::thread writer(
        [&]()
        {
            while (!stop.load(std::memory_order_relaxed))
            {
                const auto t0 = std::chrono::steady_clock::now();
                logger->info("concurrent write {}", writesCompleted.load(std::memory_order_relaxed));
                const int64_t dt =
                    std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0)
                        .count();
                writesCompleted.fetch_add(1, std::memory_order_relaxed);
                // CAS loop to track the highest observed latency.
                for (int64_t cur = maxSingleWriteMs.load(std::memory_order_relaxed);
                     dt > cur && !maxSingleWriteMs.compare_exchange_weak(cur, dt, std::memory_order_relaxed);)
                {
                }
            }
        });

    // Main thread: fill each active file with incompressible content, then push
    // it over the threshold to trigger rotation and enqueue a fat file for gzip.
    for (int i = 0; i < NUM_ROTATIONS; ++i)
    {
        // Fill to just below threshold.
        logger->info(incompressible);
        logger->flush();
        // One more write crosses the limit → rotation.
        logger->info(std::string(32 * 1024, 'T'));
    }

    // Let the writer run freely for a bit after all rotations are in flight.
    std::this_thread::sleep_for(MEASURE_WINDOW);
    stop.store(true, std::memory_order_relaxed);
    writer.join();

    const int completed = writesCompleted.load();
    const int64_t maxLatMs = maxSingleWriteMs.load();

    // With async compression >= 100 writes should finish in 600 ms.
    // If the writer were fully serialised behind 5 × gzip(256 KB pseudo-random)
    // it would accumulate hundreds of ms of blocked time and fall well below 100.
    EXPECT_GT(completed, 100) << "Writer thread completed only " << completed << " messages in "
                              << MEASURE_WINDOW.count() << " ms; expected >> 100 with async compression";

    // No single write should stall for more than 5 seconds.
    // Even a synchronous implementation that compresses inside rotate_() only
    // blocks for compress_time(256 KB) ≈ 5–50 ms; a value above 5 s indicates
    // a deadlock or extreme regression.
    EXPECT_LT(maxLatMs, 5000) << "A single write stalled for " << maxLatMs
                              << " ms, which suggests the sink mutex is held during compression I/O";

    // Active file must remain intact and writable throughout.
    logger->info("Final write after {} rotations and {} concurrent writes", NUM_ROTATIONS, completed);
    logger->flush();
    EXPECT_TRUE(std::filesystem::exists(m_logFile));
    EXPECT_GT(std::filesystem::file_size(m_logFile), 0);
}

TEST_F(DailyRotatingFileSinkTest, CleanupHandlesMixedCompressedAndUncompressed)
{
    // Verify that delete_old_files_() applies the retention policy uniformly across
    // both compressed (.log.gz) and uncompressed (.log) rotated files.
    //
    // We pre-populate the log directory with a known mix:
    //   - two files dated 2024-01-01 (one .log, one .log.gz)  ← OLDEST
    //   - two files dated 2024-01-02 (one .log, one .log.gz)  ← NEWER
    //
    // Then we create a sink with maxFiles=2 and compressionEnabled=false
    // (so cleanup runs synchronously inside rotate_()).  After one rotation
    // a fifth file appears (dated today), which pushes the count to 5 and
    // triggers cleanup.  With maxFiles=2 only the two newest files survive.
    // The test verifies that the unified count includes both .log and .log.gz.

    auto createFile = [&](const std::string& name, std::size_t contentSize = 2 * 1024)
    {
        std::ofstream f(m_tmpDir + "/" + name);
        ASSERT_TRUE(f.is_open()) << "Could not create pre-existing file: " << name;
        f << std::string(contentSize, 'X');
    };

    // Oldest pair (sorted first by cleanup because date 2024-01-01 < 2024-01-02)
    createFile("test-2024-01-01-1.log");    // uncompressed
    createFile("test-2024-01-01-2.log.gz"); // compressed

    // Newer pair
    createFile("test-2024-01-02-1.log");    // uncompressed
    createFile("test-2024-01-02-2.log.gz"); // compressed

    // compressionEnabled=false keeps cleanup synchronous inside rotate_(), making
    // observed state deterministic immediately after the triggering write returns.
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile, .maxFileSize = 5 * 1024, .maxFiles = 2, .compressionEnabled = false});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Trigger one rotation.  cleanup sees 5 rotated files (4 pre-created + 1 new)
    // and must delete the 3 oldest to honour maxFiles=2.
    writeLogsUntilRotation(logger, 6 * 1024);
    logger->flush();

    auto rotatedFiles = getRotatedFiles();

    // Only 2 rotated files must survive.
    EXPECT_LE(rotatedFiles.size(), 2) << "Cleanup must respect max_files across the full mixed .log / .log.gz set;\n"
                                         "found "
                                      << rotatedFiles.size() << " files: " << [&]()
    {
        std::string s;
        for (const auto& f : rotatedFiles) s += "  " + f + "\n";
        return s;
    }();

    // The two oldest files (2024-01-01-*) must have been deleted.
    for (const auto& f : rotatedFiles)
    {
        EXPECT_EQ(f.find("2024-01-01"), std::string::npos) << "Oldest file should have been deleted by cleanup: " << f;
    }
}

TEST_F(DailyRotatingFileSinkTest, CleanupHandlesCoexistingOriginalAndCompressed)
{
    // When compress_file_() succeeds but std::filesystem::remove() on the original
    // .log fails, both test-DATE-N.log and test-DATE-N.log.gz coexist on disk.
    // The comment in compress_file_() says "cleanup will handle it."
    // This test verifies that claim end-to-end:
    //
    //   1) delete_old_files_() does not crash when both files are present for the
    //      same rotation index.
    //   2) Both files are counted individually against the retention policy, so
    //      the file-count limit is not silently exceeded by stale originals.
    //   3) After cleanup the directory is in a consistent state (count ≤ maxFiles).
    //   4) The oldest coexisting pair is removed before any newer clean rotations.
    //
    // The coexistence state is injected directly (bypassing the compression thread)
    // which makes the test deterministic and free of timing races.

    auto createFile = [&](const std::string& name, std::size_t sz = 2 * 1024)
    {
        std::ofstream f(m_tmpDir + "/" + name);
        ASSERT_TRUE(f.is_open()) << "Could not create: " << name;
        f << std::string(sz, 'X');
    };

    // Oldest rotation: compression succeeded AND remove failed.
    // Both files exist simultaneously for the same rotation index.
    createFile("test-2024-01-01-1.log");    // original (remove failed after compress)
    createFile("test-2024-01-01-1.log.gz"); // compressed copy (successfully created)

    // A clean compressed rotation at a later date — should survive if possible.
    createFile("test-2024-01-02-1.log.gz");

    // compressionEnabled=false → cleanup runs synchronously inside rotate_(),
    // so the state is fully observable immediately after the triggering write.
    // maxFiles=2: with 3 pre-created + 1 newly rotated = 4 total,
    // cleanup must remove the 2 oldest (the entire coexisting pair).
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile, .maxFileSize = 5 * 1024, .maxFiles = 2, .compressionEnabled = false});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    writeLogsUntilRotation(logger, 6 * 1024);
    logger->flush();

    auto rotatedFiles = getRotatedFiles();

    // maxFiles=2 must be honoured even though one logical rotation occupies two slots.
    EXPECT_LE(rotatedFiles.size(), 2)
        << "Cleanup must respect maxFiles when a coexisting .log/.log.gz pair inflates the count;\n"
        << "found " << rotatedFiles.size() << " files:\n"
        << [&]()
    {
        std::string s;
        for (const auto& f : rotatedFiles) s += "  " + f + "\n";
        return s;
    }();

    // The entire coexisting pair (2024-01-01, both .log and .log.gz) must be gone.
    for (const auto& f : rotatedFiles)
    {
        EXPECT_EQ(f.find("2024-01-01"), std::string::npos)
            << "The coexisting .log/.log.gz pair must be deleted before newer clean rotations: " << f;
    }
}

TEST_F(DailyRotatingFileSinkTest, CompressionCleanupWithGzFiles)
{
    // Create rotated+compressed files, then verify cleanup works on .gz files
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
            .filePath = m_logFile, .maxFileSize = 5 * 1024, .maxFiles = 3, .compressionEnabled = true});

        auto logger = std::make_shared<spdlog::logger>("test", sink);

        for (int i = 0; i < 6; ++i)
        {
            writeLogsUntilRotation(logger, 6 * 1024);
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        logger->flush();
    }
    // Sink destroyed - all compressions complete

    auto rotatedFiles = getRotatedFiles();
    EXPECT_LE(rotatedFiles.size(), 3) << "Cleanup should respect max_files for compressed files";

    for (const auto& file : rotatedFiles)
    {
        std::string suffix = ".log.gz";
        bool ends_with_gz =
            file.size() >= suffix.size() && file.compare(file.size() - suffix.size(), suffix.size(), suffix) == 0;
        EXPECT_TRUE(ends_with_gz) << "Remaining files should be compressed: " << file;
    }
}

// ============================================================================
// requestShutdown() Tests
// ============================================================================

TEST_F(DailyRotatingFileSinkTest, RequestShutdownSkipsPendingCompressions)
{
    // After requestShutdown(), the destructor should exit quickly without
    // compressing remaining queued files.  Rotated files that were not yet
    // compressed must remain as .log (not .log.gz).

    // Use large pseudo-random (incompressible) payloads so compression
    // takes measurable time and the queue is not drained before requestShutdown().
    constexpr std::size_t ROT_SIZE = 128 * 1024; // 128 KB per rotated file
    std::string payload(ROT_SIZE - 1024, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 6364136223846793005ULL) >> 56);

    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = ROT_SIZE});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Trigger several rotations back-to-back to fill the compression queue.
    for (int i = 0; i < 5; ++i)
    {
        logger->info(payload);
        logger->flush();
        logger->info(std::string(2048, 'T')); // push over threshold → rotation
        logger->flush();
    }

    // Request fast shutdown BEFORE destruction.
    sink->requestShutdown();
    logger.reset();
    sink.reset();

    // Count uncompressed rotated files (.log but not .log.gz).
    auto rotatedFiles = getRotatedFiles();
    ASSERT_GE(rotatedFiles.size(), 1) << "Expected at least one rotated file";

    int uncompressedCount = 0;
    for (const auto& file : rotatedFiles)
    {
        if (file.size() >= 4 && file.substr(file.size() - 4) == ".log")
        {
            ++uncompressedCount;
        }
    }

    EXPECT_GT(uncompressedCount, 0)
        << "After requestShutdown(), at least some rotated files should remain uncompressed (.log)";
}

TEST_F(DailyRotatingFileSinkTest, RequestShutdownPreservesAllRotatedData)
{
    // After requestShutdown() + destruction, every rotated file must exist
    // either as .log or .log.gz — no data loss.  Partial .gz files must be
    // cleaned up by gzipCompress before throwing.

    constexpr std::size_t ROT_SIZE = 64 * 1024;
    std::string payload(ROT_SIZE - 512, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 6364136223846793005ULL) >> 56);

    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = ROT_SIZE});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    for (int i = 0; i < 4; ++i)
    {
        logger->info(payload);
        logger->flush();
        logger->info(std::string(1024, 'X'));
        logger->flush();
    }

    sink->requestShutdown();
    logger.reset();
    sink.reset();

    // Every file in the directory must be valid: either the active log,
    // a complete .log.gz, or an uncompressed .log.  No zero-byte .gz files
    // should remain (gzipCompress removes partial .gz on cancellation).
    for (const auto& entry : std::filesystem::directory_iterator(m_tmpDir))
    {
        auto filename = entry.path().filename().string();
        auto size = std::filesystem::file_size(entry.path());

        if (filename.size() >= 3 && filename.substr(filename.size() - 3) == ".gz")
        {
            EXPECT_GT(size, 0) << "Partial .gz file should not remain after requestShutdown(): " << filename;
        }

        // Every file must be non-empty (no data loss).
        EXPECT_GT(size, 0) << "File must not be empty: " << filename;
    }
}

TEST_F(DailyRotatingFileSinkTest, RequestShutdownMakesDestructorFast)
{
    // Verify that requestShutdown() + destructor completes in bounded time,
    // even when there are many large files queued for compression.

    constexpr std::size_t ROT_SIZE = 256 * 1024;
    std::string payload(ROT_SIZE - 1024, '\0');
    for (std::size_t i = 0; i < payload.size(); ++i)
        payload[i] = static_cast<char>((i * 6364136223846793005ULL) >> 56);

    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = ROT_SIZE});
    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Trigger many rotations with heavy incompressible content.
    for (int i = 0; i < 8; ++i)
    {
        logger->info(payload);
        logger->flush();
        logger->info(std::string(2048, 'T'));
        logger->flush();
    }

    sink->requestShutdown();

    // Measure destruction time.
    const auto t0 = std::chrono::steady_clock::now();
    logger.reset();
    sink.reset();
    const auto dt = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0);

    // Without requestShutdown(), compressing 8 × 256 KB of incompressible data
    // would take hundreds of ms.  With requestShutdown(), the destructor should
    // return in well under 2 seconds (the in-progress chunk finishes, then exit).
    EXPECT_LT(dt.count(), 2000)
        << "Destructor took " << dt.count() << " ms after requestShutdown(); expected < 2000 ms";
}
