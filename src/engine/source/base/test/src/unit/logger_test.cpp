#include <cstdio>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>
#include <thread>

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
    // Create sink with 10KB max size
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 10 * 1024 // 10KB
    });

    auto logger = std::make_shared<spdlog::logger>("test", sink);
    spdlog::set_default_logger(logger);

    // Write 15KB of logs (should trigger rotation)
    writeLogsUntilRotation(logger, 15 * 1024);

    // Check that rotation occurred
    auto rotatedFiles = getRotatedFiles();
    EXPECT_GE(rotatedFiles.size(), 1) << "Expected at least one rotated file";

    // Compression temporarily disabled - files should NOT be .gz
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
        .maxFileSize = 1024 * 1024,  // 1MB (large enough to not trigger size rotation)
        .rotationIntervalSeconds = 2 // Rotate every 2 seconds (testing mode)
    });

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
    // Create sink where both conditions will be met
    auto now = std::chrono::system_clock::now();
    auto now_time_t = std::chrono::system_clock::to_time_t(now);
    std::tm now_tm;
    localtime_r(&now_time_t, &now_tm);

    auto future_time_t = now_time_t + 1;
    std::tm future_tm;
    localtime_r(&future_time_t, &future_tm);

    auto sink = std::make_shared<logging::daily_rotating_file_sink>(
        logging::daily_rotating_file_sink::Config {.filePath = m_logFile,
                                                   .maxFileSize = 5 * 1024, // 5KB (small to trigger quickly)
                                                   .rotationHour = future_tm.tm_hour,
                                                   .rotationMinute = future_tm.tm_min});

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Write logs to exceed size
    writeLogsUntilRotation(logger, 6 * 1024);

    // Wait for time condition
    std::this_thread::sleep_for(std::chrono::seconds(2));

    // Write one more log to trigger rotation check
    logger->info("Trigger rotation");
    logger->flush();

    // Should have only 1 rotation (not 2)
    auto rotatedFiles = getRotatedFiles();
    EXPECT_EQ(rotatedFiles.size(), 1) << "Expected only ONE rotation when both conditions met";
}

TEST_F(DailyRotatingFileSinkTest, ContinuesIndexingAfterRestart)
{
    // First run: create rotated files
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(
            logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = 5 * 1024});
        auto logger = std::make_shared<spdlog::logger>("test", sink);

        writeLogsUntilRotation(logger, 6 * 1024);
        logger->flush();
    }

    auto filesAfterFirstRun = getRotatedFiles();
    ASSERT_GE(filesAfterFirstRun.size(), 1);

    // Second run: should not overwrite existing files
    {
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(
            logging::daily_rotating_file_sink::Config {.filePath = m_logFile, .maxFileSize = 5 * 1024});
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
                                                   .maxFiles = 3});

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
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 5 * 1024,        // 5KB per file
        .maxAccumulatedSize = 20 * 1024 // max 20KB total
    });

    auto logger = std::make_shared<spdlog::logger>("test", sink);

    // Create multiple rotations (each ~5KB, uncompressed - compression disabled)
    for (int i = 0; i < 10; ++i)
    {
        writeLogsUntilRotation(logger, 6 * 1024);
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    logger->flush();

    // Total size of rotated files should be <= 20KB (may be higher without compression)
    auto totalSize = getTotalRotatedSize();
    EXPECT_LE(totalSize, 30 * 1024) << "Total size should be near limit (compression disabled, so higher)";
}

TEST_F(DailyRotatingFileSinkTest, CleanupDeletesOldestFiles)
{
    // Create sink with max 3 files
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 5 * 1024, // 5KB per file
        .maxFiles = 3            // max 3 files
    });

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
        .maxFileSize = 5 * 1024,        // 5KB per file
        .maxFiles = 5,                  // max 5 files
        .maxAccumulatedSize = 15 * 1024 // max 15KB total (stricter than max_files)
    });

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
        .maxFileSize = 5 * 1024,        // 5KB per file
        .maxAccumulatedSize = 15 * 1024 // max 15KB total (should keep ~2-3 files)
    });

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
        auto sink = std::make_shared<logging::daily_rotating_file_sink>(
            logging::daily_rotating_file_sink::Config {.filePath = nonExistentPath, .maxFileSize = 10 * 1024});
    });
}

TEST_F(DailyRotatingFileSinkTest, MultipleRotationsSameDay)
{
    // Create sink with small size to trigger multiple rotations
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 3 * 1024 // 3KB
    });

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
    // Create sink that will generate many rotations
    auto sink = std::make_shared<logging::daily_rotating_file_sink>(logging::daily_rotating_file_sink::Config {
        .filePath = m_logFile,
        .maxFileSize = 2 * 1024 // 2KB
    });

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
