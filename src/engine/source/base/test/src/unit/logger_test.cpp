#include <cstdio>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>

#include <base/logging.hpp>

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
    void TearDown() override { logging::stop(); }
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
