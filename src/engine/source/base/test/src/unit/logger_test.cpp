#include <cstdio>
#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <regex>

#include <base/logging.hpp>

class LoggerTest : public testing::Test
{
public:
    void TearDown() override
    {
        logging::stop();
    }
};

TEST_F(LoggerTest, LogNonExist)
{
    ASSERT_ANY_THROW(logging::setLevel(logging::Level::Info));
}

TEST_F(LoggerTest, LogSuccessStart)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.level = logging::Level::Info}));
}

TEST_F(LoggerTest, LogRepeatedStart)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {}));
    ASSERT_ANY_THROW(logging::start(logging::LoggingConfig {}));
}

TEST_F(LoggerTest, LogGetSomeInstance)
{
    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {}));
    auto logger = logging::getDefaultLogger();
    auto someLogger = logging::getDefaultLogger();
    ASSERT_NE(logger, nullptr);
    ASSERT_EQ(logger, someLogger);
}

class LoggerTestLevels : public ::testing::TestWithParam<logging::Level>
{
public:
    void TearDown() override
    {
        logging::stop();
    }

    void checkLogOutputContent(const std::map<std::string, bool>& expectedMessages, const std::string& output)
    {
        for (const auto& [message, shouldContain] : expectedMessages)
        {
            if (shouldContain)
            {
                EXPECT_NE(output.find(message), std::string::npos) << "Expected message not found: " << message;
            }
            else
            {
                EXPECT_EQ(output.find(message), std::string::npos) << "Unexpected message found: " << message;
            }
        }
    }

    bool shouldContainMessage(logging::Level currentLevel, logging::Level messageLevel)
    {
        return static_cast<int>(messageLevel) >= static_cast<int>(currentLevel);
    }
};

TEST_P(LoggerTestLevels, LogChangeLevelInRuntime)
{
    auto level = GetParam();

    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.level = level}));

    testing::internal::CaptureStdout();
    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::string output = testing::internal::GetCapturedStdout();

    std::map<std::string, bool> expectedMessages = {
        {"TRACE message", shouldContainMessage(level, logging::Level::Trace)},
        {"DEBUG message", shouldContainMessage(level, logging::Level::Debug)},
        {"INFO message", shouldContainMessage(level, logging::Level::Info)},
        {"WARNING message", shouldContainMessage(level, logging::Level::Warn)},
        {"ERROR message", shouldContainMessage(level, logging::Level::Err)},
        {"CRITICAL message", shouldContainMessage(level, logging::Level::Critical)}
    };

    checkLogOutputContent(expectedMessages, output);
}

INSTANTIATE_TEST_CASE_P(Levels,
                        LoggerTestLevels,
                        ::testing::Values(logging::Level::Trace,
                                          logging::Level::Debug,
                                          logging::Level::Info,
                                          logging::Level::Warn,
                                          logging::Level::Err,
                                          logging::Level::Critical));
class LoggerTestExtraInfo : public ::testing::TestWithParam<std::tuple<logging::Level, std::regex>>
{
public:
    void TearDown() override
    {
        logging::stop();
    }
};

TEST_P(LoggerTestExtraInfo, LogPatternMatching)
{
    auto [level, pattern] = GetParam();

    ASSERT_NO_THROW(logging::start(logging::LoggingConfig {.level = level}));

    testing::internal::CaptureStdout();

    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::string output = testing::internal::GetCapturedStdout();
    std::istringstream iss(output);
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
