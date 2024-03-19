#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <regex>

#include "logging/logging.hpp"

constexpr auto TMP_FILE {"/tmp/log.txt"};

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
protected:
    void TearDown() override
    {
        logging::stop();
        std::filesystem::remove(TMP_FILE); // Remove temporary log file
    }
};

TEST_F(LoggerTest, LogNonExist)
{
    auto expected {"The 'default' logger is not initialized."};
    try
    {
        logging::setLevel("info");
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), expected);
    }
}

TEST_F(LoggerTest, LogSuccessStart)
{
    EXPECT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = TMP_FILE, .level = "info"}));
}

TEST_F(LoggerTest, LogLevelNonExist)
{
    auto expected {
        "Log initialization failed: An error occurred while setting the log level: 'non-exist' is not defined"};
    try
    {
        logging::start(logging::LoggingConfig {.filePath = TMP_FILE, .level = "non-exist"});
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), expected);
    }
}

TEST_F(LoggerTest, LogRepeatedStart)
{
    auto expected {"Log initialization failed: logger with name 'default' already exists"};
    logging::start(logging::LoggingConfig {.filePath = TMP_FILE});
    try
    {
        logging::start(logging::LoggingConfig {.filePath = TMP_FILE});
    }
    catch (const std::exception& e)
    {
        EXPECT_STREQ(e.what(), expected);
    }
}

TEST_F(LoggerTest, LogGetSomeInstance)
{
    logging::start(logging::LoggingConfig {.filePath = TMP_FILE});
    auto logger = logging::getDefaultLogger();
    auto someLogger = logging::getDefaultLogger();
    EXPECT_NE(logger, nullptr);
    EXPECT_EQ(logger, someLogger);
}

TEST_F(LoggerTest, LogChangeLevelInRuntime)
{
    EXPECT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = TMP_FILE, .level = "info"}));

    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::this_thread::sleep_for(std::chrono::milliseconds(2));

    // Verificar que no haya mensajes de nivel más bajo que el nivel configurado
    EXPECT_TRUE(readFileContents(TMP_FILE).find("TRACE message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("DEBUG message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("INFO message") != std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("WARNING message") != std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("ERROR message") != std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("CRITICAL message") != std::string::npos);

    logging::setLevel("error");

    LOG_TRACE("other TRACE message");
    LOG_DEBUG("other DEBUG message");
    LOG_INFO("other INFO message");
    LOG_WARNING("other WARNING message");
    LOG_ERROR("other ERROR message");
    LOG_CRITICAL("other CRITICAL message");

    std::this_thread::sleep_for(std::chrono::milliseconds(2));

    EXPECT_TRUE(readFileContents(TMP_FILE).find("other TRACE message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("other DEBUG message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("other INFO message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("other WARNING message") == std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("other ERROR message") != std::string::npos);
    EXPECT_TRUE(readFileContents(TMP_FILE).find("other CRITICAL message") != std::string::npos);
}

TEST_F(LoggerTest, LogWithExtraInformation)
{
    std::regex pattern(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+) \[.*\]: .*)");

    EXPECT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = TMP_FILE, .level = "debug"}));

    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::this_thread::sleep_for(std::chrono::milliseconds(2));

    std::istringstream iss(readFileContents(TMP_FILE));
    std::string line;
    while (std::getline(iss, line))
    {
        EXPECT_TRUE(std::regex_match(line, pattern));
    }
}

TEST_F(LoggerTest, LogWithoutExtraInformation)
{
    std::regex pattern(R"(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+ \d+:\d+ (\w+): .*)");

    EXPECT_NO_THROW(logging::start(logging::LoggingConfig {.filePath = TMP_FILE, .level = "trace"}));

    LOG_TRACE("TRACE message");
    LOG_DEBUG("DEBUG message");
    LOG_INFO("INFO message");
    LOG_WARNING("WARNING message");
    LOG_ERROR("ERROR message");
    LOG_CRITICAL("CRITICAL message");

    std::this_thread::sleep_for(std::chrono::milliseconds(2));

    std::istringstream iss(readFileContents(TMP_FILE));
    std::string line;
    while (std::getline(iss, line))
    {
        EXPECT_TRUE(std::regex_match(line, pattern));
    }
}
