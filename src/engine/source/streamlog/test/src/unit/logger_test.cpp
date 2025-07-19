#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <streamlog/logger.hpp>

#include <base/logging.hpp>

#include <filesystem>
#include <fstream>
#include <chrono>
#include <thread>

class LoggerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit();
        // Create temporary directory for testing
        testDir = std::filesystem::temp_directory_path() / "streamlog_test";
        std::filesystem::create_directories(testDir);
    }

    void TearDown() override
    {
        // Clean up test directory
        std::error_code ec;
        std::filesystem::remove_all(testDir, ec);
    }

    std::filesystem::path testDir;
};

TEST_F(LoggerTest, LoggerInitialization)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}-${YYYY}-${MM}-${DD}.log";
    config.bufferSize = 1024;
    
    EXPECT_NO_THROW(manager.registerLog("test_channel", config));
}

TEST_F(LoggerTest, InvalidBasePath)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = "/nonexistent/path";
    config.pattern = "test-${name}.log";
    
    EXPECT_THROW(manager.registerLog("test_channel", config), std::runtime_error);
}

TEST_F(LoggerTest, DuplicateChannelRegistration)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    EXPECT_NO_THROW(manager.registerLog("test_channel", config));
    EXPECT_THROW(manager.registerLog("test_channel", config), std::runtime_error);
}

TEST_F(LoggerTest, GetWriter)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    manager.registerLog("test_channel", config);
    
    auto writer = manager.getWriter("test_channel");
    EXPECT_NE(writer, nullptr);
    
    EXPECT_THROW(manager.getWriter("nonexistent_channel"), std::runtime_error);
}

TEST_F(LoggerTest, GetConfig)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    config.bufferSize = 2048;
    
    manager.registerLog("test_channel", config);
    
    auto retrievedConfig = manager.getConfig("test_channel");
    EXPECT_EQ(retrievedConfig.basePath, config.basePath);
    EXPECT_EQ(retrievedConfig.pattern, config.pattern);
    EXPECT_EQ(retrievedConfig.bufferSize, config.bufferSize);
    
    EXPECT_THROW(manager.getConfig("nonexistent_channel"), std::runtime_error);
}

TEST_F(LoggerTest, UpdateConfig)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    config.bufferSize = 1024;
    
    manager.registerLog("test_channel", config);
    
    // Update configuration
    streamlog::RotationConfig newConfig;
    newConfig.basePath = testDir;
    newConfig.pattern = "updated-${name}.log";
    newConfig.bufferSize = 2048;
    
    EXPECT_NO_THROW(manager.updateConfig("test_channel", newConfig));
    
    auto retrievedConfig = manager.getConfig("test_channel");
    EXPECT_EQ(retrievedConfig.pattern, newConfig.pattern);
    EXPECT_EQ(retrievedConfig.bufferSize, newConfig.bufferSize);
    
    EXPECT_THROW(manager.updateConfig("nonexistent_channel", newConfig), std::runtime_error);
}

TEST_F(LoggerTest, HasWriter)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    manager.registerLog("test_channel", config);
    
    EXPECT_FALSE(manager.hasWriter("test_channel")); // No external references yet
    
    auto writer = manager.getWriter("test_channel");
    EXPECT_TRUE(manager.hasWriter("test_channel")); // Now has external reference
    
    EXPECT_FALSE(manager.hasWriter("nonexistent_channel"));
}

TEST_F(LoggerTest, WriteMessage)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    manager.registerLog("test_channel", config);
    
    auto writer = manager.getWriter("test_channel");
    ASSERT_NE(writer, nullptr);
    
    // Write a test message
    std::string testMessage = "This is a test log message";
    (*writer)(std::move(testMessage));
    
    // Give some time for async processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check if latest link exists
    auto latestLink = testDir / "test_channel.json";
    EXPECT_TRUE(std::filesystem::exists(latestLink));
}

TEST_F(LoggerTest, DestroyChannel)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    manager.registerLog("test_channel", config);
    
    // Should be able to destroy channel when no external writers exist
    EXPECT_NO_THROW(manager.destroyChannel("test_channel"));
    
    // Channel should no longer exist
    EXPECT_THROW(manager.getWriter("test_channel"), std::runtime_error);
    
    EXPECT_THROW(manager.destroyChannel("nonexistent_channel"), std::runtime_error);
}

TEST_F(LoggerTest, DestroyChannelInUse)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}.log";
    
    manager.registerLog("test_channel", config);
    
    auto writer = manager.getWriter("test_channel");
    
    // Should not be able to destroy channel when writer exists
    EXPECT_THROW(manager.destroyChannel("test_channel"), std::runtime_error);
}

TEST_F(LoggerTest, PatternReplacement)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "logs/${YYYY}/${MM}/wazuh-${name}-${DD}.log";
    
    manager.registerLog("alerts", config);
    
    auto writer = manager.getWriter("alerts");
    (*writer)("test message");
    
    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    
    // Check if directory structure was created based on current date
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    auto tm = *std::localtime(&time_t);
    
    auto expectedDir = testDir / "logs" / std::to_string(tm.tm_year + 1900) / 
                       (tm.tm_mon + 1 < 10 ? "0" + std::to_string(tm.tm_mon + 1) : std::to_string(tm.tm_mon + 1));
    
    EXPECT_TRUE(std::filesystem::exists(expectedDir));
}

TEST_F(LoggerTest, MaxSizeRotation)
{
    streamlog::LogManager manager;
    
    streamlog::RotationConfig config;
    config.basePath = testDir;
    config.pattern = "test-${name}-${counter}.log";
    config.maxSize = 100; // Very small size to trigger rotation
    
    manager.registerLog("test_channel", config);
    
    auto writer = manager.getWriter("test_channel");
    
    // Write multiple messages to trigger size-based rotation
    for (int i = 0; i < 10; ++i)
    {
        std::string message = "This is test message number " + std::to_string(i) + " with some extra content to make it longer";
        (*writer)(std::move(message));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    
    // Give time for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Check if latest link exists
    auto latestLink = testDir / "test_channel.json";
    EXPECT_TRUE(std::filesystem::exists(latestLink));
}
