#include <filesystem>
#include <memory>

#include <gtest/gtest.h>

#include "channel.hpp"

namespace
{

// Get unique random temp folder
std::filesystem::path getTempDir()
{

    // Get pid
    const auto pid = std::to_string(getpid());
    // Get last 5 digits of current time
    // Note: This is not a perfect way to get a unique time, but it should
    // be sufficient for testing purposes.
    // It will not collide with other tests running in parallel.
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

} // namespace

TEST(ChannelTest, LoggerInitialization)
{
    logging::testInit(logging::Level::Debug);
    const auto tmpDir = getTempDir();

    auto channelHandlerPtr = streamlog::ChannelHandler::create(
        streamlog::RotationConfig {
            tmpDir.string(), // basePath
            "${YYYY}/${MMM}/wazuh-${name}-${DD}.json",
            10 * 1024 * 1024, // 10 MiB
            1 << 20           // 1 MiB buffer
        },
        "alerts");
}
