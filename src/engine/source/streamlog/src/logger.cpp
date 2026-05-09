
#include <streamlog/logger.hpp>

#include <base/logging.hpp>

#include "channel.hpp"

namespace streamlog
{

/**
 * @brief Get the Active Writers Count for a specific channel.
 *
 * @param name The name of the log channel.
 * @return The number of active writers for the specified channel.
 * @throws std::runtime_error if the log channel does not exist.
 */
std::size_t LogManager::getActiveWritersCount(const std::string& name) const
{
    std::shared_lock lock(m_channelsMutex);

    // Find the channel
    auto it = m_channels.find(name);
    if (it == m_channels.end())
    {
        throw std::runtime_error("Log channel '" + name + "' does not exist");
    }

    return it->second->getActiveWritersCount();
}

/**
 * @brief Destroys the specified log channel, releasing its resources.
 *
 * @param name The name of the log channel to destroy.
 * @throws std::runtime_error if the log channel does not exist or if in use.
 */
void LogManager::destroyChannel(const std::string& name)
{
    std::unique_lock lock(m_channelsMutex);

    // Find the channel
    auto it = m_channels.find(name);
    if (it == m_channels.end())
    {
        throw std::runtime_error("Log channel '" + name + "' does not exist");
    }

    // Check if there are active writers
    if (it->second->getActiveWritersCount() > 0)
    {
        throw std::runtime_error("Cannot destroy log channel '" + name + "' - it has active writers");
    }

    // Remove the channel from the map
    m_channels.erase(it);

    LOG_DEBUG("[Stream logger] Log channel '{}' destroyed successfully", name);
}

RotationConfig& LogManager::isolatedBasePath(const std::string& channelName, RotationConfig& config)
{

    ChannelHandler::validateChannelName(channelName);
    ChannelHandler::validateAndNormalizeConfig(config);

    // Create subdirectory in base path (if not existing and if exist check if is a directory)
    auto newBasePath = config.basePath / channelName;
    if (std::filesystem::exists(newBasePath) && !std::filesystem::is_directory(newBasePath))
    {
        throw std::runtime_error("Cannot create log channel '" + channelName
                                 + "' - path exists and is not a directory: " + newBasePath.string());
    }

    std::error_code ec;
    std::filesystem::create_directories(newBasePath, ec);
    if (ec)
    {
        throw std::runtime_error("Failed to create directories for log channel '" + channelName + "': " + ec.message());
    }

    config.basePath = std::move(newBasePath);
    return config;
}

void LogManager::requestShutdown()
{
    m_compressionShouldRun->store(false, std::memory_order_relaxed);
    LOG_INFO("[Stream logger] Shutdown requested.");
    std::unique_lock lock(m_channelsMutex);
    m_channels.clear();
}

std::shared_ptr<WriterEvent>
LogManager::ensureAndGetWriter(const std::string& name, const RotationConfig& cfg, std::string_view ext)
{
    std::shared_ptr<ChannelHandler> handler;

    // Fast path
    {
        std::shared_lock lock(m_channelsMutex);
        auto it = m_channels.find(name);
        if (it != m_channels.end())
        {
            handler = it->second;
        }
    }

    if (!handler)
    {
        std::unique_lock lock(m_channelsMutex);
        auto it = m_channels.find(name);
        if (it == m_channels.end())
        {
            auto config = cfg;
            isolatedBasePath(name, config);
            auto newHandler = ChannelHandler::create(config, name, m_store, m_scheduler, ext, m_compressionShouldRun);
            it = m_channels.emplace(name, std::move(newHandler)).first;
            LOG_DEBUG("[Stream logger] Log channel '{}' created on demand", name);
        }
        handler = it->second;
    }

    return handler->createWriter();
}
} // namespace streamlog
