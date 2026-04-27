
#include <streamlog/logger.hpp>

#include <base/logging.hpp>

#include "channel.hpp"

namespace streamlog
{

/**
 * @brief Registers a new log channel with the specified name and rotation configuration.
 *
 * @param name The name of the log channel to register.
 * @param cfg The rotation configuration for the log channel.
 * @param ext The file extension for the lastest link file.
 * @throws std::runtime_error if the channel already exists or if the configuration is invalid.
 */
void LogManager::registerLog(const std::string& name, const RotationConfig& cfg, std::string_view ext)
{
    std::unique_lock lock(m_channelsMutex);

    // Validate extension
    if (ext.empty() || !std::all_of(ext.begin(), ext.end(), ::isalnum))
    {
        throw std::runtime_error("Invalid file extension: " + std::string(ext));
    }

    // Check if the channel already exists
    if (m_channels.find(name) != m_channels.end())
    {
        throw std::runtime_error("Log channel '" + name + "' already exists");
    }

    // Create a new ChannelHandler instance and register it
    auto handler = ChannelHandler::create(cfg, name, m_store, m_scheduler, ext, m_compressionShouldRun);
    m_channels[name] = std::move(handler);

    LOG_DEBUG("[Stream logger] Log channel '{}' registered successfully", name);
}

/**
 * @brief Updates the configuration of an existing log channel.
 *
 * @param name The name of the log channel to update.
 * @param cfg The new rotation configuration for the log channel.
 * @throws std::runtime_error if the channel does not exist or if the new configuration is invalid.
 */
void LogManager::updateConfig(const std::string& name, const RotationConfig& cfg, std::string_view ext)
{
    // Check extension
    if (ext.empty() || !std::all_of(ext.begin(), ext.end(), ::isalnum))
    {
        throw std::runtime_error("Invalid file extension: " + std::string(ext));
    }

    std::unique_lock lock(m_channelsMutex);

    // Find the channel
    auto it = m_channels.find(name);
    if (it == m_channels.end())
    {
        throw std::runtime_error("Log channel '" + name + "' does not exist");
    }

    // Validate and normalize the new configuration
    RotationConfig validatedConfig = cfg;
    ChannelHandler::validateAndNormalizeConfig(validatedConfig);
    ChannelHandler::validateChannelName(name);

    // check if the channel is in use by a writer
    if (it->second->getActiveWritersCount() > 0)
    {
        // This warning should be returned to the user
        throw std::runtime_error("Cannot update log channel '" + name
                                 + "' - it has active writers. "
                                   "The update will take effect once all writers are destroyed.");
    }

    // Replace the existing channel handler with a new one
    it->second = ChannelHandler::create(validatedConfig, name, m_store, m_scheduler, ext, m_compressionShouldRun);

    LOG_DEBUG("[Stream logger] Log channel '{}' updated successfully", name);
}

/**
 * @brief Gets the current configuration of a log channel.
 *
 * @param name The name of the log channel.
 * @return The current rotation configuration of the log channel.
 * @throws std::runtime_error if the log channel does not exist.
 */
const RotationConfig& LogManager::getConfig(const std::string& name) const
{
    std::shared_lock lock(m_channelsMutex);

    // Find the channel
    auto it = m_channels.find(name);
    if (it == m_channels.end())
    {
        throw std::runtime_error("Log channel '" + name + "' does not exist");
    }

    return it->second->getConfig();
}

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
