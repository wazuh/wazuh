#include <ctistore/contentDownloader.hpp>

#include <filesystem>
#include <fstream>
#include <sstream>

#include <base/logging.hpp>
#include <contentRegister.hpp>

namespace cti::store
{

namespace
{
constexpr auto CTI_STORE_LOG_TAG = "cti-store";
} // namespace

json::Json ContentManagerConfig::toJson() const
{
    auto nj = this->toNlohmann();
    return json::Json(nj.dump().c_str());
}

nlohmann::json ContentManagerConfig::toNlohmann() const
{
    nlohmann::json j;
    j["topicName"] = topicName;
    j["interval"] = interval;
    j["ondemand"] = onDemand;
    nlohmann::json cfg;
    cfg["consumerName"] = consumerName;
    cfg["contentSource"] = contentSource;
    cfg["compressionType"] = compressionType;
    cfg["versionedContent"] = versionedContent;
    cfg["deleteDownloadedContent"] = deleteDownloadedContent;
    cfg["url"] = url;
    cfg["outputFolder"] = outputFolder;
    cfg["contentFileName"] = contentFileName;
    cfg["databasePath"] = databasePath;
    cfg["offset"] = offset;
    j["configData"] = std::move(cfg);
    return j;
}

void ContentManagerConfig::fromJson(const json::Json& config)
{
    // Use JSON Pointer style paths consistently.
    if (config.exists("/topicName"))
    {
        topicName = config.getString("/topicName").value_or(topicName);
    }
    if (config.exists("/interval"))
    {
        interval = config.getInt("/interval").value_or(interval);
    }
    if (config.exists("/ondemand"))
    {
        onDemand = config.getBool("/ondemand").value_or(onDemand);
    }

    if (config.exists("/configData"))
    {
        if (config.exists("/configData/consumerName"))
        {
            consumerName = config.getString("/configData/consumerName").value_or(consumerName);
        }
        if (config.exists("/configData/contentSource"))
        {
            contentSource = config.getString("/configData/contentSource").value_or(contentSource);
        }
        if (config.exists("/configData/compressionType"))
        {
            compressionType = config.getString("/configData/compressionType").value_or(compressionType);
        }
        if (config.exists("/configData/versionedContent"))
        {
            versionedContent = config.getString("/configData/versionedContent").value_or(versionedContent);
        }
        if (config.exists("/configData/deleteDownloadedContent"))
        {
            deleteDownloadedContent =
                config.getBool("/configData/deleteDownloadedContent").value_or(deleteDownloadedContent);
        }
        if (config.exists("/configData/url"))
        {
            url = config.getString("/configData/url").value_or(url);
        }
        if (config.exists("/configData/outputFolder"))
        {
            outputFolder = config.getString("/configData/outputFolder").value_or(outputFolder);
        }
        if (config.exists("/configData/contentFileName"))
        {
            contentFileName = config.getString("/configData/contentFileName").value_or(contentFileName);
        }
        if (config.exists("/configData/databasePath"))
        {
            databasePath = config.getString("/configData/databasePath").value_or(databasePath);
        }
        if (config.exists("/configData/offset"))
        {
            offset = config.getInt("/configData/offset").value_or(offset);
        }
    }
}

void ContentManagerConfig::validate() const
{
    if (topicName.empty())
    {
        throw std::runtime_error("ContentManagerConfig: topicName cannot be empty");
    }
    if (interval <= 0)
    {
        throw std::runtime_error("ContentManagerConfig: interval must be > 0");
    }
    if (consumerName.empty())
    {
        throw std::runtime_error("ContentManagerConfig: consumerName cannot be empty");
    }
    if (contentSource.empty())
    {
        throw std::runtime_error("ContentManagerConfig: contentSource cannot be empty");
    }

    static const std::array<std::string, 3> allowedSources {"cti-offset", "offline", "cti-api"};
    const bool sourceOk = std::any_of(
        allowedSources.begin(), allowedSources.end(), [&](const std::string& v) { return v == contentSource; });
    if (!sourceOk)
    {
        throw std::runtime_error("ContentManagerConfig: unsupported contentSource: " + contentSource);
    }

    if (compressionType.empty())
    {
        throw std::runtime_error("ContentManagerConfig: compressionType cannot be empty");
    }
    if (versionedContent.empty())
    {
        throw std::runtime_error("ContentManagerConfig: versionedContent cannot be empty");
    }
    if (outputFolder.empty())
    {
        throw std::runtime_error("ContentManagerConfig: outputFolder cannot be empty");
    }
    if (databasePath.empty())
    {
        throw std::runtime_error("ContentManagerConfig: databasePath cannot be empty");
    }
    if (offset < 0)
    {
        throw std::runtime_error("ContentManagerConfig: offset must be >= 0");
    }

    // URL validation: only a basic scheme check (http/https) unless contentSource == offline
    if (contentSource != "offline")
    {
        if (url.empty())
        {
            throw std::runtime_error("ContentManagerConfig: url cannot be empty for non-offline sources");
        }
        if (!(url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0))
        {
            throw std::runtime_error("ContentManagerConfig: url must start with http:// or https://");
        }
    }
}

ContentDownloader::ContentDownloader(const ContentManagerConfig& config, FileProcessingCallback fileProcessingCallback)
    : m_config(config)
    , m_fileProcessingCallback(fileProcessingCallback)
{
    if (!m_config.basePath.empty())
    {
        std::filesystem::path base {m_config.basePath};
        const auto makeAbsolute = [&](const std::string& value) -> std::string
        {
            if (value.empty())
            {
                return value;
            }
            std::filesystem::path p {value};
            if (p.is_absolute())
            {
                return p.string();
            }
            return (base / p).string();
        };
        m_config.outputFolder = makeAbsolute(m_config.outputFolder);
        m_config.databasePath = makeAbsolute(m_config.databasePath);
    }

    LOG_DEBUG("CTI Store ContentDownloader initializing with topic: {}", m_config.topicName);

    if (!m_fileProcessingCallback)
    {
        m_fileProcessingCallback = [this](const std::string& message) -> FileProcessingResult
        {
            return defaultFileProcessingCallback(message);
        };
    }

    try
    {
        if (!m_config.outputFolder.empty())
        {
            std::filesystem::create_directories(m_config.outputFolder);
        }
        if (!m_config.databasePath.empty())
        {
            std::filesystem::create_directories(m_config.databasePath);
        }
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to create CTI store directories: {}", e.what());
        throw;
    }
}

ContentDownloader::~ContentDownloader()
{
    if (m_isRunning)
    {
        stop();
    }
}

bool ContentDownloader::start()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (m_isRunning)
    {
        LOG_WARNING("ContentDownloader is already running");
        return false;
    }

    try
    {
        LOG_INFO("Starting CTI Store ContentDownloader");

        // Validate config before proceeding to register creation.
        m_config.validate();

        // Usar método centralizado para construir la configuración JSON
        auto nlohmannConfig = m_config.toNlohmann();

        // Initialize ContentRegister with the file processing callback
        m_contentRegister =
            std::make_unique<ContentRegister>(m_config.topicName, nlohmannConfig, m_fileProcessingCallback);

        m_isRunning = true;
        m_shouldStop = false;

        LOG_INFO("CTI Store ContentDownloader started successfully");
        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Failed to start ContentDownloader: {}", e.what());
        return false;
    }
}

void ContentDownloader::stop()
{
    std::lock_guard<std::mutex> lock(m_mutex);

    if (!m_isRunning)
    {
        LOG_DEBUG("ContentDownloader is not running");
        return;
    }

    LOG_INFO("Stopping CTI Store ContentDownloader");

    m_shouldStop = true;
    m_contentRegister.reset();
    m_isRunning = false;

    LOG_INFO("CTI Store ContentDownloader stopped");
}

bool ContentDownloader::isRunning() const
{
    return m_isRunning;
}

void ContentDownloader::updateInterval(size_t newInterval)
{
    std::lock_guard<std::mutex> lock(m_mutex);

    m_config.interval = newInterval;

    if (m_contentRegister)
    {
        m_contentRegister->changeSchedulerInterval(newInterval);
        LOG_INFO("Updated ContentDownloader interval to {} seconds", newInterval);
    }
}

ContentManagerConfig ContentDownloader::getConfig() const
{
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_config;
}

void ContentDownloader::updateConfig(const ContentManagerConfig& config)
{
    config.validate();

    std::lock_guard<std::mutex> lock(m_mutex);

    m_config = config;
}

FileProcessingResult ContentDownloader::processMessage(const std::string& message)
{
    try
    {
        LOG_DEBUG("Processing message from Content Manager");

        // Parse the message as JSON using RapidJSON
        json::Json parsedMessage(message.c_str());

        if (!parsedMessage.exists("/paths") || !parsedMessage.exists("/type") || !parsedMessage.exists("/offset"))
        {
            throw std::runtime_error("Invalid message. Missing required fields.");
        }

        auto type = parsedMessage.getString("/type").value_or("");
        auto offset = parsedMessage.getInt("/offset").value_or(0);

        return processContentFiles(parsedMessage, type, offset);
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error processing message: {}", e.what());
        return {0, "", false};
    }
}

FileProcessingResult ContentDownloader::defaultFileProcessingCallback(const std::string& message)
{
    try
    {
        LOG_INFO("Starting CTI content update process");

        auto result = processMessage(message);

        if (m_shouldStop || !std::get<2>(result))
        {
            LOG_DEBUG("Content update process interrupted or failed. Offset: {}, Hash: {}",
                      std::get<0>(result),
                      std::get<1>(result));
            return result;
        }

        LOG_INFO("CTI content update process completed successfully");
        return result;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error in file processing callback: {}", e.what());
        return {0, "", false};
    }
}

FileProcessingResult
ContentDownloader::processContentFiles(const json::Json& parsedMessage, const std::string& type, int offset)
{
    int currentOffset = offset;
    std::string hash = "";

    try
    {
        if (type == "offsets")
        {
            // Process incremental updates
            auto pathsArray = parsedMessage.getArray("/paths");
            if (pathsArray.has_value())
            {
                for (const auto& pathValue : pathsArray.value())
                {
                    if (m_shouldStop)
                    {
                        LOG_DEBUG("Processing interrupted by stop signal");
                        break;
                    }

                    auto pathStr = json::Json(pathValue).getString().value_or("");
                    LOG_DEBUG("Processing file: {}", pathStr);

                    // Read and process the file
                    std::ifstream file(pathStr);
                    if (!file.is_open())
                    {
                        throw std::runtime_error("Unable to open file: " + pathStr);
                    }

                    std::string line;
                    while (std::getline(file, line) && !m_shouldStop)
                    {
                        json::Json item(line.c_str());

                        // Store the content
                        if (!storeContent(item))
                        {
                            LOG_WARNING("Failed to store content item");
                        }

                        // Update offset if available
                        if (item.exists("/offset"))
                        {
                            currentOffset = item.getInt("/offset").value_or(currentOffset);
                        }
                    }
                }
            }
        }
        else if (type == "raw")
        {
            // Process full download
            LOG_INFO("Processing raw content (full download)");

            // Clear existing data for full refresh
            // This would typically clear the database

            auto pathsArray = parsedMessage.getArray("/paths");
            if (pathsArray.has_value())
            {
                for (const auto& pathValue : pathsArray.value())
                {
                    if (m_shouldStop)
                    {
                        LOG_DEBUG("Processing interrupted by stop signal");
                        return {0, "", true};
                    }

                    auto pathStr = json::Json(pathValue).getString().value_or("");
                    LOG_DEBUG("Processing raw file: {}", pathStr);

                    std::ifstream file(pathStr);
                    if (!file.is_open())
                    {
                        throw std::runtime_error("Unable to open file: " + pathStr);
                    }

                    std::string line;
                    int lineCount = 0;

                    while (std::getline(file, line) && !m_shouldStop)
                    {
                        if (++lineCount % 1000 == 0)
                        {
                            LOG_DEBUG("Processed {} lines", lineCount);
                        }

                        json::Json item(line.c_str());

                        // Update offset to the highest value
                        if (item.exists("/offset"))
                        {
                            int itemOffset = item.getInt("/offset").value_or(0);
                            currentOffset = std::max(currentOffset, itemOffset);
                        }

                        // Store the content
                        if (!storeContent(item))
                        {
                            LOG_WARNING("Failed to store content item at line {}", lineCount);
                        }
                    }

                    LOG_INFO("Processed {} lines from raw file", lineCount);
                }
            }
        }
        else
        {
            throw std::runtime_error("Unknown message type: " + type);
        }

        LOG_DEBUG("Last offset processed: {}", currentOffset);
        return {currentOffset, hash, true};
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error processing content files: {}", e.what());
        return {currentOffset, hash, false};
    }
}

bool ContentDownloader::storeContent(const json::Json& content)
{
    try
    {
        // This is where the content would be stored in the local database
        // The actual storage implementation would depend on the database backend
        // For now, this is a placeholder

        if (!content.exists("/name"))
        {
            LOG_WARNING("Content item missing 'name' field");
            return false;
        }

        auto name = content.getString("/name").value_or("unknown");
        LOG_TRACE("Storing content item: {}", name);

        // TODO: Implement actual database storage
        // This would integrate with the ICMReader interface implementation

        return true;
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("Error storing content: {}", e.what());
        return false;
    }
}

} // namespace cti::store