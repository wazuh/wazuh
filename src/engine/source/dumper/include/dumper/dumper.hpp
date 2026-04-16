#ifndef DUMPER_DUMPER_HPP
#define DUMPER_DUMPER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>

#include <fmt/format.h>
#include <streamlog/ilogger.hpp>

#include <dumper/idumper.hpp>

namespace dumper
{

constexpr auto CHANNEL_NAME = "event-dumps";
constexpr auto CHANNEL_EXTENSION = "json";

class Dumper final : public IDumper
{
private:
    // Shared mutex
    mutable std::shared_mutex m_loggerMutex;             ///< Mutex for thread-safe access to the logger
    std::weak_ptr<streamlog::ILogManager> m_logger;      ///< Logger for dumping events
    streamlog::RotationConfig m_channelConfig;           ///< Lazy-created streamlog channel configuration
    std::shared_ptr<streamlog::WriterEvent> m_logWriter; ///< Writer for logging events

public:
    explicit Dumper(std::weak_ptr<streamlog::ILogManager> logManager,
                    streamlog::RotationConfig channelConfig,
                    bool isActive = false)
        : m_logger(std::move(logManager))
        , m_channelConfig(std::move(channelConfig))
        , m_logWriter()
    {
        auto logger = m_logger.lock();
        if (!logger)
        {
            throw std::runtime_error("Logger for dumper is not available");
        }

        if (isActive)
        {
            m_logWriter = logger->ensureAndGetWriter(CHANNEL_NAME, m_channelConfig, CHANNEL_EXTENSION);
        }
    }

    /**
     * @copydoc IDumper::dump
     */
    void dump(const std::string& data) override;

    /**
     * @copydoc IDumper::dump
     */
    void dump(const char* data) override;

    /**
     * @copydoc IDumper::dump
     */
    void dump(std::string_view data) override;

    /**
     * @copydoc IDumper::activate
     */
    void activate() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        if (!m_logWriter)
        {
            auto logger = m_logger.lock();
            if (!logger)
            {
                throw std::runtime_error("Logger for dumper is not available");
            }
            m_logWriter = logger->ensureAndGetWriter(CHANNEL_NAME, m_channelConfig, CHANNEL_EXTENSION);
        }
    }

    /**
     * @copydoc IDumper::deactivate
     */
    void deactivate() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        m_logWriter.reset();
    }

    /**
     * @copydoc IDumper::isActive
     */
    bool isActive() const override
    {
        std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
        return m_logWriter != nullptr;
    }

    ~Dumper() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        m_logWriter.reset();
    }
};

} // namespace dumper

#endif // DUMPER_DUMPER_HPP
