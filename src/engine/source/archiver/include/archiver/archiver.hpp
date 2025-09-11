#ifndef ARCHIVER_ARCHIVER_HPP
#define ARCHIVER_ARCHIVER_HPP

#include <memory>
#include <mutex>
#include <shared_mutex>
#include <stdexcept>
#include <string>

#include <fmt/format.h>
#include <streamlog/ilogger.hpp>

#include <archiver/iarchiver.hpp>

namespace archiver
{

class Archiver final : public IArchiver
{
private:
    // Shared mutex
    mutable std::shared_mutex m_loggerMutex;             ///< Mutex for thread-safe access to the logger
    std::weak_ptr<streamlog::ILogManager> m_logger;      ///< Logger for archiving events
    std::shared_ptr<streamlog::WriterEvent> m_logWriter; ///< Writer for logging events

public:
    explicit Archiver(std::weak_ptr<streamlog::ILogManager> logManager, bool isActive = false)
        : m_logger(std::move(logManager))
        , m_logWriter()
    {
        auto logger = m_logger.lock();
        if (!logger)
        {
            throw std::runtime_error("Logger for archive is not available");
        }

        if (isActive)
        {
            m_logWriter = logger->getWriter("archives");
        }
    }

    /**
     * @copydoc IArchiver::archive
     */
    void archive(const std::string& data) override;

    /**
     * @copydoc IArchiver::archive
     */
    void archive(const char* data) override;

    /**
     * @copydoc IArchiver::activate
     */
    void activate() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        if (!m_logWriter)
        {
            auto logger = m_logger.lock();
            if (!logger)
            {
                throw std::runtime_error("Logger for archive is not available");
            }
            m_logWriter = logger->getWriter("archives");
        }
    }

    /**
     * @copydoc IArchiver::deactivate
     */
    void deactivate() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        m_logWriter.reset();
    }

    /**
     * @copydoc IArchiver::isActive
     */
    bool isActive() const override
    {
        std::shared_lock<std::shared_mutex> lock(m_loggerMutex);
        return m_logWriter != nullptr;
    }

    ~Archiver() override
    {
        std::unique_lock<std::shared_mutex> lock(m_loggerMutex);
        m_logWriter.reset();
    }
};

} // namespace archiver

#endif // ARCHIVER_ARCHIVER_HPP
