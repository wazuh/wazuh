/**
 * Implementation of the logging module needs to be defined in a cpp file, as spdlog uses static variables that need to
 * be defined only once when included in multiple translation units. This issue occurs when the old logging.hpp is moved
 * to a static library that is linked in multiple libraries, leading to multiple definitions of static variables if not
 * properly managed.
 *
 * See: https://github.com/gabime/spdlog/issues/1658#issuecomment-681193558
 *
 */

#include <base/logging.hpp>
#include <spdlog/pattern_formatter.h>

namespace logging
{

class CustomSink : public spdlog::sinks::sink
{
public:
    CustomSink()
        : m_upFormatter(std::make_unique<spdlog::pattern_formatter>())
    {
    }

    void log(const spdlog::details::log_msg& message) override
    {
        if (should_log(message.level))
        {
            m_level = message.level;
            spdlog::memory_buf_t buf;
            m_upFormatter->format(message, buf);
            std::string formatted_message(buf.data(), buf.size());

            if (message.level >= spdlog::level::warn)
            {
                std::cerr << formatted_message;
            }
            else
            {
                std::cout << formatted_message;
            }
        }
    }

    void flush() override
    {
        if (m_level >= spdlog::level::warn)
        {
            std::cerr << std::flush;
        }
        else
        {
            std::cout << std::flush;
        }
    }

    void set_pattern(const std::string& pattern) override
    {
        m_upFormatter = std::make_unique<spdlog::pattern_formatter>(pattern, spdlog::pattern_time_type::local);
    }

    void set_formatter(std::unique_ptr<spdlog::formatter> sink_formatter) override
    {
        m_upFormatter = std::move(sink_formatter);
    }

private:
    spdlog::level::level_enum m_level;
    std::unique_ptr<spdlog::formatter> m_upFormatter;
};

std::shared_ptr<spdlog::logger> getDefaultLogger()
{
    auto logger = spdlog::get("default");
    if (!logger)
    {
        throw std::runtime_error("The 'default' logger is not initialized.");
    }

    return logger;
}

Level getLevel()
{
    auto spdLevel = getDefaultLogger()->level();
    for (const auto& [level, spdlogLevel] : SEVERITY_LEVEL)
    {
        if (spdlogLevel == spdLevel)
        {
            return level;
        }
    }
    throw std::runtime_error("getLevel: Invalid log level.");
}

void setLevel(Level level)
{
    getDefaultLogger()->set_level(SEVERITY_LEVEL.at(level));

    if (level <= Level::Debug)
    {
        getDefaultLogger()->set_pattern(LOG_DEBUG_HEADER);
    }
    else
    {
        getDefaultLogger()->set_pattern(DEFAULT_LOG_HEADER);
    }
}

void start(const LoggingConfig& cfg)
{
    std::shared_ptr<spdlog::logger> logger;

    if (0 < cfg.dedicatedThreads)
    {
        spdlog::init_thread_pool(cfg.queueSize, cfg.dedicatedThreads);
    }

    if (cfg.filePath == STD_ERR_PATH || cfg.filePath == STD_OUT_PATH || cfg.filePath.empty())
    {
        auto custumSink = std::make_shared<CustomSink>();

        logger = std::make_shared<spdlog::logger>("default", custumSink);
        spdlog::set_default_logger(logger);
    }
    else
    {
        logger = spdlog::basic_logger_mt("default", cfg.filePath, cfg.truncate);
    }

    setLevel(cfg.level);
    logger->flush_on(spdlog::level::trace);
}

void stop()
{
    spdlog::shutdown();
}

void testInit(Level lvl)
{
    auto logger = spdlog::get("default");

    if (!logger)
    {
        LoggingConfig logConfig;
        logConfig.level = lvl;
        start(logConfig);
    }
}

} // namespace logging
