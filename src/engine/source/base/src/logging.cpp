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

namespace logging
{

std::shared_ptr<spdlog::logger> getDefaultLogger()
{
    auto logger = spdlog::get("default");
    if (!logger)
    {
        throw std::runtime_error("The 'default' logger is not initialized.");
    }

    return logger;
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

    if (cfg.filePath == STD_ERR_PATH)
    {
        logger = spdlog::stderr_color_mt("default");
    }
    else if (cfg.filePath == STD_OUT_PATH)
    {
        logger = spdlog::stdout_color_mt("default");
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

void testInit()
{
    auto logger = spdlog::get("default");

    if (!logger)
    {
        LoggingConfig logConfig;
        logConfig.level = Level::Warn;
        start(logConfig);
    }
}

} // namespace logging
