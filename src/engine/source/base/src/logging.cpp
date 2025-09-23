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
#include <base/libwazuhshared.hpp>

#include <spdlog/pattern_formatter.h>

namespace Log
{
std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
    GLOBAL_LOG_FUNCTION;
};

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

    setenv(base::process::ENV_ENGINE_STANDALONE, "true", 1);
}

void initializeFullLogFunction(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        callback)
{
    Log::assignLogFunction(callback);
}

#ifdef __cplusplus
extern "C"
{
#endif

    void init()
    {
        using LogginFnWrapperType = void (*)(int, const char*, const char*, int, const char*, const char*, va_list);
        const auto logWrapper = base::libwazuhshared::getFunction<LogginFnWrapperType>("mtLoggingFunctionsWrapper");
        base::libwazuhshared::setLoggerTag(logging::default_tag());

        initializeFullLogFunction(
            [logWrapper](const int logLevel,
                       const std::string& tag,
                       const std::string& file,
                       const int line,
                       const std::string& func,
                       const std::string& logMessage,
                       va_list args)
            { logWrapper(logLevel, tag.c_str(), file.c_str(), line, func.c_str(), logMessage.c_str(), args); });
    }

#ifdef __cplusplus
}
#endif

void applyLevelStandalone(logging::Level target, int debugCount)
{
    // -d takes priority over the configuration
    const logging::Level effective = (debugCount > 1)    ? logging::Level::Trace
                                     : (debugCount == 1) ? logging::Level::Debug
                                                         : target; // without -d, use config level (target)

    const auto current = logging::getLevel();
    if (current != effective)
    {
        logging::setLevel(effective);
        LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(effective));
    }
}

void applyLevelWazuh(logging::Level target, int debugCount)
{
    // -d takes priority over the configuration
    const logging::Level effective = (debugCount > 1)    ? logging::Level::Trace
                                     : (debugCount == 1) ? logging::Level::Debug
                                                         : target; // without -d, use config level (target)

    if (effective != logging::Level::Debug && effective != logging::Level::Trace)
    {
        return; // Info/Warn/Err/Critical
    }

    using NowDebugFnType = void (*)();
    const auto nowDebug = base::libwazuhshared::getFunction<NowDebugFnType>("nowDebug");

    const int times = (effective == logging::Level::Debug) ? 1 : 2;
    for (int i = 0; i < times; ++i) nowDebug();

    LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(effective));
}

/**
 * @brief Creates a spdlog-based logging function compatible with GLOBAL_LOG_FUNCTION signature
 *        for use in standalone mode.
 *
 * This function returns a logging function that uses spdlog internally and is compatible
 * with the GLOBAL_LOG_FUNCTION signature used throughout the Wazuh codebase.
 *
 * @return A function that can be used to log messages using spdlog in standalone mode.
 *         The returned function has the signature:
 *         void(const int, const char*, const char*, const int, const char*, const char*, va_list)
 */
std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
createStandaloneLogFunction()
{
    return [](const int logLevel,
              const char* tag,
              const char* file,
              const int line,
              const char* func,
              const char* msg,
              va_list args) -> void
    {
        // Convert the log level from Wazuh format to logging::Level
        logging::Level level;
        switch (logLevel)
        {
            case 0: level = logging::Level::Debug; break;
            case 1: level = logging::Level::Info; break;
            case 2: level = logging::Level::Warn; break;
            case 3: level = logging::Level::Err; break;
            case 4: level = logging::Level::Critical; break;
            case 5: level = logging::Level::Trace; break;
            default: level = logging::Level::Info; break;
        }

        char buffer[4096]; // Max size of formatted message TODO move a constant
        vsnprintf(buffer, sizeof(buffer), msg, args);
        backend_log(level, file, line, func, buffer, strlen(buffer));
    };
}
} // namespace logging
