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

namespace Log
{
std::function<void(
    const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>
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

    void init(full_log_fnc_t callback)
    {
        initializeFullLogFunction(
            [callback](const int logLevel,
                          const std::string& tag,
                          const std::string& file,
                          const int line,
                          const std::string& func,
                          const std::string& logMessage,
                          va_list args)
            { callback(logLevel, tag.c_str(), file.c_str(), line, func.c_str(), logMessage.c_str(), args); });
    }

#ifdef __cplusplus
}
#endif

bool standaloneModeEnabled()
{
    static int cached = -1;
    if (cached == -1)
    {
        const char* env = std::getenv("WAZUH_SKIP_OSSEC_CONF");
        if (env)
        {
            std::string val(env);
            std::transform(val.begin(), val.end(), val.begin(), ::tolower);
            cached = (val == "true");
        }
        else
        {
            cached = 0;
        }
    }
    return cached == 1;
}

logging::Level computeEffectiveLevel(int debugCount, const std::string& cfgLevelStr)
{
    if (debugCount > 0)
    {
        return (debugCount == 1) ? logging::Level::Debug : logging::Level::Trace;
    }
    return logging::strToLevel(cfgLevelStr);
}

void applyLevelStandalone(logging::Level target)
{
    const auto current = logging::getLevel();
    if (current != target)
    {
        logging::setLevel(target);
        LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(target));
    }
}

void applyLevelWazuh(logging::Level target, void* libwazuhshared)
{
    if (target != logging::Level::Debug && target != logging::Level::Trace)
    {
        return; // Nothing to do for Info/Warn/Err/Critical/Off
    }

    using now_debug_fn_t = void (*)();
    auto* nowDebug = reinterpret_cast<now_debug_fn_t>(dlsym(libwazuhshared, "nowDebug"));
    if (!nowDebug)
    {
        throw std::runtime_error {fmt::format("nowDebug symbol not found: {}", dlerror())};
    }

    const int times = (target == logging::Level::Debug) ? 1 : 2;
    for (int i = 0; i < times; ++i) nowDebug();
    LOG_DEBUG("Changed log level to '{}'", logging::levelToStr(target));
}

} // namespace logging
