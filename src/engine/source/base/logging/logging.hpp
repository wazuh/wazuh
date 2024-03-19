#ifndef _H_LOGGING
#define _H_LOGGING

#include <iostream>
#include <map>

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

namespace logging
{

/**
 * @brief Default path for the error log file.
 * The default path where error logs should be saved.
 */
constexpr char DEFAULT_LOG_ERROR_PATH[] {"/dev/stderr"};

/**
 * @brief Default path for the info log file.
 * The default path where info logs should be saved.
 */
constexpr char DEFAULT_LOG_INFO_PATH[] {"/dev/stdout"};

/**
 * @brief Default log header format.
 * The default format used for log messages.
 */
constexpr char DEFAULT_LOG_HEADER[] {"%Y-%m-%d %T.%e %P:%t %l: %v"};

/**
 * @brief Log header format for debug messages.
 * The format used for log messages with debug level.
 * It includes additional information such as source file, function, and line number.
 */
constexpr char LOG_DEBUG_HEADER[] {"%Y-%m-%d %T.%e %P:%t %l [%s %! %#]: %v"};

/**
 * @brief Default log level.
 * Possible values: "trace", "debug", "info", "warning", "error", "critical", "off".
 */
constexpr char DEFAULT_LOG_LEVEL[] {"info"};

/**
 * @brief Default number of dedicated threads.
 * 0 means no dedicated threads.
 */
constexpr uint32_t DEFAULT_LOG_THREADS {0};

/**
 * @brief Default size of the log threads' queue.
 */
constexpr uint32_t DEFAULT_LOG_THREADS_QUEUE_SIZE {8192};

/**
 * @brief Default flush interval for logs.
 * Value in milliseconds.
 */
constexpr uint32_t DEFAULT_LOG_FLUSH_INTERVAL {1};

/**
 * @brief Type alias for mapping log level strings to their corresponding enum values.
 */
using LogLevelMap = std::map<std::string, spdlog::level::level_enum>;

/**
 * @brief Map of log level strings to their corresponding enum values.
 */
const LogLevelMap SEVERITY_LEVEL {{"trace", spdlog::level::trace},
                                  {"debug", spdlog::level::debug},
                                  {"info", spdlog::level::info},
                                  {"warning", spdlog::level::warn},
                                  {"error", spdlog::level::err},
                                  {"critical", spdlog::level::critical},
                                  {"off", spdlog::level::off}};

/**
 * @brief Structure holding logging configuration parameters.
 */
struct LoggingConfig
{
    std::string filePath {DEFAULT_LOG_INFO_PATH};              ///< Path to the log file.
    std::string level {DEFAULT_LOG_LEVEL};                     ///< Log level.
    const uint32_t flushInterval {DEFAULT_LOG_FLUSH_INTERVAL}; ///< Flush interval in milliseconds.
    const uint32_t dedicatedThreads {DEFAULT_LOG_THREADS};     ///< Number of dedicated threads.
    const uint32_t queueSize {DEFAULT_LOG_THREADS_QUEUE_SIZE}; ///< Size of the log queue for dedicated threads.
    bool truncate; ///< If true, the log file will be deleted for each start of the engine.
};

/**
 * @brief Retrieves the default logger.
 * @return Shared pointer to the default logger.
 */
inline std::shared_ptr<spdlog::logger> getDefaultLogger()
{
    auto logger = spdlog::get("default");
    if (!logger)
    {
        throw std::runtime_error("The 'default' logger is not initialized.");
    }

    return logger;
}

/**
 * @brief Sets the log level.
 * @param levelStr The log level as a string.
 */
inline void setLevel(const std::string& levelStr)
{
    auto levelIter = SEVERITY_LEVEL.find(levelStr);
    if (levelIter == SEVERITY_LEVEL.end())
    {
        throw std::runtime_error(
            fmt::format("An error occurred while setting the log level: '{}' is not defined", levelStr));
    }

    getDefaultLogger()->set_level(levelIter->second);

    if (levelIter->second == spdlog::level::debug)
    {
        getDefaultLogger()->set_pattern(LOG_DEBUG_HEADER);
    }
    else
    {
        getDefaultLogger()->set_pattern(DEFAULT_LOG_HEADER);
    }
}

/**
 * @brief Starts logging with the given configuration.
 * @param cfg Logging configuration parameters.
 */
inline void start(const LoggingConfig& cfg)
{
    try
    {
        if (0 < cfg.dedicatedThreads)
        {
            // Here we set the amount of DEDICATED threads
            spdlog::init_thread_pool(cfg.queueSize, cfg.dedicatedThreads);
        }

        if (!cfg.filePath.empty())
        {
            if (cfg.filePath == DEFAULT_LOG_ERROR_PATH)
            {
                auto logger = spdlog::stderr_color_mt("default");
                logger->flush_on(spdlog::level::err);
            }
            else if (cfg.filePath == DEFAULT_LOG_INFO_PATH)
            {
                auto logger = spdlog::stdout_color_mt("default");
                logger->flush_on(spdlog::level::info);
            }
            else
            {
                spdlog::basic_logger_mt("default", cfg.filePath, cfg.truncate);
                spdlog::flush_every(std::chrono::milliseconds(cfg.flushInterval));
                setLevel(cfg.level);
            }
        }
        else
        {
            spdlog::stdout_color_mt("default");
            spdlog::flush_every(std::chrono::milliseconds(cfg.flushInterval));
            setLevel(cfg.level);
        }
    }
    catch (const std::exception& e)
    {
        throw std::runtime_error(fmt::format("Log initialization failed: {}", e.what()));
    }
}

/**
 * @brief Stops logging.
 */
inline void stop()
{
    spdlog::shutdown();
}

inline void testInit()
{
    static bool initialized = false;

    if (!initialized)
    {
        LoggingConfig logConfig;
        logConfig.level = "off";
        logConfig.filePath = "";
        start(logConfig);
        initialized = true;
    }
}

} // namespace logging

#define LOG_TRACE(msg, ...) logging::getDefaultLogger()->trace(msg, ##__VA_ARGS__)
#define LOG_DEBUG(msg, ...)                                                                                            \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::debug, msg, ##__VA_ARGS__)
#define LOG_INFO(msg, ...)                                                                                             \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::info, msg, ##__VA_ARGS__)
#define LOG_WARNING(msg, ...)                                                                                          \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::warn, msg, ##__VA_ARGS__)
#define LOG_ERROR(msg, ...)                                                                                            \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::err, msg, ##__VA_ARGS__)
#define LOG_CRITICAL(msg, ...)                                                                                         \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::critical, msg, ##__VA_ARGS__)

#endif
