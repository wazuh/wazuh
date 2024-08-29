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
constexpr auto STD_ERR_PATH {"/dev/stderr"};

/**
 * @brief Default path for the info log file.
 * The default path where info logs should be saved.
 */
constexpr auto STD_OUT_PATH {"/dev/stdout"};

// constexpr auto WAZUH_LOG_HEADER {"%D %T wazuh-engine[%P] %s:%# at %!(): %l: %v"};

/**
 * @brief Default log header format.
 * The default format used for log messages.
 */
constexpr auto DEFAULT_LOG_HEADER {"%Y-%m-%d %T.%e %P:%t %l: %v"};

/**
 * @brief Log header format for debug messages.
 * The format used for log messages with debug level.
 * It includes additional information such as source file, function, and line number.
 */
constexpr auto LOG_DEBUG_HEADER {"%Y-%m-%d %T.%e %P:%t %s:%# at %!(): %l: %v"};

/**
 * @brief Default log level.
 * Possible values: "trace", "debug", "info", "warning", "error", "critical", "off".
 */
constexpr auto DEFAULT_LOG_LEVEL {"info"};

/**
 * @brief Default number of dedicated threads.
 * 0 means no dedicated threads.
 */
constexpr auto DEFAULT_LOG_THREADS {0};

/**
 * @brief Default size of the log threads' queue.
 */
constexpr auto DEFAULT_LOG_THREADS_QUEUE_SIZE {8192};

/**
 * @brief Default flush interval for logs.
 * Value in milliseconds.
 */
constexpr auto DEFAULT_LOG_FLUSH_INTERVAL {1};

/**
 * @brief Enum class defining logging levels.
 *
 * This enum class represents different logging levels such as Trace, Debug, Info, Warn, Err, Critical, and Off.
 */
enum class Level
{
    Trace,    /**< Trace logging level. */
    Debug,    /**< Debug logging level. */
    Info,     /**< Information logging level. */
    Warn,     /**< Warning logging level. */
    Err,      /**< Error logging level. */
    Critical, /**< Critical logging level. */
    Off       /**< Turn off logging. */
};

/**
 * @brief Alias for mapping logging levels to spdlog levels.
 *
 * This alias represents a mapping between custom logging levels and corresponding spdlog levels.
 */
using LevelMap = std::unordered_map<Level, spdlog::level::level_enum>;

/**
 * @brief Map of custom logging levels to spdlog levels.
 *
 * This static constant variable represents a mapping of custom logging levels to corresponding spdlog levels.
 * It is used for converting between custom logging levels and spdlog levels.
 */
static const LevelMap SEVERITY_LEVEL {
    {Level::Trace, spdlog::level::trace},       /**< Trace level mapping. */
    {Level::Debug, spdlog::level::debug},       /**< Debug level mapping. */
    {Level::Info, spdlog::level::info},         /**< Info level mapping. */
    {Level::Warn, spdlog::level::warn},         /**< Warning level mapping. */
    {Level::Err, spdlog::level::err},           /**< Error level mapping. */
    {Level::Critical, spdlog::level::critical}, /**< Critical level mapping. */
    {Level::Off, spdlog::level::off}            /**< Off level mapping. */
};

/**
 * @brief Get string representation of the level
 *
 * @param level level to convert
 * @return constexpr auto String representation of the level
 */
constexpr static auto levelToStr(Level level)
{
    switch (level)
    {
        case Level::Trace: return "trace";
        case Level::Debug: return "debug";
        case Level::Info: return "info";
        case Level::Warn: return "warning";
        case Level::Err: return "error";
        case Level::Critical: return "critical";
        default: return "off";
    }
}

/**
 * @brief Get level from string representation
 *
 * @param level String representation of the level
 * @return spdlog::level::level_enum
 */
constexpr static auto strToLevel(std::string_view level)
{
    if (level == levelToStr(Level::Trace))
    {
        return Level::Trace;
    }
    else if (level == levelToStr(Level::Debug))
    {
        return Level::Debug;
    }
    else if (level == levelToStr(Level::Info))
    {
        return Level::Info;
    }
    else if (level == levelToStr(Level::Warn))
    {
        return Level::Warn;
    }
    else if (level == levelToStr(Level::Err))
    {
        return Level::Err;
    }
    else if (level == levelToStr(Level::Critical))
    {
        return Level::Critical;
    }
    return Level::Off;
}

/**
 * @brief Structure holding logging configuration parameters.
 */
struct LoggingConfig
{
    std::string filePath {STD_OUT_PATH};                       ///< Path to the log file.
    Level level {Level::Info};                                 ///< Log level.
    const uint32_t flushInterval {DEFAULT_LOG_FLUSH_INTERVAL}; ///< Flush interval in milliseconds.
    const uint32_t dedicatedThreads {DEFAULT_LOG_THREADS};     ///< Number of dedicated threads.
    const uint32_t queueSize {DEFAULT_LOG_THREADS_QUEUE_SIZE}; ///< Size of the log queue for dedicated threads.
    bool truncate {false}; ///< If true, the log file will be deleted for each start of the engine.
};

/**
 * @brief Retrieves the default logger.
 * @return Shared pointer to the default logger.
 */
std::shared_ptr<spdlog::logger> getDefaultLogger();

/**
 * @brief Sets the log level.
 * @param levelStr The log level as a string.
 */
void setLevel(Level level);

/**
 * @brief Starts logging with the given configuration.
 * @param cfg Logging configuration parameters.
 */
void start(const LoggingConfig& cfg);

/**
 * @brief Stops logging.
 */
void stop();

/**
 * @brief Initializes the logger for testing purposes.
 */
void testInit();

} // namespace logging

#define LOG_TRACE(msg, ...)                                                                                            \
    logging::getDefaultLogger()->log(                                                                                  \
        spdlog::source_loc {__FILE__, __LINE__, SPDLOG_FUNCTION}, spdlog::level::trace, msg, ##__VA_ARGS__)
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

#endif // _H_LOGGING
