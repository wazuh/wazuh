#ifndef _LOGGING_HPP
#define _LOGGING_HPP

#include <dlfcn.h>
#include <iostream>
#include <map>

#include <spdlog/async.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#include "commonDefs.h"
#include "loggerHelper.h"

#define LAMBDA_SEPARATOR "::<lambda>"

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
    Off,      /**< Turn off logging. */
    Invalid
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
        case Level::Off: return "off";
        default: return "invalid";
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
    if (level == levelToStr(Level::Debug))
    {
        return Level::Debug;
    }
    if (level == levelToStr(Level::Info))
    {
        return Level::Info;
    }
    if (level == levelToStr(Level::Warn))
    {
        return Level::Warn;
    }
    if (level == levelToStr(Level::Err))
    {
        return Level::Err;
    }
    if (level == levelToStr(Level::Critical))
    {
        return Level::Critical;
    }
    if (level == levelToStr(Level::Off))
    {
        return Level::Off;
    }
    throw std::invalid_argument(fmt::format("Invalid log level: '{}'", level));
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
 * @brief Retrieves the log level.
 * @return The log level.
 * @throw std::runtime_error If the log level is invalid.
 */
Level getLevel();

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
 *
 * @param lvl Log level to set.
 */
void testInit(Level lvl = Level::Warn);

inline std::string getLambdaName(const char* parentScope, const std::string& lambdaName)
{
    return std::string(parentScope) + LAMBDA_SEPARATOR + lambdaName;
}

void initializeFullLogFunction(
    const std::function<void(
        const int, const std::string&, const std::string&, const int, const std::string&, const std::string&, va_list)>&
        logFunction);

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief Method to initialize the shared library with a full log function.
     *
     * @param logFunction Log function.
     */
    void init(full_log_fnc_t callback);
#ifdef __cplusplus
}
#endif

constexpr inline const char* default_tag()
{
    return "wazuh-engine";
}

/**
 * @brief Checks whether standalone mode is enabled for the Wazuh engine.
 *
 * Reads the environment variable `WAZUH_ENGINE_STANDALONE_MODE_ENABLED` once
 * and caches the result for subsequent calls. The check is case-insensitive.
 *
 * If the variable is set to the string `"true"`, standalone mode is considered
 * enabled. Any other value (or absence of the variable) disables standalone mode.
 *
 * @return true  If standalone mode is enabled.
 * @return false Otherwise.
 */
bool standaloneModeEnabled();

/**
 * @brief Unified logging bridge for both standalone (spdlog) and Wazuh callback modes.
 *
 * This templated function routes log messages either to spdlog (standalone mode)
 * or to the Wazuh-provided logging callback, depending on the value of
 * `standaloneModeEnabled()`.
 *
 * In standalone mode, the message is forwarded directly to the default spdlog
 * logger with source location information.
 *
 * In Wazuh callback mode, the message is first formatted with {fmt}, and then
 * dispatched to the appropriate `Log::Logger::*` method based on the severity level.
 *
 * @tparam Args Variadic template parameters for the format string arguments.
 * @param lvl      The spdlog logging level (trace, debug, info, warn, err, critical).
 * @param file     Source file name where the log was invoked (typically `__FILE__`).
 * @param line     Source line number where the log was invoked (typically `__LINE__`).
 * @param funcName Function name context for the log (typically `SPDLOG_FUNCTION` or custom).
 * @param fmtstr   The format string (constexpr-checked by {fmt}).
 * @param args     Arguments to be formatted into the message.
 *
 * @note In Wazuh callback mode, `trace` maps to `Log::Logger::debugVerbose`,
 *       `debug` to `Log::Logger::debug`, `info` to `Log::Logger::info`,
 *       `warn` to `Log::Logger::warning`, and both `err` and `critical` map
 *       to `Log::Logger::error`.
 */
template<typename... Args>
inline void log_bridge(spdlog::level::level_enum lvl,
                       const char* file,
                       int line,
                       const char* funcName,
                       fmt::format_string<Args...> fmtstr,
                       Args&&... args)
{
    if (standaloneModeEnabled())
    {
        auto logger = getDefaultLogger();
        logger->log(spdlog::source_loc {file, line, funcName}, lvl, fmtstr, std::forward<Args>(args)...);
    }
    else
    {
        auto msg = fmt::format(fmtstr, std::forward<Args>(args)...);
        switch (lvl)
        {
            case spdlog::level::trace:
                Log::Logger::debugVerbose(default_tag(), {file, line, funcName}, "%s", msg.c_str());
                break;
            case spdlog::level::debug:
                Log::Logger::debug(default_tag(), {file, line, funcName}, "%s", msg.c_str());
                break;
            case spdlog::level::info:
                Log::Logger::info(default_tag(), {file, line, funcName}, "%s", msg.c_str());
                break;
            case spdlog::level::warn:
                Log::Logger::warning(default_tag(), {file, line, funcName}, "%s", msg.c_str());
                break;
            case spdlog::level::err:
            case spdlog::level::critical:
                Log::Logger::error(default_tag(), {file, line, funcName}, "%s", msg.c_str());
                break;
            default: Log::Logger::info(default_tag(), {file, line, funcName}, "%s", msg.c_str()); break;
        }
    }
}

/**
 * @brief Calculates the effective log level to use.
 *
 * Determines the logging level based on the number of `-d` options provided
 * (debugCount) and the configured log level string. If debugCount > 0,
 * it overrides the configuration: one `-d` sets Debug, two or more set Trace.
 *
 * @param debugCount Number of debug flags passed on the CLI (-d occurrences).
 * @param cfgLevelStr Log level string taken from the configuration (e.g., "info", "debug").
 * @return logging::Level The effective logging level.
 */
logging::Level computeEffectiveLevel(int debugCount, const std::string& cfgLevelStr);

/**
 * @brief Applies the desired log level in standalone (spdlog) mode.
 *
 * Sets the default logger to the given level, if different from the current one,
 * and emits a debug message notifying the change.
 *
 * @param target The target log level to apply.
 */
void applyLevelStandalone(logging::Level target);

/**
 * @brief Applies the desired log level when running in Wazuh callback mode.
 *
 * In callback mode, log levels are switched through the symbol `nowDebug`
 * resolved from libwazuhshared. One call to `nowDebug` enables Debug level;
 * two consecutive calls enable Trace level.
 *
 * @param target The target log level to apply. Only Debug and Trace are supported.
 * @param libwazuhshared Handle to the opened libwazuhshared shared library.
 *                       Must be a valid dlopen() handle.
 *
 * @throw std::runtime_error If the `nowDebug` symbol cannot be resolved.
 */
void applyLevelWazuh(logging::Level target, void* libwazuhshared);

} // namespace logging

// TRACE
#define LOG_TRACE(msg, ...)                                                                                            \
    ::logging::log_bridge(spdlog::level::trace, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_TRACE_L(functionName, msg, ...)                                                                            \
    ::logging::log_bridge(spdlog::level::trace, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

// DEBUG
#define LOG_DEBUG(msg, ...)                                                                                            \
    ::logging::log_bridge(spdlog::level::debug, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_DEBUG_L(functionName, msg, ...)                                                                            \
    ::logging::log_bridge(spdlog::level::debug, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

// INFO
#define LOG_INFO(msg, ...)                                                                                             \
    ::logging::log_bridge(spdlog::level::info, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_INFO_L(functionName, msg, ...)                                                                             \
    ::logging::log_bridge(spdlog::level::info, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

// WARNING
#define LOG_WARNING(msg, ...)                                                                                          \
    ::logging::log_bridge(spdlog::level::warn, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_WARNING_L(functionName, msg, ...)                                                                          \
    ::logging::log_bridge(spdlog::level::warn, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

// ERROR
#define LOG_ERROR(msg, ...)                                                                                            \
    ::logging::log_bridge(spdlog::level::err, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_ERROR_L(functionName, msg, ...)                                                                            \
    ::logging::log_bridge(spdlog::level::err, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

// CRITICAL
#define LOG_CRITICAL(msg, ...)                                                                                         \
    ::logging::log_bridge(spdlog::level::critical, __FILE__, __LINE__, SPDLOG_FUNCTION, fmt::runtime(msg), ##__VA_ARGS__)
#define LOG_CRITICAL_L(functionName, msg, ...)                                                                         \
    ::logging::log_bridge(spdlog::level::critical, __FILE__, __LINE__, (functionName), fmt::runtime(msg), ##__VA_ARGS__)

#endif // _LOGGING_HPP
