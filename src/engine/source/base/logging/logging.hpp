#ifndef _H_LOGGING
#define _H_LOGGING

#include <fmtlog-inl.h>
#include <fmtlog.h>

namespace logging
{
enum class LogLevel
{
    Debug = 0,
    Info,
    Warn,
    Error,
    Off,
};

// Not great but avoiding having a cpp file for this
struct LoggingConfig
{
    const char* filePath = nullptr;
    const char* header = nullptr;
    LogLevel logLevel = LogLevel::Info;
    int pollInterval = 5000 /*ns*/;
};

static inline void loggingInit(LoggingConfig const& cfg)
{
    if (cfg.filePath)
    {
        std::string path = cfg.filePath;
        // TODO: check portability issues
        if ("/dev/stdout" == path)
        {
            fmtlog::setLogFile(stdout, false);
        }
        else if ("/dev/stderr" == path)
        {
            fmtlog::setLogFile(stderr, false);
        }
        else
        {
            fmtlog::setLogFile(cfg.filePath, false);
        }
    }
    else
    {
        fmtlog::setLogFile(stderr, false);
    }

    if (cfg.header)
    {
        fmtlog::setHeaderPattern(cfg.header);
    }

    fmtlog::startPollingThread(cfg.pollInterval);

    fmtlog::setLogLevel(fmtlog::LogLevel(cfg.logLevel));
}

static inline void loggingTerm()
{
    fmtlog::stopPollingThread();
}
} // namespace logging

#define WAZUH_LOG_DEBUG(fmt, ...) FMTLOG(fmtlog::DBG, fmt, ##__VA_ARGS__);
#define WAZUH_LOG_INFO(fmt, ...)  FMTLOG(fmtlog::INF, fmt, ##__VA_ARGS__);
#define WAZUH_LOG_WARN(fmt, ...)  FMTLOG(fmtlog::WRN, fmt, ##__VA_ARGS__);
#define WAZUH_LOG_ERROR(fmt, ...) FMTLOG(fmtlog::ERR, fmt, ##__VA_ARGS__);
#endif
