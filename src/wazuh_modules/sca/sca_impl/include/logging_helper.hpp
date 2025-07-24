#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "logging_helper.h"

#ifdef __cplusplus
} /// extern "C"
#endif

#include <functional>
#include <string>

class LoggingHelper
{
public:
    static LoggingHelper& getInstance()
    {
        static LoggingHelper instance;
        return instance;
    }

    static void setLogCallback(std::function<void(const modules_log_level_t level, const char* log)> callback)
    {
        getInstance().m_externalLogCallback = callback;
    }

    void log(const modules_log_level_t level, const std::string& message) const
    {
        if(!m_externalLogCallback)
        {
            throw std::runtime_error("Log callback not set.");
        }

        m_externalLogCallback(level, message.c_str());
    }

 private:
    LoggingHelper() = default;

    LoggingHelper(const LoggingHelper&) = delete;
    LoggingHelper& operator=(const LoggingHelper&) = delete;
    LoggingHelper(LoggingHelper&&) = delete;
    LoggingHelper& operator=(LoggingHelper&&) = delete;

    std::function<void(const modules_log_level_t level, const char* log)> m_externalLogCallback;
};
