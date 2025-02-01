#ifndef _METRICS_OTLOGGER_HPP
#define _METRICS_OTLOGGER_HPP

#include <fmt/format.h>

#include <base/logging.hpp>

#include "ot.hpp"

namespace metrics
{

class OtLogger : public otsdk::internal_log::LogHandler
{
public:
    ~OtLogger() override = default;

    void Handle(otsdk::internal_log::LogLevel level,
                const char* file,
                int line,
                const char* msg,
                const otsdk::AttributeMap& attributes) noexcept override
    {
        // Prepare the message
        auto message = fmt::format("Internal OTSDK message: {}:{}: {}", file, line, msg);

        switch (level)
        {
            case otsdk::internal_log::LogLevel::Debug: LOG_DEBUG(message); break;
            case otsdk::internal_log::LogLevel::Info: LOG_INFO(message); break;
            case otsdk::internal_log::LogLevel::Warning: LOG_WARNING(message); break;
            case otsdk::internal_log::LogLevel::Error: LOG_ERROR(message); break;
            default: LOG_ERROR("Unknown log level from OTSDK: {}", message); break;
        }
    }
};

} // namespace metrics

#endif // _METRICS_OTLOGGER_HPP
