#include "container_instances.h"

#include "container_instances_facade.hpp"

#include "json.hpp"
#include "logging_helper.h"

#include <cstdarg>
#include <memory>
#include <string>

namespace
{

    constexpr const char* LOG_TAG = "wazuh-modulesd:container-instances";

    struct CJsonFree
    {
        void operator()(char* raw) const
        {
            cJSON_free(raw);
        }
    };

    /// full_log_fnc_t is variadic-by-va_list; this shim turns a plain string call
    /// into one.
    void dispatchLog(full_log_fnc_t callback, int level, const char* format, ...)
    {
        va_list args;
        va_start(args, format);
        callback(level, LOG_TAG, "", 0, "", format, args);
        va_end(args);
    }

    int toModulesLogLevel(wazuh::container_instances::LogLevel level)
    {
        using wazuh::container_instances::LogLevel;
        switch (level)
        {
            case LogLevel::debugVerbose: return LOG_DEBUG_VERBOSE;
            case LogLevel::debug: return LOG_DEBUG;
            case LogLevel::info: return LOG_INFO;
            case LogLevel::warn: return LOG_WARNING;
            case LogLevel::error: return LOG_ERROR;
        }
        return LOG_INFO;
    }

} // namespace

#ifdef __cplusplus
extern "C"
{
#endif

    void container_instances_start(full_log_fnc_t callbackLog, const cJSON* configuration)
    {
        auto logger = [callbackLog](wazuh::container_instances::LogLevel level, const std::string& message)
        {
            dispatchLog(callbackLog, toModulesLogLevel(level), "%s", message.c_str());
        };

        try
        {
            nlohmann::json parsed;
            if (configuration != nullptr)
            {
                const std::unique_ptr<char, CJsonFree> raw {cJSON_PrintUnformatted(configuration)};
                parsed = nlohmann::json::parse(raw.get());
            }
            wazuh::container_instances::ContainerInstancesFacade::instance().start(parsed, logger);
        }
        catch (const std::exception& error)
        {
            dispatchLog(callbackLog, LOG_ERROR, "Cannot start container_instances: %s", error.what());
        }
    }

    void container_instances_stop(void)
    {
        wazuh::container_instances::ContainerInstancesFacade::instance().stop();
    }

#ifdef __cplusplus
}
#endif
