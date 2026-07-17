/*
 * Wazuh remoted module (C++ worker bridge)
 * Copyright (C) 2015, Wazuh Inc.
 * July 17, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "remotedModule.hpp"
#include "remotedModuleFacade.hpp"

namespace Log
{
    // Single definition of the DSO-global log sink used by loggerHelper.h.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

void RemotedModule::start(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction,
    const remoted_module_config_t& configuration) const
{
    RemotedModuleFacade::instance().start(logFunction, configuration);
}

void RemotedModule::stop() const
{
    RemotedModuleFacade::instance().stop();
}

#ifdef __cplusplus
extern "C"
{
#endif

    void remoted_module_start(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration)
    {
        try
        {
            // Defaults when remoted passes no configuration.
            remoted_module_config_t config {};
            if (configuration)
            {
                config = *configuration;
            }

            RemotedModule::instance().start(
                [callbackLog](const int logLevel,
                              const char* tag,
                              const char* file,
                              const int line,
                              const char* func,
                              const char* logMessage,
                              va_list args)
                {
                    if (callbackLog)
                    {
                        callbackLog(logLevel, tag, file, line, func, logMessage, args);
                    }
                },
                config);
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(LogFn {REMOTED_MODULE_LOGTAG}, "Error starting remoted module: %s", e.what());
        }
    }

    void remoted_module_stop(void)
    {
        try
        {
            RemotedModule::instance().stop();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(LogFn {REMOTED_MODULE_LOGTAG}, "Error stopping remoted module: %s", e.what());
        }
    }

#ifdef __cplusplus
}
#endif
