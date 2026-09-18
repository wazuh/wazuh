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

int RemotedModule::tlsCaMatchesLeaf() const
{
    return RemotedModuleFacade::instance().tlsCaMatchesLeaf();
}

int RemotedModule::tlsCaLeafSignerPem(char* buffer, std::size_t capacity) const
{
    return RemotedModuleFacade::instance().tlsCaLeafSignerPem(buffer, capacity);
}

#ifdef __cplusplus
extern "C"
{
#endif

    // Not wrapped in try/catch: a start failure (e.g. missing TLS certificate/key)
    // must propagate out of this C-ABI boundary, not be swallowed into a retry.
    // remoted must not start without the HTTPS transport up.
    void remoted_module_start(full_log_fnc_t callbackLog, const remoted_module_config_t* configuration)
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
        catch (...)
        {
            // Same reasoning as remoted_module_start(): nothing may cross back into C. This one
            // also runs from atexit() (see secure.c), where a terminate would turn a clean
            // shutdown into a crash.
            LOGFN_ERROR(LogFn {REMOTED_MODULE_LOGTAG}, "Error stopping remoted module: non-standard exception.");
        }
    }

    int remoted_module_tls_ca_matches_leaf(void)
    {
        try
        {
            return RemotedModule::instance().tlsCaMatchesLeaf();
        }
        catch (...)
        {
            // Nothing may cross back into C. "Unknown" is also the right answer for a failure to
            // determine the answer, and the one caller treats it as "proceed" -- see the ABI doc
            // comment. Silent on purpose: this is polled per upgrade, and a throwing accessor
            // would otherwise log once per agent per poll cycle.
            return -1;
        }
    }

    int remoted_module_tls_leaf_signer_pem(char* buffer, size_t capacity)
    {
        try
        {
            return RemotedModule::instance().tlsCaLeafSignerPem(buffer, capacity);
        }
        catch (...)
        {
            // Same discipline as remoted_module_tls_ca_matches_leaf(): nothing may cross back into
            // C, and silent on purpose -- this is polled once per legacy upgrade, and a throwing
            // accessor would log once per agent per poll cycle. -1 rather than 0 because a failure
            // to produce the certificate is not the same finding as "no certificate signs the
            // leaf"; the caller refuses to deliver on either.
            return -1;
        }
    }

#ifdef __cplusplus
}
#endif
