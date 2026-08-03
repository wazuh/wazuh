/*
 * Wazuh inventory sync server module
 * Copyright (C) 2015, Wazuh Inc.
 * July 28, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "inventorySyncServer.hpp"
#include "cjsonSmartDeleter.hpp"
#include "inventorySyncServerFacade.hpp"

namespace Log
{
    // Single definition of the DSO-global log sink used by loggerHelper.h. It has hidden
    // visibility, so every .so needs its own -- this one is not shared with (and cannot be
    // interposed by) libinventory_sync.so's copy, which is the point.
    std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>
        GLOBAL_LOG_FUNCTION;
} // namespace Log

bool InventorySyncServer::start(
    const std::function<void(const int, const char*, const char*, const int, const char*, const char*, va_list)>&
        logFunction,
    const inventory_sync_server_config_t& configuration,
    nlohmann::json indexerConfig) const
{
    return invsync::InventorySyncServerFacade::instance().start(logFunction, configuration, std::move(indexerConfig));
}

void InventorySyncServer::stop() const
{
    invsync::InventorySyncServerFacade::instance().stop();
}

#ifdef __cplusplus
extern "C"
{
#endif

    int inventory_sync_server_start(full_log_fnc_t callbackLog, const inventory_sync_server_config_t* configuration)
    {
        try
        {
            // Defaults when modulesd passes no configuration.
            inventory_sync_server_config_t config {};
            if (configuration)
            {
                config = *configuration;
            }

            // Convert the borrowed <indexer> subtree into an owned nlohmann::json HERE, at the
            // boundary. inventory_sync_server.h promises the pointer is borrowed for the duration
            // of this call only, so the copy has to happen before we return -- and doing it here
            // keeps cJSON out of the facade entirely.
            nlohmann::json indexerConfig = nlohmann::json::object();
            if (config.indexer != nullptr)
            {
                const std::unique_ptr<char, CJsonSmartFree> printed {cJSON_Print(config.indexer)};
                if (printed)
                {
                    indexerConfig = nlohmann::json::parse(printed.get());
                }
            }

            // Defensive: the copy above is the only reader of this pointer. Clearing it means a
            // later change that starts passing `config` further down cannot accidentally
            // dereference a pointer the caller has already freed.
            config.indexer = nullptr;

            const bool started = InventorySyncServer::instance().start(
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
                config,
                std::move(indexerConfig));

            return started ? 0 : 1;
        }
        catch (const std::exception& e)
        {
            // moduleLogFn() is a pre-built static: constructing a LogFn here would allocate inside
            // an exception handler at the C boundary, where a second throw is std::terminate.
            LOGFN_ERROR(invsync::moduleLogFn(), "Error starting inventory sync server: %s", e.what());
        }
        // LCOV_EXCL_START
        catch (...)
        {
            // inventory_sync_server.h promises this never throws into C. A non-std::exception
            // escaping here would cross the extern "C" boundary into modulesd's C code, where
            // there is no handler -- std::terminate, taking the whole daemon down.
            //
            // Excluded from coverage rather than tested: nothing in this module or the libraries it
            // calls throws a non-std type, so there is no way to reach it without adding a throw for
            // the test's benefit. It stays because the guarantee has to hold if that ever changes.
            LOGFN_ERROR(invsync::moduleLogFn(), "Error starting inventory sync server: non-standard exception.");
        }
        // LCOV_EXCL_STOP

        /*
         * An exception escaping start() IS fatal: the facade never launched its worker, so there is
         * no retry loop and the module would stay absent for the daemon's whole life while modulesd
         * looked healthy. Reporting non-zero makes the shim refuse to run without inventory ingress,
         * the same answer an unbindable socket gets.
         */
        return 1;
    }

    void inventory_sync_server_stop(void)
    {
        try
        {
            InventorySyncServer::instance().stop();
        }
        catch (const std::exception& e)
        {
            LOGFN_ERROR(invsync::moduleLogFn(), "Error stopping inventory sync server: %s", e.what());
        }
        // LCOV_EXCL_START
        catch (...)
        {
            // Same reasoning as inventory_sync_server_start(): nothing may cross back into C.
            // This one runs from modulesd's signal handler (wazuh_modules/src/main.c), where a
            // terminate would turn a clean shutdown into a crash. Unreachable for the same reason,
            // and excluded for the same reason.
            LOGFN_ERROR(invsync::moduleLogFn(), "Error stopping inventory sync server: non-standard exception.");
        }
        // LCOV_EXCL_STOP
    }

#ifdef __cplusplus
}
#endif
