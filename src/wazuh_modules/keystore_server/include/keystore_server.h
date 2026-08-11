/*
 * Wazuh keystore server module
 * Copyright (C) 2015, Wazuh Inc.
 * August 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _KEYSTORE_SERVER_H
#define _KEYSTORE_SERVER_H

/*
 * C-ABI bridge for the keystore_server C++ module.
 *
 * The `queue/sockets/keystore` UDS used to be hosted by the legacy inventory_sync module -- an
 * accident of history: the keystore has nothing to do with inventory synchronization, and its one
 * production consumer is the Python framework (credential_manager.py fetches the indexer
 * credentials for the manager API). Hosting it in its own minimal module is what let that module
 * retire without taking the API's indexer access down with it.
 *
 * modulesd resolves the two entry points below with dlopen/dlsym (see
 * wazuh_modules/src/wm_keystore_server.c), so the function-pointer typedefs are load-bearing.
 */

// Define EXPORTED for any platform
#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#ifdef __cplusplus
extern "C"
{
#endif

#include "commonDefs.h" // full_log_fnc_t

    /**
     * @brief Start the keystore socket server. Binds and serves immediately; returns non-zero when
     *        the socket cannot be bound (modulesd treats that as fatal: an API that silently lost
     *        its indexer credentials is worse than one that refuses to start).
     *
     * @param callbackLog Logging callback (modulesd passes mtLoggingFunctionsWrapper).
     * @param socketPath  UDS path to bind, RELATIVE to the install dir. NULL -> the production
     *                    default ("queue/sockets/keystore"). Non-NULL exists for tests.
     */
    EXPORTED int keystore_server_start(full_log_fnc_t callbackLog, const char* socketPath);

    /**
     * @brief Stop the module: closes the socket. Idempotent; safe if never started.
     */
    EXPORTED void keystore_server_stop(void);

#ifdef __cplusplus
}
#endif

// Function-pointer typedefs. REQUIRED: modulesd loads this module via dlopen and resolves both
// symbols with dlsym (see wazuh_modules/src/wm_keystore_server.c).
typedef int (*keystore_server_start_func)(full_log_fnc_t callbackLog, const char* socketPath);
typedef void (*keystore_server_stop_func)(void);

#endif // _KEYSTORE_SERVER_H
