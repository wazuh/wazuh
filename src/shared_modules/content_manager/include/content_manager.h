/*
 * Wazuh content manager.
 * Copyright (C) 2015, Wazuh Inc.
 * May 1, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTENT_MANAGER_H
#define _CONTENT_MANAGER_H

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

#include "common/commonDefs.h"

    EXPORTED void content_manager_start(full_log_fnc_t callbackLog);

    EXPORTED void content_manager_stop();

#ifdef __cplusplus
}
#endif

typedef void (*content_manager_start_func)(full_log_fnc_t callbackLog);

typedef void (*content_manager_stop_func)();

#endif // _CONTENT_MANAGER_H
