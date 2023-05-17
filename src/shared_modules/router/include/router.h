/*
 * Wazuh router
 * Copyright (C) 2015, Wazuh Inc.
 * March 25, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _ROUTER_H
#define _ROUTER_H

// Define EXPORTED for any platform

#if __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include "logging_helper.h"

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief Log callback function.
     *
     * @param level Log level.
     * @param log Log message.
     * @param tag Log tag.
     */
    typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

    /**
     * @brief Start router mechanism.
     *
     * @param callbackLog Log callback function.
     */
    EXPORTED void router_start(log_callback_t callbackLog);

    /**
     * @brief Stop router mechanism.
     *
     */
    EXPORTED void router_stop();

#ifdef __cplusplus
}
#endif

typedef void (*router_start_func)(log_callback_t callbackLog);

typedef void (*router_stop_func)();

#endif // _ROUTER_H
