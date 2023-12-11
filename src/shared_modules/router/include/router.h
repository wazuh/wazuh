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
     * @brief Initialize router mechanism.
     *
     * @param callbackLog Log callback function.
     */
    EXPORTED int router_initialize(log_callback_t callbackLog);

    /**
     * @brief Start router mechanism.
     *
     */
    EXPORTED int router_start();

    /**
     * @brief Stop router mechanism.
     *
     */
    EXPORTED int router_stop();

    /**
     * @brief Send a message to the router provider.
     *
     * @param provider_name Name of the router provider.
     * @param message Message to send.
     * @param message_size Size of the message.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send(const char* provider_name, const char* message, unsigned int message_size);

    /**
     * @brief Destroy a router provider.
     *
     * @param provider_name Name of the router provider.
     */
    EXPORTED void router_provider_destroy(const char* provider_name);

#ifdef __cplusplus
}
#endif

typedef int (*router_initialize_func)(log_callback_t callbackLog);

typedef int (*router_start_func)();

typedef int (*router_stop_func)();

typedef bool (*router_provider_send_func)(char* provider_name,
                                          const char* message,
                                          unsigned int message_size);

typedef void (*router_provider_destroy_func)(char* provider_name);

#endif // _ROUTER_H
