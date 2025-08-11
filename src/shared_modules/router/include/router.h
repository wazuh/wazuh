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
#include <stddef.h>

/**
 * @brief Agent context structure containing agent information.
 *
 * This structure holds the essential information about an agent that can be
 * used for routing messages and identifying the source of communications.
 */
struct agent_ctx
{
    /** @brief Unique identifier for the agent */
    const char* id;

    /** @brief Human-readable name of the agent */
    const char* name;

    /** @brief IP address of the agent */
    const char* ip;

    /** @brief Version string of the agent software */
    const char* version;

    /** @brief Module of the agent */
    const char* module;
};

#ifdef __cplusplus
extern "C"
{
#endif
    /**
     * @brief Represents the handle associated with router manipulation.
     */
    typedef void* ROUTER_PROVIDER_HANDLE;

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
     * @brief Create a router provider.
     *
     * @param name Name of the router provider.
     * @param isLocal True if the router provider is local, false otherwise.
     * @return ROUTER_PROVIDER_HANDLE Handle to the router provider.
     */
    EXPORTED ROUTER_PROVIDER_HANDLE router_provider_create(const char* name, bool isLocal);

    /**
     * @brief Send a message to the router provider.
     *
     * @param handle Handle to the router provider.
     * @param message Message to send.
     * @param message_size Size of the message.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send(ROUTER_PROVIDER_HANDLE handle, const char* message, unsigned int message_size);

    /**
     * @brief Send a message to the router provider using flatbuffers.
     *
     * @param handle Handle to the router provider.
     * @param message Message to send.
     * @param schema Schema of the message.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send_fb(ROUTER_PROVIDER_HANDLE handle, const char* message, const char* schema);

    /**
     * @brief Send a message to the router provider using flatbuffers and agent context.
     *
     * @param handle Handle to the router provider.
     * @param message Message to send.
     * @param message_size Size of the message.
     * @param agent_ctx Agent context.
     * @return true if the message was sent successfully.
     * @return false if the message was not sent successfully.
     */
    EXPORTED int router_provider_send_fb_agent_ctx(ROUTER_PROVIDER_HANDLE handle,
                                                   const char* message,
                                                   const size_t message_size,
                                                   const struct agent_ctx* agent_ctx);

    /**
     * @brief Destroy a router provider.
     *
     * @param handle Handle to the router provider.
     */
    EXPORTED void router_provider_destroy(ROUTER_PROVIDER_HANDLE handle);

    EXPORTED void router_register_api_endpoint(const char* module,
                                               const char* socketPath,
                                               const char* method,
                                               const char* endpoint,
                                               void* callbackPre,
                                               void* callbackPost);

    EXPORTED void router_start_api(const char* socket_path);

    EXPORTED void router_stop_api(const char* socket_path);

#ifdef __cplusplus
}
#endif

typedef int (*router_initialize_func)(log_callback_t callbackLog);

typedef int (*router_start_func)();

typedef int (*router_stop_func)();

typedef ROUTER_PROVIDER_HANDLE (*router_provider_create_func)(const char* name, bool isLocal);

typedef bool (*router_provider_send_func)(ROUTER_PROVIDER_HANDLE handle,
                                          const char* message,
                                          unsigned int message_size);
typedef bool (*router_provider_send_fb_func)(ROUTER_PROVIDER_HANDLE handle, const char* message, const char* schema);

typedef bool (*router_provider_send_fb_agent_ctx_func)(ROUTER_PROVIDER_HANDLE handle,
                                                       const char* message,
                                                       const size_t message_size,
                                                       const struct agent_ctx* agent_ctx);

typedef void (*router_provider_destroy_func)(ROUTER_PROVIDER_HANDLE handle);

typedef void (*router_register_api_endpoint_func)(const char* module,
                                                  const char* socketPath,
                                                  const char* method,
                                                  const char* endpoint,
                                                  void* callbackPre,
                                                  void* callbackPost);

typedef void (*router_start_api_func)(const char* socket_path);

typedef void (*router_stop_api_func)(const char* socket_path);

#endif // _ROUTER_H
