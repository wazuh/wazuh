/*
 * Wazuh Module for Container Images
 * Copyright (C) 2015, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _CONTAINER_IMAGES_H
#define _CONTAINER_IMAGES_H

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#include "logging_helper.h"

typedef void((*log_callback_t)(const modules_log_level_t level, const char* log, const char* tag));

EXPORTED void container_images_set_log_function(log_callback_t callback);

EXPORTED void container_images_init(const unsigned int interval,
                                    const bool scanOnStart,
                                    const bool enabled,
                                    const char** referenceTypes,
                                    const char** referenceValues,
                                    const unsigned int referencesCount);

/// Registry options, set before container_images_start() and only when a registry
/// reference is configured. Kept apart from container_images_init() so the existing
/// initialization contract does not change for a module that configures no registry.
EXPORTED void container_images_set_registry_options(const char** registryHosts,
                                                    const char** registryUserKeys,
                                                    const char** registryPasskeyKeys,
                                                    const unsigned int registryAuthCount,
                                                    const char* caBundle);

EXPORTED void container_images_start();

EXPORTED void container_images_stop();

EXPORTED void container_images_release_resources();

#ifdef __cplusplus
}
#endif

typedef void (*container_images_set_log_function_func)(log_callback_t callback);
typedef void (*container_images_init_func)(const unsigned int interval,
                                           const bool scanOnStart,
                                           const bool enabled,
                                           const char** referenceTypes,
                                           const char** referenceValues,
                                           const unsigned int referencesCount);
typedef void (*container_images_set_registry_options_func)(const char** registryHosts,
                                                           const char** registryUserKeys,
                                                           const char** registryPasskeyKeys,
                                                           const unsigned int registryAuthCount,
                                                           const char* caBundle);
typedef void (*container_images_start_func)();
typedef void (*container_images_stop_func)();
typedef void (*container_images_release_resources_func)();

#endif // _CONTAINER_IMAGES_H
