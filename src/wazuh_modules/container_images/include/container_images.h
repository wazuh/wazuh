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
                                    const char** localPaths,
                                    const unsigned int localPathsCount);

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
                                           const char** localPaths,
                                           const unsigned int localPathsCount);
typedef void (*container_images_start_func)();
typedef void (*container_images_stop_func)();
typedef void (*container_images_release_resources_func)();

#endif // _CONTAINER_IMAGES_H
