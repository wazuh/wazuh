/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef REMOTED_MODULE_WRAPPERS_H
#define REMOTED_MODULE_WRAPPERS_H

// Forward declarations to avoid including remoted_module.h
typedef void (*logging_callback_t)(int level, const char* message);
typedef struct remoted_module_config_t remoted_module_config_t;

void __wrap_remoted_module_start(const logging_callback_t logCb, const remoted_module_config_t* config);

void __wrap_remoted_module_stop(void);

#endif
