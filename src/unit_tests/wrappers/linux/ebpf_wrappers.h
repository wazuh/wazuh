/* Copyright (C) 2025, Wazuh Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef WRAP_EBPF_FUNCTIONS_H
#define WRAP_EBPF_FUNCTIONS_H

#include <stddef.h>

// Forward declaration of syscheck_config if it is a struct type
typedef struct _config syscheck_config;

// Define FunctionPtr as a pointer to a function that returns void and takes no arguments
typedef void (*FunctionPtr)();

// Declare the wrap functions
int __wrap_ebpf_whodata_healthcheck(void);

// Declare the wrap version of fimebpf_initialize
void __wrap_fimebpf_initialize(const char* config_dir,
                                FunctionPtr get_user,
                                FunctionPtr get_group,
                                FunctionPtr whodata_event,
                                FunctionPtr free_whodata_event,
                                FunctionPtr loggingFunction,
                                FunctionPtr abspath,
                                FunctionPtr is_shutdown,
                                syscheck_config syscheck);

#endif // WRAP_EBPF_FUNCTIONS_H
