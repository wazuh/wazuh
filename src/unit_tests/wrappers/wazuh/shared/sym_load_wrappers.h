/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef SYM_LOAD_WRAPPERS_H
#define SYM_LOAD_WRAPPERS_H
#include "sym_load.h"

void* __wrap_so_get_module_handle_on_path(const char *path, const char *so);

void* __wrap_so_get_module_handle(const char *so);

void* __wrap_so_get_function_sym(void *handle, const char *function_name);

int __wrap_so_free_library(void *handle);

#endif
