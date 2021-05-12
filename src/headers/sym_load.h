/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef H_SYMLOAD_OS
#define H_SYMLOAD_OS

#ifndef WIN32
#include <dlfcn.h>
#else
#include <windows.h>
#endif

void* so_get_module_handle_on_path(const char *path, const char *so);
void* so_get_module_handle(const char *so);
void* so_get_function_sym(void *handle, const char *function_name);
int so_free_library(void *handle);

#endif //H_SYMLOAD_OS