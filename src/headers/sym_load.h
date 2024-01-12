/* Copyright (C) 2015, Wazuh Inc.
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
#include <winsock2.h>
#include <windows.h>
#endif

void* so_get_module_handle_on_path(const char *path, const char *so);
void* so_get_module_handle(const char *so);
/**
 * @brief Check if a module/library is already loaded. Must call a corresponding so_free_library()
 * if not used in WIN32. If RTLD_NOLOAD isn't found in the system,
 * the behavior is the same than so_get_module_handle().
 *
 * @param so The name of the module/library to check.
 * @return void* A handle to module if it is already loaded, NULL otherwise.
 */
void* so_check_module_loaded(const char *so);
void* so_get_function_sym(void *handle, const char *function_name);
int so_free_library(void *handle);

#endif //H_SYMLOAD_OS
