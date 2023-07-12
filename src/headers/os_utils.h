/*
 * OS processes
 * Copyright (C) 2015, Wazuh Inc.
 * January 25, 2019
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef OS_UTILS_OP_H
#define OS_UTILS_OP_H

#ifdef WIN32
#include <tlhelp32.h>
#endif
/* Process struct */
typedef struct W_Proc_Info {
    char *p_name;
    char *p_path;
} W_Proc_Info;


char *w_os_get_runps(const char *ps, int mpid);
/* Get list of Unix processes */
OSList *w_os_get_process_list();
/* Check if a file exists */
int w_is_file(const char * const file);
/* Delete the process list */
int w_del_plist(OSList *p_list);

#ifdef WIN32
/* Executes Wow64DisableWow64FsRedirection if the OS version supports it */
void SafeWow64DisableWow64FsRedirection(PVOID *oldValue);
#endif

#endif /* OS_UTILS_OP_H */
