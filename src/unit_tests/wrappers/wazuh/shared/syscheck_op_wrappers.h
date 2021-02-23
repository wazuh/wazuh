/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef SYSCHECK_OP_WRAPPERS_H
#define SYSCHECK_OP_WRAPPERS_H

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#endif // WIN32

char *__wrap_decode_win_permissions(char *raw_perm);

int __wrap_delete_target_file(const char *path);

char *__wrap_get_group(int gid);

#ifndef WIN32
char *__wrap_get_user(int uid);
#else
char *__wrap_get_user(const char *path, char **sid);

char *__wrap_get_file_user(const char *path, char **sid);
#endif

unsigned int __wrap_w_directory_exists(const char *path);

unsigned int __wrap_w_get_file_attrs(const char *file_path);

int __wrap_w_get_file_permissions(const char *file_path, char *permissions, int perm_size);

int __wrap_remove_empty_folders(const char *folder);

#ifdef WIN32
/**
 * @brief This function loads the expect and will return of the function get_user
 */
void expect_get_user(const char *path, char **sid, char *user);

/**
 * @brief This function loads the expect and will return of the function get_user
 */
void expect_get_file_user(const char *path, char *sid, char *user);

/**
 * @brief This function loads the expect and will return of the function w_get_file_permissions
 */
void expect_w_get_file_permissions(const char *file_path, char *perms, int ret);

/**
 * @brief Mock calls to get_registry_permissions
 */
DWORD __wrap_get_registry_permissions(HKEY hndl,  char *perm_key);

/**
 * @brief This function loads the expect and will return of the function get_registry_permissions
 */
void expect_get_registry_permissions(const char *permissions, DWORD retval);

#else
/**
 * @brief This function loads the expect and will return of the function get_user
 */
void expect_get_user(int uid, char *ret);
#endif /*WIN32*/

/**
 * @brief This function loads the expect and will return of the function get_group
 */
void expect_get_group(int gid, char *ret);

#endif /*SYSCHECK_OP_WRAPPERS_H*/
