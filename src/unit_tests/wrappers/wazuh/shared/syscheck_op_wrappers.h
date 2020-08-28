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

char *__wrap_decode_win_permissions(char *raw_perm);

int __wrap_delete_target_file(const char *path);

const char *__wrap_get_group(int gid);

#ifndef WIN32
char *__wrap_get_user(int uid);
#else
char *__wrap_get_user(const char *path, char **sid);
#endif

unsigned int __wrap_w_directory_exists(const char *path);

unsigned int __wrap_w_get_file_attrs(const char *file_path);

int __wrap_w_get_file_permissions(const char *file_path, char *permissions, int perm_size);

#endif
