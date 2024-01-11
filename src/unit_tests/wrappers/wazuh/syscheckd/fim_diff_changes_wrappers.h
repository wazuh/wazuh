/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DIFF_CHANGES_WRAPPERS_H
#define DIFF_CHANGES_WRAPPERS_H

#ifdef WIN32
#include <winsock2.h>
#include <windows.h>
#include "../../../../config/syscheck-config.h"
#endif


char *__wrap_fim_file_diff(const char *filename);

int __wrap_fim_diff_process_delete_file(const char *file_name);

/**
 * @brief This function loads the expect and will return of the function fim_file_diff
 */
void expect_fim_file_diff(const char *filename, char *ret);

/**
 * @brief This function loads the expect and will return of the function fim_diff_process_delete_file
 */
void expect_fim_diff_process_delete_file(const char *filename, int ret);

#ifdef WIN32
char *__wrap_fim_registry_value_diff(const char *key_name,
                                     const char *value_name,
                                     const char *value_data,
                                     DWORD data_type,
                                     const registry_t *configuration);

/**
 * @brief This function loads the expect and will return of the function fim_registry_value_diff
 */
void expect_fim_registry_value_diff(const char *key_name,
                                    const char *value_name,
                                    const char *value_data,
                                    DWORD data_size,
                                    DWORD data_type,
                                    char *ret);
#endif
#endif /* DIFF_CHANGES_WRAPPERS_H */
