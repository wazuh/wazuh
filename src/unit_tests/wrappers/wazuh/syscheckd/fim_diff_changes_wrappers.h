/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef DIFF_CHANGES_WRAPPERS_H
#define DIFF_CHANGES_WRAPPERS_H

char *__wrap_fim_file_diff(const char *filename);

char *__wrap_fim_diff_process_delete_file(const char *file_name);

/**
 * @brief This function loads the expect and will return of the function fim_file_diff
 */
void expect_fim_file_diff(const char *filename, char *ret);

/**
 * @brief This function loads the expect and will return of the function fim_file_diff
 */
void expect_fim_diff_process_delete_file(const char *filename, char *ret);

#endif /* DIFF_CHANGES_WRAPPERS_H */
