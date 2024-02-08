/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef WM_EXEC_WRAPPERS_H
#define WM_EXEC_WRAPPERS_H

int __wrap_wm_exec(char *command, char **output, int *exitcode, int secs, const char * add_path);
void expect_wm_exec(char *command, int sec, const char * add_path, char *output_command, int exitcode, int return_code);

#endif
