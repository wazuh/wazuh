/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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

#endif
