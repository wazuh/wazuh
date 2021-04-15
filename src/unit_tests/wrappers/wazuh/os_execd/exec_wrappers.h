/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_EXEC_WRAPPERS_H
#define OS_EXEC_WRAPPERS_H

int __wrap_read_exec_config();

char *__wrap_get_command_by_name(const char *name, int *timeout);

#endif
