/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STDLIB_WRAPPERS_H
#define STDLIB_WRAPPERS_H

int __wrap_atexit(void (*callback)(void));

char *__wrap_realpath(const char *path, char *resolved_path);

int __wrap_system(const char *__command);
void expect_system(int ret);

int __wrap_mkstemp(char *template);

#endif
