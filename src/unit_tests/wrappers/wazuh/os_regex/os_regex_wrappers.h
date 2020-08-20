/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_REGEX_WRAPPERS_H
#define OS_REGEX_WRAPPERS_H

#include "os_regex/os_regex.h"

int __wrap_OSRegex_Compile(const char *pattern, OSRegex *reg, int flags);

const char *__wrap_OSRegex_Execute(const char *str, OSRegex *reg);

int __wrap_OS_StrIsNum(const char *str);

#endif
