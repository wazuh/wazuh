/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef OS_REGEX_OP_H
#define OS_REGEX_OP_H

#ifndef WIN32
#include <regex.h>

/* POSIX regex pattern matching */
int OS_PRegex(const char *str, const char *regex);

// Execute a POSIX regex. Return 1 on success or 0 on error.
int w_regexec(const char * pattern, const char * string, size_t nmatch, regmatch_t * pmatch);

#endif
#endif
