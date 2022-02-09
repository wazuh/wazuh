/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STRING_WRAPPERS_H
#define STRING_WRAPPERS_H

#include <string.h>

char *__wrap_strerror (int __errnum);

size_t __wrap_strlen(const char *s);
#endif
