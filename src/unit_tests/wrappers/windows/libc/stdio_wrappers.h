/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STDIO_WRAPPERS_WINDOWS_H
#define STDIO_WRAPPERS_WINDOWS_H

#include <stdio.h>

char * wrap_fgets(char * __s, int __n, FILE * __stream);

int wrap_fprintf(FILE *__stream, const char *__format, ...);

#define fprintf wrap_fprintf
#define fgets wrap_fgets

#endif
