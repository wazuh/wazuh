/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef STDIO_WRAPPERS_MACOS_H
#define STDIO_WRAPPERS_MACOS_H

#undef fprintf
#define fprintf wrap_fprintf
#undef snprintf
#define snprintf wrap_snprintf

int wrap_fprintf(FILE *__stream, const char *__format, ...);
int wrap_snprintf(char * s, size_t n, const char *__format, ...);

#endif