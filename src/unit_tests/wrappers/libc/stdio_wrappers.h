/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef STDIO_WRAPPERS_H
#define STDIO_WRAPPERS_H

#include <stdio.h>

int __wrap_fclose(FILE *_File);

int __wrap_fflush(FILE *__stream);

char * __wrap_fgets (char * __s, int __n, FILE * __stream);

FILE* __wrap_fopen(const char* path, const char* mode);

int __wrap_fprintf (FILE *__stream, const char *__format, ...);

size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream);

int __wrap_fseek(FILE *stream, long offset, int whence);

size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int __wrap_remove(const char *filename);

int __wrap_rename(const char *__old, const char *__new);

#endif
