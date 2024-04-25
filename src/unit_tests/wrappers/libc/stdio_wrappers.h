/* Copyright (C) 2015, Wazuh Inc.
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

extern fpos_t * test_position;

int __wrap_fclose(FILE *_File);
void expect_fclose(FILE *_File, int ret);

int __wrap_fflush(FILE *__stream);

char * __wrap_fgets (char * __s, int __n, FILE * __stream);

FILE* __wrap_fopen(const char* path, const char* mode);
void expect_fopen(const char* path, const char* mode, FILE *fp);

int __wrap_fprintf (FILE *__stream, const char *__format, ...);
void expect_fprintf(FILE *__stream, const char *formatted_msg, int ret);

int __wrap_snprintf(char *__s, size_t __maxlen, const char *__format, ...);

size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream);
void expect_fread(char *file, int ret);

long int __wrap_ftell(FILE *__stream);

int __wrap_fseek(FILE *stream, long offset, int whence);

size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);

int __wrap_remove(const char *filename);

int __wrap_rename(const char *__old, const char *__new);

size_t __wrap_strlen(const char *s);

int __wrap_fgetpos (FILE *__restrict __stream, fpos_t * __pos);

void __wrap_clearerr (FILE *__stream);

int __wrap_fileno (FILE *__stream);

int __wrap_fgetc(FILE * stream);

int __wrap__fseeki64(FILE *stream, long offset, int whence);

FILE *__wrap_popen(const char *command, const char *type);
void expect_popen(const char *command, const char *type, FILE *ret);

int __wrap_pclose(FILE *stream);

int __wrap_fputc(char character, FILE *stream);

FILE *__wrap_open_memstream(char **__bufloc, size_t *__sizeloc);

ssize_t __wrap_getline(char ** lineptr, size_t * n, FILE * stream);

#endif
