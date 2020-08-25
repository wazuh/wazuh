/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "headers/defs.h"
#include "../common.h"


extern int __real_fclose(FILE *_File);
int __wrap_fclose(FILE *_File) {
    if(test_mode) {
        check_expected(_File);
        return mock();
    } else {
        return __real_fclose(_File);
    }
}

extern int __real_fflush(FILE *__stream);
int __wrap_fflush(FILE *__stream) {
    if (test_mode) {
        return 0;
    }
    return __real_fflush(__stream);
}

extern char * __real_fgets (char * __s, int __n, FILE * __stream);
char * __wrap_fgets (char * __s, int __n, FILE * __stream) {
    if (test_mode) {
        char *buffer = mock_type(char*);
        check_expected(__stream);
        if(buffer) {
            strncpy(__s, buffer, __n);
            return __s;
        }
        return NULL;
    } else {
        return __real_fgets(__s, __n, __stream);
    }
}

extern FILE* __real_fopen(const char* path, const char* mode);
FILE* __wrap_fopen(const char* path, const char* mode) {
    if(test_mode) {
        check_expected_ptr(path);
        check_expected(mode);
        return mock_ptr_type(FILE*);
    } else {
        return __real_fopen(path, mode);
    }
}

int __wrap_fprintf (FILE *__stream, const char *__format, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;
    int ret;

    va_start(args, __format);
    if (test_mode) {
        vsnprintf(formatted_msg, OS_MAXSTR, __format, args);

        check_expected(__stream);
        check_expected(formatted_msg);

        ret = mock();
    } else {
        ret = vfprintf(__stream, __format, args);
    }
    va_end(args);

    return ret;
}

extern size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (test_mode) {
        strncpy((char *) ptr, mock_type(char *), n);
        return mock();
    }
    return __real_fread(ptr, size, n, stream);
}

extern int __real_fseek(FILE *stream, long offset, int whence);
int __wrap_fseek(FILE *stream, long offset, int whence) {
    if (test_mode) {
        return mock();
    }
    return __real_fseek(stream, offset, whence);
}

extern size_t __real_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream);
size_t __wrap_fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream) {
    if (test_mode) {
        return mock_type(size_t);
    }
    return __real_fwrite(ptr, size, nmemb, stream);
}

extern int __real_remove(const char *filename);
int __wrap_remove(const char *filename) {
    if(test_mode){
        check_expected(filename);
        return mock();
    }
    return __real_remove(filename);
}

int __wrap_rename(const char *__old, const char *__new) {
    check_expected(__old);
    check_expected(__new);
    return mock();
}
