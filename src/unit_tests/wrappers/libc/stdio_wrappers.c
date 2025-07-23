/* Copyright (C) 2015, Wazuh Inc.
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
#include <stdint.h>
#include <cmocka.h>
#include <stdio.h>
#include <string.h>
#include "headers/defs.h"
#include "../common.h"

fpos_t * test_position = NULL;

extern int __real_fclose(FILE *_File);
int __wrap_fclose(FILE *_File) {
    if(test_mode) {
        check_expected(_File);
        return mock();
    } else {
        return __real_fclose(_File);
    }
}
void expect_fclose(FILE *_File, int ret) {
    expect_value(__wrap_fclose, _File, _File);
    will_return(__wrap_fclose, ret);
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
            size_t buff_len = strlen(buffer);
            if (buff_len + 1 < (size_t) __n) {
                strncpy(__s, buffer, buff_len + 1);
            } else {
                strncpy(__s, buffer, __n - 1);
                __s[ __n - 1] = '\0';
            }
            return __s;
        }
        return NULL;
    } else {
        return __real_fgets(__s, __n, __stream);
    }
}

extern int __real_fgetpos(FILE *__restrict __stream, fpos_t * __pos);
int __wrap_fgetpos (FILE *__restrict __stream, fpos_t * __pos) {
    if(test_mode) {
        check_expected(__stream);
        memcpy(__pos, test_position, sizeof(fpos_t));
        return mock();
    } else {
        return __real_fgetpos(__stream, __pos);
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
void expect_fopen(const char* path, const char* mode, FILE *fp) {
    expect_string(__wrap_fopen, path, path);
    expect_string(__wrap_fopen, mode, mode);
    will_return(__wrap_fopen, fp);
}

int __wrap_fprintf(FILE *__stream, const char *__format, ...) {
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

void expect_fprintf(FILE *__stream, const char *formatted_msg, int ret) {
#ifndef WIN32
    expect_value(__wrap_fprintf, __stream, __stream);
    expect_string(__wrap_fprintf, formatted_msg, formatted_msg);
    will_return(__wrap_fprintf, ret);
#else
    expect_value(wrap_fprintf, __stream, __stream);
    expect_string(wrap_fprintf, formatted_msg, formatted_msg);
    will_return(wrap_fprintf, ret);
#endif
}

int __wrap_snprintf(char *__s, size_t __maxlen, const char *__format, ...) {
    if (test_mode) {
        check_expected_ptr(__maxlen);
        check_expected_ptr(__format);
        memset(__s, 0, __maxlen);

        return mock_type(int);
    } else {
        va_list args;
        va_start(args, __format);

        int val = vsnprintf(__s, __maxlen, __format, args);

        va_end(args);

        return val;
    }
}

extern size_t __real_fread(void *ptr, size_t size, size_t n, FILE *stream);
size_t __wrap_fread(void *ptr, size_t size, size_t n, FILE *stream) {
    if (test_mode) {
        strncpy((char *) ptr, mock_type(char *), n);
        size_t ret = mock();
        if (ret > n){
            return n;
        } else {
            return ret;
        }
    }
    return __real_fread(ptr, size, n, stream);
}

void expect_fread(char *file, size_t ret) {
    will_return(__wrap_fread, file);
    will_return(__wrap_fread, ret);
}

long int __wrap_ftell(__attribute__ ((__unused__)) FILE *stream) {
    return mock();
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

void __wrap_clearerr (FILE *__stream) {
    function_called();
    check_expected(__stream);
    return;
}

int __wrap_fileno (FILE *__stream) {
    check_expected(__stream);
    return mock();
}

extern int __real_fgetc(FILE * stream);
int __wrap_fgetc(FILE * stream) {
    if(test_mode) {
        return mock_type(int);
    } else {
        return __real_fgetc(stream);
    }
}

int __wrap__fseeki64(__attribute__ ((__unused__)) FILE *stream, \
                     __attribute__ ((__unused__)) long offset, __attribute__ ((__unused__)) int whence) {
     return mock();
}

extern FILE *__real_popen(const char *command, const char *type);
FILE *__wrap_popen(const char *command, const char *type) {
    if(!test_mode){
        return __real_popen(command, type);
    }
    check_expected(command);
    check_expected(type);
    return mock_ptr_type(FILE*);
}

void expect_popen(const char *command, const char *type, FILE *ret) {
  expect_string(__wrap_popen, command, command);
  expect_string(__wrap_popen, type, type);
  will_return(__wrap_popen, ret);
}

int __wrap_pclose(FILE *stream) {
    check_expected(stream);
    return mock();
}

int __wrap_fputc(char character, FILE *stream) {
    check_expected(character);
    check_expected(stream);
    return mock();
}

FILE *__wrap_open_memstream(char **__bufloc, size_t *__sizeloc) {
    *__bufloc = mock_type(char *);
    *__sizeloc = mock_type(size_t);
    return mock_ptr_type(FILE*);
}

ssize_t __wrap_getline(char ** lineptr, size_t * n, FILE * stream) {
    *lineptr = mock_ptr_type(char *);
    *n = strlen(*lineptr);
    return *n;
}
