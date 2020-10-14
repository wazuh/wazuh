/*
 * Copyright (C) 2015-2020, Wazuh Inc.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <sys/mman.h>
#include <plist/plist.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include "headers/defs.h"
#include "../../common.h"

char * wrap_fgets(char * __s, int __n, FILE * __stream) {
    if (test_mode) {
        check_expected(__stream);
        return mock_type(char*);
    }
    else {
        return fgets(__s, __n, __stream);
    }
}

int wrap_fprintf (FILE *__stream, const char *__format, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;
    int ret;
    va_start(args, __format);

    if (test_mode) {
        vsnprintf(formatted_msg, OS_MAXSTR, __format, args);
        check_expected(__stream);
        check_expected(formatted_msg);
        ret = mock();
    }
    else {
        ret = vfprintf(__stream, __format, args);
    }

    va_end(args);
    return ret;
}

int wrap_snprintf (char * s, size_t n, const char *__format, ...) {
    va_list args;
    int ret;
    va_start(args, __format);

    if (test_mode) {
        vsnprintf(s, n, __format, args);
        check_expected(s);
        ret = mock();
    }
    else {
        ret = snprintf(s, n, __format, args);
    }

    va_end(args);
    return ret;
}

int wrap_fstat (int __fd, struct stat *__buf) {
    if (test_mode) {
        __buf->st_size = mock_type(int);
        return mock_type(int);
    }
    
    return fstat(__fd, __buf);
}

int wrap_fileno (FILE *fp) {
    if (test_mode) {
        return mock_type(int);
    }
    return fileno(fp);
}

int wrap_fclose (FILE *fp) {
    if (test_mode) {
        check_expected(fp);
        return mock_type(int);
    }
    return fclose(fp);
}

int wrap_fwrite(char *src, int n, size_t size, FILE *fp) {
    if (test_mode) {
        check_expected(src);
        return mock();
    }
    return fwrite(src, n, size, fp);
}

int wrap_fseek(FILE *fp, int seek,  int flag) {
    if (test_mode) {
        check_expected(fp);
        return 1;
    }
    return fseek(fp, seek, flag);
}

void * wrap_mmap (void *start, size_t length, int prot, int flags, int fd, off_t offset) {
    if (test_mode) {
        check_expected(fd);
        return mock_type(void*);
    }
    return mmap(start, length, prot, flags, fd, offset);
}

int wrap_munmap (void *mem, size_t size) {
    if (test_mode) {
        check_expected(mem);
        return 1;
    }
    return munmap(mem, size);
}

FILE * wrap_tmpfile () {
    if (test_mode) {
        return mock_type(FILE*);
    }
    return tmpfile();
}

/* TODO: MOVE TO ANOTHER FILE */

void wrap_plist_from_bin (char * bin, size_t size, plist_t *node) {
    if (test_mode) {
        check_expected(bin);
        *node = mock_type(plist_t);
        return;
    }
    
    plist_from_bin(bin, size, node);
}

/* TODO: MOVE TO ANOTHER FILE */

void wrap_plist_to_xml (plist_t *node, char ** xml, uint32_t *size) {
    if (test_mode) {
        check_expected(node);
        *xml = mock_type(char*);
        *size = mock_type(uint32_t);
        return;
    }
    
    plist_to_xml(node, xml, size);
}

/* TODO: MOVE TO ANOTHER FILE */

void wrap_plist_free(plist_t node) {
    if (test_mode) {
        check_expected(node);
        return;
    }
    
    plist_free(node);
}

/* TODO : MOVE TO ANOTHER FILE */

void wrap_mterror(const char *tag, const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}