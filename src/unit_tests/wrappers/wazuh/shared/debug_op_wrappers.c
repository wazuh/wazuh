/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "debug_op_wrappers.h"
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>
#include <stdio.h>

int __wrap_isChroot() {
    return mock();
}

void __wrap__mdebug1(__attribute__((unused)) const char * file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char * func,
                     const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mdebug2(__attribute__((unused)) const char * file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char * func,
                     const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror(__attribute__((unused)) const char * file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char * func,
                    const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__merror_exit(__attribute__((unused)) const char * file,
                         __attribute__((unused)) int line,
                         __attribute__((unused)) const char * func,
                         const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
    mock_assert(0, "merror_exit called", file, line);
}

void __wrap__mferror(__attribute__((unused)) const char * file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char * func,
                    const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__minfo(__attribute__((unused)) const char * file,
                   __attribute__((unused)) int line,
                   __attribute__((unused)) const char * func,
                   const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug1(const char *tag,
                      __attribute__((unused)) const char * file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char * func,
                      const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtdebug2(const char *tag,
                      __attribute__((unused)) const char * file,
                      __attribute__((unused)) int line,
                      __attribute__((unused)) const char * func,
                      const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror(const char *tag,
                     __attribute__((unused)) const char * file,
                     __attribute__((unused)) int line,
                     __attribute__((unused)) const char * func,
                     const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mterror_exit(const char *tag,
                          __attribute__((unused)) const char * file,
                          __attribute__((unused)) int line,
                          __attribute__((unused)) const char * func,
                          const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtinfo(const char *tag,
                    __attribute__((unused)) const char * file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char * func,
                    const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mtwarn(const char *tag,
                    __attribute__((unused)) const char * file,
                    __attribute__((unused)) int line,
                    __attribute__((unused)) const char * func,
                    const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    check_expected(tag);

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

void __wrap__mwarn(__attribute__((unused)) const char * file,
                   __attribute__((unused)) int line,
                   __attribute__((unused)) const char * func,
                   const char *msg, ...) {
    char formatted_msg[OS_MAXSTR];
    va_list args;

    va_start(args, msg);
    vsnprintf(formatted_msg, OS_MAXSTR, msg, args);
    va_end(args);

    check_expected(formatted_msg);
}

char * __wrap_win_strerror(__attribute__((unused)) unsigned long error) {
    return mock_type(char*);
}

