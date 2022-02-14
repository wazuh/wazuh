/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "pwd_wrappers.h"

#ifndef WIN32
#include <stddef.h>
#include <stdarg.h>
#include <setjmp.h>
#include <cmocka.h>
#include <errno.h>
#include <string.h>


int __wrap_getpwnam_r(const char *name,
                      struct passwd *pwd,
                      __attribute__((unused))  char *buf,
                      size_t buflen,
                      struct passwd **result) {
    *result = NULL;

    if (buflen < 1024) {
        return ERANGE;
    }

    if (strcmp(name, "wazuh") == 0) {
        pwd->pw_uid = 1000;
        *result = pwd;
    }

    return 0;
}
// Test solaris version of this wrapper.
#ifdef SOLARIS
struct passwd **__wrap_getpwuid_r(__attribute__((unused)) uid_t uid,
                                  struct passwd *pwd,
                                  __attribute__((unused)) char *buf,
                                  __attribute__((unused)) size_t buflen) {
        pwd->pw_name = mock_type(char*);
        return mock_type(struct passwd*);
}
#else
int __wrap_getpwuid_r(__attribute__((unused)) uid_t uid,
                      struct passwd *pwd,
                      __attribute__((unused)) char *buf,
                      __attribute__((unused)) size_t buflen,
                      struct passwd **result) {
    pwd->pw_name = mock_type(char*);
    *result = mock_type(struct passwd*);
    return mock();
}
#endif
#endif
