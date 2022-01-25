/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PWD_WRAPPERS_H
#define PWD_WRAPPERS_H

#ifndef WIN32
#include <stddef.h>
#include <pwd.h>

int __wrap_getpwnam_r(const char *name,
                      struct passwd *pwd,
                      char *buf,
                      size_t buflen,
                      struct passwd **result);

#ifdef SOLARIS
struct passwd **__wrap_getpwuid_r(uid_t uid,
                                  struct passwd *pwd,
                                  char *buf,
                                  size_t buflen);
#else
int __wrap_getpwuid_r(uid_t uid,
                      struct passwd *pwd,
                      char *buf,
                      size_t buflen,
                      struct passwd **result);
#endif

#endif
#endif
