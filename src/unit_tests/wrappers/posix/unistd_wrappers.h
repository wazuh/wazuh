/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef UNISTD_WRAPPERS_H
#define UNISTD_WRAPPERS_H

#include <unistd.h>

int __wrap_unlink(const char *file);

int __wrap__unlink(const char *file);

int __wrap_close();

extern int __real_getpid();
int __wrap_getpid();

#ifndef WIN32
void __wrap_sleep(unsigned int seconds);
#endif

int __wrap_sysconf(int name);

int __wrap_usleep(useconds_t usec);

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

#endif
