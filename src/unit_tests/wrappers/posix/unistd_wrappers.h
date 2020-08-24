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
#include <errno.h>

#ifndef WIN32
int __wrap_unlink(const char *file);
#else
int __wrap__unlink(const char *file);
#endif

int __wrap_close(int fd);

extern int __real_getpid();
int __wrap_getpid();

#ifndef WIN32
void __wrap_sleep(unsigned int seconds);
#endif

int __wrap_sysconf(int name);

int __wrap_usleep(useconds_t usec);

ssize_t __wrap_read(int fildes, void *buf, size_t nbyte);

int __wrap_gethostname(char *name, int len);

int __wrap_readlink(void **state);

int __wrap_symlink(const char *path1, const char *path2);

#endif
