/* Copyright (C) 2015, Wazuh Inc.
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

#undef _unlink
#define _unlink wrap__unlink

int __wrap_unlink(const char *file);
#ifdef WIN32
int wrap__unlink(const char *file);
#endif

#ifndef WIN32
int __wrap_close(int fd) __attribute__((weak));
#else
int __wrap_close(int fd);
#endif

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

int __wrap_access (const char *__name, int __type);
#ifdef WIN32
int __wrap__access (const char *__name, int __type);
#endif

#endif
