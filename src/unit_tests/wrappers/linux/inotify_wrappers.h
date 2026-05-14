/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef INOTIFY_WRAPPERS_H
#define INOTIFY_WRAPPERS_H

#include <stdint.h>

int __wrap_inotify_add_watch(int fd,
                             const char *pathname,
                             uint32_t mask);

int __wrap_inotify_init();

int __wrap_inotify_rm_watch();

#endif
