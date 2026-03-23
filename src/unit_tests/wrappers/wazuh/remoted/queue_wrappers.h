/*
 * Wazuh Shared Configuration Manager
 * Copyright (C) 2015, Wazuh Inc.
 * May 17, 2022.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef REM_QUEUE_WRAPPERS_H
#define REM_QUEUE_WRAPPERS_H

#include <stddef.h>

size_t __wrap_rem_get_qsize();
size_t __wrap_rem_get_tsize();

int __wrap_rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_storage * addr, int sock);

#endif /* REM_QUEUE_WRAPPERS_H */
