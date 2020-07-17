/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef OS_NET_WRAPPERS_H
#define OS_NET_WRAPPERS_H

#include <stdint.h>
#include <string.h>

int __wrap_OS_ConnectUnixDomain(const char *path, int type, int max_msg_size);

int __wrap_OS_SendSecureTCP(int sock, uint32_t size, const void * msg);

int __wrap_OS_RecvSecureTCP(int sock, char * ret, uint32_t size);

#endif
