/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef QUEUE_WRAPPERS_H
#define QUEUE_WRAPPERS_H

int __wrap_rem_msgpush(const char * buffer, unsigned long size, struct sockaddr_in * addr, int sock);

#endif
