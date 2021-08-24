/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef NETBUFFER_WRAPPERS_H
#define NETBUFFER_WRAPPERS_H

int __wrap_nb_close(__attribute__((unused)) netbuffer_t * buffer, int sock);

#endif
