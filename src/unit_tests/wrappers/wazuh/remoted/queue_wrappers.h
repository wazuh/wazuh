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

#ifndef QUEUE_WRAPPERS_H
#define QUEUE_WRAPPERS_H

#include <stddef.h>

size_t __wrap_rem_get_qsize();
size_t __wrap_rem_get_tsize();

#endif /* QUEUE_WRAPPERS_H */
