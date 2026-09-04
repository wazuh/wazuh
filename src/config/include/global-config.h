/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef CCONFIG_H
#define CCONFIG_H

#include "shared.h"

/* Configuration structure.
 *
 * One member, and <global> accepts exactly one element to match. Read by remoted, which compares an
 * agent's keepalive staleness against it, and by the Task Manager's disconnection sweep, which uses
 * it as both the staleness threshold and its own interval -- so it is shared configuration rather
 * than either module's own.
 */
typedef struct __Config {
    long agents_disconnection_time;
} _Config;

#endif /* CCONFIG_H */
