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

/* Configuration structure */
typedef struct __Config {
    /* Agent's disconnection global parameters */
    long agents_disconnection_time;
    long agents_disconnection_alert_time;
} _Config;

#endif /* CCONFIG_H */
