/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef _AGENTLESSD_H
#define _AGENTLESSD_H

#include "config/agentlessd-config.h"

#ifndef ARGV0
#define ARGV0 "ossec-agentlessd"
#endif

/** Prototypes **/

/* Main monitord */
void Agentlessd(void) __attribute__((noreturn));

/* Global variables */
extern agentlessd_config lessdc;

#endif

