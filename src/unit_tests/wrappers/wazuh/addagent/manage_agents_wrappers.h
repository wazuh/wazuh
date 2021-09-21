/* Copyright (C) 2015-2021, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef MANAGE_AGENTS_WRAPPERS_H
#define MANAGE_AGENTS_WRAPPERS_H

#include <time.h>

double __wrap_get_time_since_agent_disconnection(const char *id);
void __wrap_OS_RemoveAgentGroup(const char *id);
time_t __wrap_get_time_since_agent_registration(int id);

#endif
