/* Copyright (C) 2015-2020, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef PRIVSEP_OP_WRAPPERS_H
#define PRIVSEP_OP_WRAPPERS_H

int __wrap_Privsep_GetUser(const char *name);

int __wrap_Privsep_GetGroup(const char *name);

#endif
