/* @(#) $Id$ */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 3) as published by the FSF - Free Software
 * Foundation
 */

/* Functions for privilege separation.
 */

#ifndef __PRIV_H

#define __PRIV_H
#include "shared.h"

int Privsep_GetUser(char * name);

int Privsep_GetGroup(char * name);

int Privsep_SetUser(uid_t uid);

int Privsep_SetGroup(gid_t gid);

int Privsep_Chroot(char * path);

#endif
