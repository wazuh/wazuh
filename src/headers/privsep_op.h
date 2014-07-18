/* @(#) $Id: ./src/headers/privsep_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions for privilege separation.
 */

#ifndef __PRIV_H

#define __PRIV_H
#include "shared.h"

int Privsep_GetUser(const char * name) __attribute__((nonnull));

int Privsep_GetGroup(const char * name) __attribute__((nonnull));

int Privsep_SetUser(uid_t uid);

int Privsep_SetGroup(gid_t gid);

int Privsep_Chroot(const char * path) __attribute__((nonnull));

#endif
