/*   $OSSEC, privsep_op.h, v0.1, 2004/07/30, Daniel B. Cid$   */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
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
#include <sys/types.h>

int Privsep_GetUser(char * name);

int Privsep_GetGroup(char * name);

int Privsep_SetUser(uid_t uid);

int Privsep_SetGroup(gid_t gid);

int Privsep_Chroot(char * path);

#endif
