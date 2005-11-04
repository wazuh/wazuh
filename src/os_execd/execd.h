/*   $OSSEC, execd.h, v0.2, 2005/11/01, Daniel B. Cid$   */

/* Copyright (C) 2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */


#ifndef _EXECD_H

/* Maximum number of active responses active */
#define MAX_AR      64

/* Maximum number of command arguments */
#define MAX_ARGS    32


/* Function prototypes */
int ReadExecConfig();
char *GetCommandbyName(char *name);
void ExecCmd(char **cmd);


#define _EXECD_H



#endif
