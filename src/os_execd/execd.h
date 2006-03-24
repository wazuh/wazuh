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

#ifndef ARGV0
#define ARGV0 "ossec-execd"
#endif


/* Add/delete arguments for the commands */
#define ADD_ENTRY       "add"
#define DELETE_ENTRY    "delete"


/* Maximum number of active responses active */
#define MAX_AR      64


/* Maximum number of command arguments */
#define MAX_ARGS    16 


/* Execd select timeout -- in seconds */
#define EXECD_TIMEOUT   90



/* Function prototypes */
void ExecdStart(int queue);

int ReadExecConfig();

char *GetCommandbyName(char *name, int *timeout);

void ExecCmd(char **cmd);

int ExecdConfig(char * cfgfile);



#define _EXECD_H



#endif
