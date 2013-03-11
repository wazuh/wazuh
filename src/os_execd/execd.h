/* @(#) $Id: ./src/os_execd/execd.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 *
 * More details at the LICENSE file included with OSSEC or
 * online at http://www.ossec.net/en/licensing.html .
 */


#ifndef _EXECD_H
#define _EXECD_H

#ifndef ARGV0
#define ARGV0 "ossec-execd"
#endif


/* Add/delete arguments for the commands */
#define ADD_ENTRY       "add"
#define DELETE_ENTRY    "delete"


/* Maximum number of active responses active */
#define MAX_AR      64


/* Maximum number of command arguments */
#define MAX_ARGS    32


/* Execd select timeout -- in seconds */
#define EXECD_TIMEOUT   90



/** Function prototypes **/

void ExecdStart(int queue);

void WinExecdRun(char *exec_msg);

int ReadExecConfig();

char *GetCommandbyName(char *name, int *timeout);

void ExecCmd(char **cmd);

void ExecCmd_Win32(char *cmd);

int ExecdConfig(char * cfgfile);

int WinExecd_Start();

void WinTimeoutRun(int timeout);

void FreeTimeoutEntry(void *timeout_entry);




#define _EXECD_H

#endif
