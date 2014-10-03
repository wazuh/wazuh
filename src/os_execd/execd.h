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

extern int repeated_offenders_timeout[];

/** Function prototypes **/

void WinExecdRun(char *exec_msg);

int ReadExecConfig(void);

char *GetCommandbyName(const char *name, int *timeout);

void ExecCmd(char *const *cmd);

void ExecCmd_Win32(char *cmd);

int ExecdConfig(const char * cfgfile);

int WinExecd_Start(void);

void WinTimeoutRun(int timeout);

/* Timeout data structure */
typedef struct _timeout_data
{
    time_t time_of_addition;
    int time_to_block;
    char **command;
}timeout_data;

void FreeTimeoutEntry(timeout_data *timeout_entry);

#endif
