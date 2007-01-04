/* @(#) $Id$ */

/* Copyright (C) 2004 Daniel B. Cid <dcid@ossec.net>
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Part of the OSSEC HIDS
 * Available at http://www.ossec.net/hids/
 */

/* Functions to handle operation with files
 */

#ifndef __FILE_H

#define __FILE_H

#define OS_PIDFILE	"/var/run"

/* Set the program name. Must be done before **anything** else */
void OS_SetName(char *name);

int File_DateofChange(char *file);

int IsDir(char *file);

int CreatePID(char *name, int pid);

int DeletePID(char *name);

/* daemonize a process */
void goDaemon();

/* not really a file operation, but returns the uname */
char *getuname();

#endif
