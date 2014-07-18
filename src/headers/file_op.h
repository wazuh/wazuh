/* @(#) $Id: ./src/headers/file_op.h, 2011/09/08 dcid Exp $
 */

/* Copyright (C) 2009 Trend Micro Inc.
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

time_t File_DateofChange(const char *file);

int IsDir(char *file);

int CreatePID(char *name, int pid);

int DeletePID(char *name);

int MergeFiles(char *finalpath, char **files);

int MergeAppendFile(char *finalpath, char *files);

int UnmergeFiles(char *finalpath, char *optdir);

/* daemonize a process */
void goDaemon(void);

/* daemonize a process without closing stdin/stdou/stderr */
void goDaemonLight(void);

/* not really a file operation, but returns the uname */
char *getuname(void);

/* Checks for vista. */
#ifdef WIN32
int checkVista();
int isVista;
#endif

#endif
