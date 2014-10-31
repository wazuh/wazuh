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

#include <time.h>



#define OS_PIDFILE	"/var/run"

/* Set the program name. Must be done before **anything** else */
void OS_SetName(const char *name) __attribute__((nonnull));

time_t File_DateofChange(const char *file) __attribute__((nonnull));

int IsDir(const char *file) __attribute__((nonnull));

int CreatePID(const char *name, int pid) __attribute__((nonnull));

int DeletePID(const char *name) __attribute__((nonnull));

int MergeFiles(const char *finalpath, char **files) __attribute__((nonnull));

int MergeAppendFile(const char *finalpath, const char *files) __attribute__((nonnull(1)));

int UnmergeFiles(const char *finalpath, const char *optdir) __attribute__((nonnull(1)));

/* daemonize a process */
void goDaemon(void);

/* daemonize a process without closing stdin/stdou/stderr */
void goDaemonLight(void);

/* not really a file operation, but returns the uname */
char *getuname(void);

/* return basename of path */
char *basename_ex(char *path) __attribute__((nonnull));

/* rename file or directory */
int rename_ex(const char *source, const char *destination) __attribute__((nonnull));

/* create temporary file */
int mkstemp_ex(char *tmp_path) __attribute__((nonnull));

/* Checks for vista. */
#ifdef WIN32
int checkVista();
int isVista;
#endif

#endif
