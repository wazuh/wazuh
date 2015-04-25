/* Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

/* Functions to handle operation with files */

#ifndef __FILE_H
#define __FILE_H

#include <time.h>

#define OS_PIDFILE  "/var/run"

/* Set the program name - must be done before *anything* else */
void OS_SetName(const char *name) __attribute__((nonnull));

time_t File_DateofChange(const char *file) __attribute__((nonnull));

int IsDir(const char *file) __attribute__((nonnull));

int CreatePID(const char *name, int pid) __attribute__((nonnull));

int DeletePID(const char *name) __attribute__((nonnull));

int MergeFiles(const char *finalpath, char **files) __attribute__((nonnull));

int MergeAppendFile(const char *finalpath, const char *files) __attribute__((nonnull(1)));

int UnmergeFiles(const char *finalpath, const char *optdir) __attribute__((nonnull(1)));

/* Daemonize a process */
void goDaemon(void);

/* Daemonize a process without closing stdin/stdout/stderr */
void goDaemonLight(void);

/* Not really a file operation, but returns the uname */
char *getuname(void);

/* Return basename of path */
char *basename_ex(char *path) __attribute__((nonnull));

/* Rename file or directory */
int rename_ex(const char *source, const char *destination) __attribute__((nonnull));

/* Create temporary file */
int mkstemp_ex(char *tmp_path) __attribute__((nonnull));

/* Checks for Windows Vista */
#ifdef WIN32
int checkVista();
int isVista;
#endif

#endif /* __FILE_H */

