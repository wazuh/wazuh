/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef EXECD_H
#define EXECD_H

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
#define EXECD_TIMEOUT   1

extern int repeated_offenders_timeout[];
extern char ** wcom_ca_store;
extern time_t pending_upg;
extern int is_disabled;
extern int req_timeout;
extern int max_restart_lock;

/** Function prototypes **/

void WinExecdRun(char *exec_msg);
int ReadExecConfig(void);
void CheckExecConfig();
cJSON *getARConfig(void);
cJSON *getARInternalOptions(void);
cJSON *getExecdInternalOptions(void);
cJSON *getClusterConfig(void);
char *GetCommandbyName(const char *name, int *timeout) __attribute__((nonnull));
void ExecCmd(char *const *cmd) __attribute__((nonnull));
void ExecCmd_Win32(char *cmd);
int ExecdConfig(const char *cfgfile) __attribute__((nonnull));
int WinExecd_Start(void);
void WinTimeoutRun(void);

size_t wcom_open(const char *file_path, const char *mode, char **output);
size_t wcom_write(const char *file_path, char *buffer, size_t length, char **output);
size_t wcom_close(const char *file_path, char **output);
size_t wcom_sha1(const char *file_path, char **output);
size_t wcom_unmerge(const char *file_path, char **output);
size_t wcom_uncompress(const char * source, const char * target, char ** output);
size_t wcom_upgrade(const char * package, const char * installer, char ** output);
size_t wcom_upgrade_result(char **output);
size_t wcom_clear_upgrade_result(char **output);
size_t wcom_restart(char **output);
size_t wcom_dispatch(char *command, size_t length, char **output);
size_t lock_restart(int timeout);
size_t wcom_getconfig(const char * section, char ** output);

#ifndef WIN32
// Com request thread dispatcher
void * wcom_main(void * arg);
#endif

/* Timeout data structure */
typedef struct _timeout_data {
    time_t time_of_addition;
    int time_to_block;
    char **command;
} timeout_data;

void FreeTimeoutEntry(timeout_data *timeout_entry);

#endif /* EXECD_H */
