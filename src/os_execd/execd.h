/* Copyright (C) 2015-2021, Wazuh Inc.
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

#include "shared.h"
#include "os_xml/os_xml.h"
#include "../external/cJSON/cJSON.h"

#ifndef ARGV0
#define ARGV0 "wazuh-modulesd"
#endif

#define WM_EXECD_LOGTAG ARGV0 ":execd" // Tag for log messages

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
extern time_t pending_upg;
extern int is_disabled;
extern int req_timeout;
extern int max_restart_lock;
extern OSList *timeout_list;

/* Timeout data structure */
typedef struct _timeout_data {
    time_t time_of_addition;
    int time_to_block;
    char **command;
    char *parameters;
} timeout_data;

/**
 * Function prototypes - Windows
 **/

/**
 * @brief Main function on the execd - for Windows. Does all the data receiving, etc.
 *
 * @param exec_msg execd json file for starting purposes.
 */
void win_execd_run(char *exec_msg);

/**
 * @brief Executes the \p cmd command.
 *
 * @param cmd Specific command to be executed.
 */
void exec_cmd_win(char *cmd);

/**
 * @brief Timeout execd execution for Windows.
 */
void win_timeout_run(void);


/**
 * Function prototypes
 **/

/**
 * @brief Reads the config file.
 *
 * @return 1 if Active Response is enabled, 0 otherwise.
 */
int execd_config();

/**
 * @brief Reads the shared exec config.
 *
 * @return 1 on success, 0 otherwise.
 *
 * @details Format of the file is 'name - command - timeout'.
 */
int read_exec_config(void);

/**
 * @brief Main function on the execd. Does all the data receiving, etc.
 *
 * @param q Specific queue to start with.
 */
void execd_start(int q);

/**
 * @brief Function to shutdown execd module.
 *
 */
void execd_shutdown();

/**
 * @brief Gets a pointer to the command name (full path).
 *
 * @param name    Command name to get the pointer to.
 * @param timeout Timeout value to write for the current command.
 *
 * @return Pointer to the command name (full path) on success, NULL otherwise.
 *
 * @details If timeout is not NULL, write the timeout for that
 *  command to it
 */
char *get_command_by_name(const char *name, int *timeout) __attribute__((nonnull));

/**
 * @brief Execute command given. Must be a argv** NULL terminated.
 *
 * @param cmd Command to be executed.
 *
 * @details Prints error to log message in case of problems.
 */
void exec_command(char *const *cmd) __attribute__((nonnull));

/**
 * @brief Frees the timeout entry.
 *
 * @param timeout_entry timeout data structure to be freed.
 *
 * @details Must be called after popping it from the timeout list
 */
void free_timeout_entry(timeout_data *timeout_entry);

cJSON *get_ar_config(void);
cJSON *get_execd_internal_options(void);
cJSON *get_cluster_config(void);

size_t wcom_unmerge(const char *file_path, char **output);
size_t wcom_uncompress(const char * source, const char * target, char ** output);
size_t wcom_restart(char **output);
size_t wcom_dispatch(char *command, char **output);
size_t lock_restart(int timeout);
size_t wcom_getconfig(const char * section, char ** output);


#ifndef WIN32
// Com request thread dispatcher
void * wcom_main(void * arg);
#endif


#endif /* EXECD_H */
