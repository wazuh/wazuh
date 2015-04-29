/* Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef WIN32

#include "shared.h"
#include "list_op.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "execd.h"

#ifdef ARGV0
#undef ARGV0
#endif

#define ARGV0 "ossec-execd"

/* Timeout list */
OSList *timeout_list;
OSListNode *timeout_node;


int WinExecd_Start()
{
    int c;
    int test_config = 0;
    char *cfg = DEFAULTCPATH;

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
    }

    /* Exit if test_config */
    if (test_config) {
        return (0);
    }

    /* Active response disabled */
    if (c == 1) {
        verbose(EXEC_DISABLED, ARGV0);
        return (0);
    }

    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        ErrorExit(LIST_ERROR, ARGV0);
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, getpid());

    return (1);
}

void WinTimeoutRun(int curr_time)
{
    /* Check if there is any timed out command to execute */
    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        /* Timed out */
        if ((curr_time - list_entry->time_of_addition) >
                list_entry->time_to_block) {
            ExecCmd_Win32(list_entry->command[0]);

            /* Delete currently node - already sets the pointer to next */
            OSList_DeleteCurrentlyNode(timeout_list);
            timeout_node = OSList_GetCurrentlyNode(timeout_list);

            /* Clear the memory */
            FreeTimeoutEntry(list_entry);
        }

        else {
            timeout_node = OSList_GetNextNode(timeout_list);
        }
    }
}

void WinExecdRun(char *exec_msg)
{
    time_t curr_time;

    int i, j;
    int timeout_value;
    int added_before = 0;

    char **timeout_args;

    char *tmp_msg = NULL;
    char *name;
    char *command;
    char *cmd_user;
    char *cmd_ip;
    char buffer[OS_MAXSTR + 1];

    timeout_data *timeout_entry;

    /* Current time */
    curr_time = time(0);

    /* Get application name */
    name = exec_msg;

    /* Zero the name */
    tmp_msg = strchr(exec_msg, ' ');
    if (!tmp_msg) {
        merror(EXECD_INV_MSG, ARGV0, exec_msg);
        return;
    }
    *tmp_msg = '\0';
    tmp_msg++;

    /* Get user */
    cmd_user = tmp_msg;
    tmp_msg = strchr(tmp_msg, ' ');
    if (!tmp_msg) {
        merror(EXECD_INV_MSG, ARGV0, cmd_user);
        return;
    }
    *tmp_msg = '\0';
    tmp_msg++;

    /* Get IP */
    cmd_ip = tmp_msg;
    tmp_msg = strchr(tmp_msg, ' ');
    if (!tmp_msg) {
        merror(EXECD_INV_MSG, ARGV0, cmd_ip);
        return;
    }
    *tmp_msg = '\0';
    tmp_msg++;

    /* Get the command to execute (valid name) */
    command = GetCommandbyName(name, &timeout_value);
    if (!command) {
        ReadExecConfig();
        command = GetCommandbyName(name, &timeout_value);
        if (!command) {
            merror(EXEC_INV_NAME, ARGV0, name);
            return;
        }
    }

    /* Command not present */
    if (command[0] == '\0') {
        return;
    }

    /* Allocate memory for the timeout argument */
    os_calloc(MAX_ARGS + 2, sizeof(char *), timeout_args);

    /* Add initial variables to the timeout cmd */
    snprintf(buffer, OS_MAXSTR, "\"%s\" %s \"%s\" \"%s\" \"%s\"",
             command, DELETE_ENTRY, cmd_user, cmd_ip, tmp_msg);
    os_strdup(buffer, timeout_args[0]);
    timeout_args[1] = NULL;

    /* Get size for the strncmp */
    i = 0, j = 0;
    while (buffer[i] != '\0') {
        if (buffer[i] == ' ') {
            j++;
        }

        i++;
        if (j == 4) {
            break;
        }
    }

    /* Check if this command was already executed */
    timeout_node = OSList_GetFirstNode(timeout_list);
    added_before = 0;

    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;
        if (strncmp(list_entry->command[0], timeout_args[0], i) == 0) {
            /* Means we executed this command before
             * and we don't need to add it again
             */
            added_before = 1;

            /* Update the timeout */
            list_entry->time_of_addition = curr_time;
            break;
        }

        /* Continue with the next entry in timeout list */
        timeout_node = OSList_GetNextNode(timeout_list);
    }

    /* If it wasn't added before, do it now */
    if (!added_before) {
        snprintf(buffer, OS_MAXSTR, "\"%s\" %s \"%s\" \"%s\" \"%s\"", command,
                 ADD_ENTRY, cmd_user, cmd_ip, tmp_msg);
        /* Execute command */
        ExecCmd_Win32(buffer);

        /* We don't need to add to the list if the timeout_value == 0 */
        if (timeout_value) {
            /* Create the timeout entry */
            os_calloc(1, sizeof(timeout_data), timeout_entry);
            timeout_entry->command = timeout_args;
            timeout_entry->time_of_addition = curr_time;
            timeout_entry->time_to_block = timeout_value;

            /* Add command to the timeout list */
            if (!OSList_AddData(timeout_list, timeout_entry)) {
                merror(LIST_ADD_ERROR, ARGV0);
                FreeTimeoutEntry(timeout_entry);
            }
        }

        /* If no timeout, we still need to free it in here */
        else {
            char **ss_ta = timeout_args;
            while (*timeout_args) {
                os_free(*timeout_args);
                *timeout_args = NULL;
                timeout_args++;
            }
            os_free(ss_ta);
        }
    }

    /* We didn't add it to the timeout list */
    else {
        char **ss_ta = timeout_args;

        /* Clear the timeout arguments */
        while (*timeout_args) {
            os_free(*timeout_args);
            *timeout_args = NULL;
            timeout_args++;
        }

        os_free(ss_ta);
    }
}

#endif /* WIN32 */

