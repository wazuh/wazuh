/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
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
extern w_queue_t * winexec_queue;

/* Timeout list */
OSList *timeout_list;
OSListNode *timeout_node;

void *win_exec_main(void * args);

/* Shut down win-execd properly */
static void WinExecd_Shutdown()
{
    /* Remove pending active responses */
    minfo(EXEC_SHUTDOWN);

    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        mdebug2("Delete pending AR: %s", list_entry->command[0]);
        ExecCmd_Win32(list_entry->command[0]);

        /* Delete current node - already sets the pointer to next */
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);

        /* Clear the memory */
        FreeTimeoutEntry(list_entry);
    }
}

int WinExecd_Start()
{
    int c;
    int test_config = 0;
    char *cfg = DEFAULTCPATH;
    winexec_queue = queue_init(OS_SIZE_128);

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Exit if test_config */
    if (test_config) {
        return (0);
    }

    /* Active response disabled */
    if (c == 1) {
        minfo(EXEC_DISABLED);
        return (0);
    }

    CheckExecConfig();

    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        merror_exit(LIST_ERROR);
    }

    /* Delete pending AR at succesfull exit */
    atexit(WinExecd_Shutdown);

    /* Start up message */
    minfo(STARTUP_MSG, getpid());

    if (CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)win_exec_main,
            winexec_queue, 0, NULL) == NULL) {
        merror(THREAD_ERROR);
    }

    return (1);
}

// Create a thread to run windows AR simultaneous
void *win_exec_main(__attribute__((unused)) void * args) {
    while(1) {
        WinExecdRun(queue_pop_ex(winexec_queue));
    }
}

void WinTimeoutRun()
{
    time_t curr_time = time(NULL);

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
        if (name[0] != '!') {
            mwarn(EXECD_INV_MSG, exec_msg);

            return;
        } else {
            tmp_msg = exec_msg + strlen(exec_msg);
        }
    } else {
        *tmp_msg = '\0';
        tmp_msg++;
    }

    /* Get user */
    cmd_user = tmp_msg;
    tmp_msg = strchr(tmp_msg, ' ');
    if (!tmp_msg) {
        if (name[0] != '!') {
            mwarn(EXECD_INV_MSG, cmd_user);
            return;
        } else {
            tmp_msg = cmd_user + strlen(cmd_user);
        }
    } else {
        *tmp_msg = '\0';
        tmp_msg++;
    }

    /* Get IP */
    cmd_ip = tmp_msg;
    tmp_msg = strchr(tmp_msg, ' ');
    if (!tmp_msg) {
        if (name[0] != '!') {
            mwarn(EXECD_INV_MSG, cmd_ip);
            return;
        } else {
            tmp_msg = cmd_ip + strlen(cmd_ip);
        }
    } else {
        *tmp_msg = '\0';
        tmp_msg++;
    }

    /* Get the command to execute (valid name) */
    command = GetCommandbyName(name, &timeout_value);
    if (!command) {
        ReadExecConfig();
        command = GetCommandbyName(name, &timeout_value);
        if (!command) {
            merror(EXEC_INV_NAME, name);
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
        snprintf(buffer, OS_MAXSTR, name[0] == '!' ? "\"%s\" %s %s %s %s" : "\"%s\" %s \"%s\" \"%s\" \"%s\"", command,
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
                merror(LIST_ADD_ERROR);
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
