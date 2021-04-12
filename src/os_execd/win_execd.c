/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
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

#define ARGV0 "wazuh-execd"
extern w_queue_t * winexec_queue;

/* Timeout list */
OSList *timeout_list;
OSListNode *timeout_node;

DWORD WINAPI win_exec_main(void * args);

/* Shut down win-execd properly */
static void WinExecd_Shutdown()
{
    /* Remove pending active responses */
    mtinfo(WM_EXECD_LOGTAG, EXEC_SHUTDOWN);

    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        mdebug2("Delete pending AR: %s", list_entry->command[0]);

        wfd_t *wfd = wpopenv(list_entry->command[0], list_entry->command, W_BIND_STDIN);
        if (wfd) {
            fwrite(list_entry->parameters, 1, strlen(list_entry->parameters), wfd->file);
            wpclose(wfd);
        } else {
            mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
        }

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
    char *cfg = DEFAULTCPATH;
    winexec_queue = queue_init(OS_SIZE_128);

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        mterror_exit(WM_EXECD_LOGTAG, CONFIG_ERROR, cfg);
    }

    /* Active response disabled */
    if (c == 1) {
        mtinfo(WM_EXECD_LOGTAG, EXEC_DISABLED);
        return (0);
    }

    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        mterror_exit(WM_EXECD_LOGTAG, LIST_ERROR);
    }

    /* Delete pending AR at succesfull exit */
    atexit(WinExecd_Shutdown);

    /* Start up message */
    mtinfo(WM_EXECD_LOGTAG, STARTUP_MSG, getpid());

    w_create_thread(NULL, 0, win_exec_main,
                    winexec_queue, 0, NULL);

    return (1);
}

// Create a thread to run windows AR simultaneous
DWORD WINAPI win_exec_main(__attribute__((unused)) void * args) {
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
        if ((curr_time - list_entry->time_of_addition) > list_entry->time_to_block) {

            mdebug1("Executing command '%s %s' after a timeout of '%ds'",
                list_entry->command[0],
                list_entry->parameters ? list_entry->parameters : "",
                list_entry->time_to_block
            );

            wfd_t *wfd = wpopenv(list_entry->command[0], list_entry->command, W_BIND_STDIN);
            if (wfd) {
                fwrite(list_entry->parameters, 1, strlen(list_entry->parameters), wfd->file);
                wpclose(wfd);
            } else {
                mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
            }

            /* Delete currently node - already sets the pointer to next */
            OSList_DeleteCurrentlyNode(timeout_list);
            timeout_node = OSList_GetCurrentlyNode(timeout_list);

            /* Clear the memory */
            FreeTimeoutEntry(list_entry);
        } else {
            timeout_node = OSList_GetNextNode(timeout_list);
        }
    }
}

void WinExecdRun(char *exec_msg)
{
    time_t curr_time;

    int timeout_value;
    int added_before = 0;

    cJSON *json_root = NULL;
    char *name = NULL;
    char *cmd[2] = { NULL, NULL };
    char *cmd_parameters = NULL;

    timeout_data *timeout_entry;

    /* Current time */
    curr_time = time(0);

    /* Parse message */
    if (json_root = cJSON_Parse(exec_msg), !json_root) {
        mterror(WM_EXECD_LOGTAG, EXEC_INV_JSON, exec_msg);
        return;
    }

    /* Get application name */
    cJSON *json_command = cJSON_GetObjectItem(json_root, "command");
    if (json_command && (json_command->type == cJSON_String)) {
        name = json_command->valuestring;
    } else {
        mterror(WM_EXECD_LOGTAG, EXEC_INV_CMD, exec_msg);
        cJSON_Delete(json_root);
        return;
    }

    /* Get command to execute */
    cmd[0] = GetCommandbyName(name, &timeout_value);
    if (!cmd[0]) {
        ReadExecConfig();
        cmd[0] = GetCommandbyName(name, &timeout_value);
        if (!cmd[0]) {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_NAME, name);
            cJSON_Delete(json_root);
            return;
        }
    }
    if (cmd[0][0] == '\0') {
        cJSON_Delete(json_root);
        return;
    }

    /* Check if this command was already executed */
    timeout_node = OSList_GetFirstNode(timeout_list);
    added_before = 0;

    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;
        if (strcmp(list_entry->command[0], cmd[0]) == 0) {
            /* Means we executed this command before and we don't need to add it again */
            added_before = 1;

            /* Update the timeout */
            mdebug1("Command already received, updating time of addition to now.");
            list_entry->time_of_addition = curr_time;
            break;
        }

        /* Continue with the next entry in timeout list */
        timeout_node = OSList_GetNextNode(timeout_list);
    }

    /* If it wasn't added before, do it now */
    if (!added_before) {
        /* Command parameters */
        cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(ADD_ENTRY));
        cJSON *json_origin = cJSON_GetObjectItem(json_root, "origin");
        cJSON_ReplaceItemInObject(json_origin, "module", cJSON_CreateString(ARGV0));
        cJSON *json_parameters = cJSON_GetObjectItem(json_root, "parameters");
        cJSON_AddItemToObject(json_parameters, "program", cJSON_CreateString(cmd[0]));
        cmd_parameters = cJSON_PrintUnformatted(json_root);

        /* Execute command */
        mdebug1("Executing command '%s %s'", cmd[0], cmd_parameters ? cmd_parameters : "");

        wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
        if (wfd) {
            fwrite(cmd_parameters, 1, strlen(cmd_parameters), wfd->file);
            wpclose(wfd);
        } else {
            mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
            os_free(cmd_parameters);
            cJSON_Delete(json_root);
            return;
        }

        /* We don't need to add to the list if the timeout_value == 0 */
        if (timeout_value) {
            /* Timeout parameters */
            cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(DELETE_ENTRY));

            /* Create the timeout entry */
            os_calloc(1, sizeof(timeout_data), timeout_entry);
            os_calloc(2, sizeof(char *), timeout_entry->command);
            os_strdup(cmd[0], timeout_entry->command[0]);
            timeout_entry->command[1] = NULL;
            timeout_entry->parameters = cJSON_PrintUnformatted(json_root);
            timeout_entry->time_of_addition = curr_time;
            timeout_entry->time_to_block = timeout_value;

            /* Add command to the timeout list */
            mdebug1("Adding command '%s %s' to the timeout list, with a timeout of '%ds'.",
                timeout_entry->command[0],
                timeout_entry->parameters,
                timeout_entry->time_to_block
            );

            if (!OSList_AddData(timeout_list, timeout_entry)) {
                mterror(WM_EXECD_LOGTAG, LIST_ADD_ERROR);
                FreeTimeoutEntry(timeout_entry);
            }
        }
    }

    os_free(cmd_parameters);
    cJSON_Delete(json_root);
}

#endif /* WIN32 */
