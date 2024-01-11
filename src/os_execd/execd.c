/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "list_op.h"
#include "os_regex/os_regex.h"
#include "os_net/os_net.h"
#include "wazuh_modules/wmodules.h"
#include "../external/cJSON/cJSON.h"
#include "execd.h"
#include "active-response/active_responses.h"

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};
time_t pending_upg = 0;

STATIC OSList *timeout_list;
STATIC OSListNode *timeout_node;
STATIC OSHash *repeated_hash;

#ifdef WIN32
#ifdef WAZUH_UNIT_TESTING
    #include "unit_tests/wrappers/windows/libc/stdio_wrappers.h"
#endif
extern w_queue_t * winexec_queue;
DWORD WINAPI win_exec_main(void * args);
#endif


/* Free the timeout entry
 * Must be called after popping it from the timeout list
 */
void FreeTimeoutEntry(timeout_data *timeout_entry)
{
    char **tmp_str;

    if (!timeout_entry) {
        return;
    }

    tmp_str = timeout_entry->command;

    /* Clear the command arguments */
    if (tmp_str) {
        while (*tmp_str) {
            os_free(*tmp_str);
            *tmp_str = NULL;
            tmp_str++;
        }
        os_free(timeout_entry->command);
    }

    os_free(timeout_entry->parameters);

    os_free(timeout_entry->rkey);

    os_free(timeout_entry);
}

/* Free the timeout list
 */
void FreeTimeoutList() {
    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        FreeTimeoutEntry((timeout_data *)timeout_node->data);
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);
    }
    os_free(timeout_list);
}

#ifdef WIN32
void ExecdShutdown()
#else
void ExecdShutdown(int sig)
#endif
{
    /* Remove pending active responses */
    minfo(EXEC_SHUTDOWN);

    timeout_node = timeout_list ? OSList_GetFirstNode(timeout_list) : NULL;
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        mdebug2("Delete pending AR: '%s' '%s'", list_entry->command[0], list_entry->parameters);

        wfd_t *wfd = wpopenv(list_entry->command[0], list_entry->command, W_BIND_STDIN);
        if (wfd) {
            /* Send alert to AR script */
            fprintf(wfd->file_in, "%s\n", list_entry->parameters);
            fflush(wfd->file_in);
            wpclose(wfd);
        } else {
            merror(EXEC_CMD_FAIL, strerror(errno), errno);
        }

        /* Delete current node - already sets the pointer to next */
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);

        /* Clear the memory */
        FreeTimeoutEntry(list_entry);
    }

#ifndef WIN32
    HandleSIG(sig);
#endif
}

#ifdef WIN32
void ExecdTimeoutRun()
#else
void ExecdTimeoutRun(int *childcount)
#endif
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
                /* Send alert to AR script */
                fprintf(wfd->file_in, "%s\n", list_entry->parameters);
                fflush(wfd->file_in);
                wpclose(wfd);
            } else {
                merror(EXEC_CMD_FAIL, strerror(errno), errno);
            }

            /* Delete currently node - already sets the pointer to next */
            OSList_DeleteCurrentlyNode(timeout_list);
            timeout_node = OSList_GetCurrentlyNode(timeout_list);

            /* Clear the memory */
            FreeTimeoutEntry(list_entry);

#ifndef WIN32
            (*childcount)++;
#endif
        } else {
            timeout_node = OSList_GetNextNode(timeout_list);
        }
    }
}

#ifdef WIN32
void ExecdRun(char *exec_msg)
#else
void ExecdRun(char *exec_msg, int *childcount)
#endif
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
        merror(EXEC_INV_JSON, exec_msg);
        return;
    }

    /* Get application name */
    cJSON *json_command = cJSON_GetObjectItem(json_root, "command");
    if (json_command && (json_command->type == cJSON_String)) {
        name = json_command->valuestring;
    } else {
        merror(EXEC_INV_CMD, exec_msg);
        cJSON_Delete(json_root);
        return;
    }

#ifndef WIN32
    if (!strcmp(name, "restart-wazuh")) {
        char *cmd_api[MAX_ARGS] = {0};

        cJSON_Delete(json_root);

        os_strdup("active-response/bin/restart.sh", cmd_api[0]);

    #ifdef CLIENT
        os_strdup("agent", cmd_api[1]);
    #else
        os_strdup("manager", cmd_api[1]);
    #endif

        ExecCmd(cmd_api);
        return;
    }
#endif

    /* Get command to execute */
    cmd[0] = GetCommandbyName(name, &timeout_value);
    if (!cmd[0]) {
        ReadExecConfig();
        cmd[0] = GetCommandbyName(name, &timeout_value);
        if (!cmd[0]) {
            merror(EXEC_INV_NAME, name);
            cJSON_Delete(json_root);
            return;
        }
    }
    if (cmd[0][0] == '\0') {
        cJSON_Delete(json_root);
        return;
    }

    /* Command parameters */
    cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(ADD_ENTRY));
    cJSON *json_origin = cJSON_GetObjectItem(json_root, "origin");
    cJSON_ReplaceItemInObject(json_origin, "module", cJSON_CreateString(ARGV0));
    cJSON *json_parameters = cJSON_GetObjectItem(json_root, "parameters");
    cJSON_AddItemToObject(json_parameters, "program", cJSON_CreateString(cmd[0]));
    cmd_parameters = cJSON_PrintUnformatted(json_root);

    /* Execute command */
    mdebug1("Executing command '%s %s'", cmd[0], cmd_parameters ? cmd_parameters : "");

    wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN | W_BIND_STDOUT);
    if (wfd) {
        char response[OS_SIZE_8192];
        char rkey[OS_SIZE_4096];
        cJSON *keys_json = NULL;

        /* Send alert to AR script */
        fprintf(wfd->file_in, "%s\n", cmd_parameters);
        fflush(wfd->file_in);

        /* Receive alert keys from AR script to check timeout list */
        if (fgets(response, sizeof(response), wfd->file_out) == NULL) {
            mdebug1("Active response won't be added to timeout list. "
                    "Message not received with alert keys from script '%s'", cmd[0]);
            wpclose(wfd);
            os_free(cmd_parameters);
            cJSON_Delete(json_root);
            return;
        }

        /* Set rkey initially with the name of the AR */
        memset(rkey, '\0', OS_SIZE_4096);
        snprintf(rkey, OS_SIZE_4096 - 1, "%s", basename_ex(cmd[0]));

        keys_json = get_json_from_input(response);
        if (keys_json != NULL) {
            const char *action = get_command_from_json(keys_json);
            if ((action != NULL) && (strcmp(CHECK_KEYS_ENTRY, action) == 0)) {
                char *keys = get_keys_from_json(keys_json);
                if (keys != NULL) {
                    /* Append to rkey the alert keys that the AR script will use */
                    strcat(rkey, keys);
                    os_free(keys);
                }
            }
            cJSON_Delete(keys_json);
        }

        added_before = 0;

        /* We don't need to add to the list if the timeout_value == 0 */
        if (timeout_value) {
            if (repeated_hash != NULL) {
                char *ntimes = NULL;

                if ((ntimes = (char *) OSHash_Get(repeated_hash, rkey))) {
                    int ntimes_int = 0;
                    int i2 = 0;
                    int new_timeout = 0;

                    ntimes_int = atoi(ntimes);
                    while (repeated_offenders_timeout[i2] != 0) {
                        i2++;
                    }
                    if (ntimes_int >= i2) {
                        new_timeout = repeated_offenders_timeout[i2 - 1] * 60;
                    } else {
                        os_free(ntimes);       /* In hash_op.c, data belongs to caller */
                        os_calloc(16, sizeof(char), ntimes);
                        new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                        ntimes_int++;
                        snprintf(ntimes, 16, "%d", ntimes_int);
                        if (OSHash_Update(repeated_hash, rkey, ntimes) != 1) {
                            os_free(ntimes);
                            merror("At ExecdRun: OSHash_Update() failed");
                        }
                    }
                    mdebug1("Repeated offender. Setting timeout to '%ds'", new_timeout);
                    timeout_value = new_timeout;
                } else {
                    /* Add to the repeated offenders list */
                    char *tmp_zero;
                    os_strdup("0", tmp_zero);
                    if (OSHash_Add(repeated_hash, rkey, tmp_zero) != 2) {
                        os_free(tmp_zero);
                        merror("At ExecdRun: OSHash_Add() failed");
                    }
                }
            }

            /* Check if this command was already executed */
            timeout_node = OSList_GetFirstNode(timeout_list);
            while (timeout_node) {
                timeout_data *list_entry;

                list_entry = (timeout_data *)timeout_node->data;
                if (strcmp(list_entry->rkey, rkey) == 0) {
                    /* Means we executed this command before and we don't need to add it again */
                    added_before = 1;

                    /* Update the timeout */
                    mdebug1("Command already received, updating time of addition to now.");
                    list_entry->time_of_addition = curr_time;
                    list_entry->time_to_block = timeout_value;
                    break;
                }

                /* Continue with the next entry in timeout list */
                timeout_node = OSList_GetNextNode(timeout_list);
            }

            /* If it wasn't added before, do it now */
            if (!added_before) {
                /* Timeout parameters */
                cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(DELETE_ENTRY));

                /* Create the timeout entry */
                os_calloc(1, sizeof(timeout_data), timeout_entry);
                os_calloc(2, sizeof(char *), timeout_entry->command);
                os_strdup(cmd[0], timeout_entry->command[0]);
                timeout_entry->command[1] = NULL;
                timeout_entry->parameters = cJSON_PrintUnformatted(json_root);
                os_strdup(rkey, timeout_entry->rkey);
                timeout_entry->time_of_addition = curr_time;
                timeout_entry->time_to_block = timeout_value;

                /* Add command to the timeout list */
                mdebug1("Adding command '%s %s' to the timeout list, with a timeout of '%ds'.",
                    timeout_entry->command[0],
                    timeout_entry->parameters,
                    timeout_entry->time_to_block
                );

                if (!OSList_AddData(timeout_list, timeout_entry)) {
                    merror(LIST_ADD_ERROR);
                    FreeTimeoutEntry(timeout_entry);
                }
            }
        }

        /* If it wasn't added before, continue execution */
        if (!added_before) {
            /* Continue command */
            cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(CONTINUE_ENTRY));
        } else {
            /* Abort command */
            cJSON_ReplaceItemInObject(json_root, "command", cJSON_CreateString(ABORT_ENTRY));
        }

        os_free(cmd_parameters);
        cmd_parameters = cJSON_PrintUnformatted(json_root);

        /* Send continue/abort message to AR script */
        fprintf(wfd->file_in, "%s\n", cmd_parameters);
        fflush(wfd->file_in);

        wpclose(wfd);

#ifndef WIN32
        (*childcount)++;
#endif
    } else {
        merror(EXEC_CMD_FAIL, strerror(errno), errno);
    }

    os_free(cmd_parameters);
    cJSON_Delete(json_root);
}

#ifndef WIN32

void ExecdStart(int q)
{
    int childcount = 0;

    char buffer[OS_MAXSTR + 1];

    /* Select */
    fd_set fdset;
    struct timeval socket_timeout;

    /* Clear the buffer */
    memset(buffer, '\0', OS_MAXSTR + 1);

#ifndef WAZUH_UNIT_TESTING
    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        merror_exit(LIST_ERROR);
    }
#endif

    if (repeated_offenders_timeout[0] != 0) {
        repeated_hash = OSHash_Create();
    } else {
        repeated_hash = NULL;
    }

    /* Main loop */
    while (1) {
        /* Clean up any children */
        while (childcount) {
            int wp;
            wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0 && errno != ECHILD) {
                merror(WAITPID_ERROR, errno, strerror(errno));
                break;
            }
            /* if = 0, we still need to wait for the child process */
            else if (wp == 0) {
                break;
            }
            /* Child completed if wp > 0 */
            else {
                childcount--;
            }
        }

        ExecdTimeoutRun(&childcount);

        /* Set timeout to EXECD_TIMEOUT */
        socket_timeout.tv_sec = EXECD_TIMEOUT;
        socket_timeout.tv_usec = 0;

        /* Set FD values */
        FD_ZERO(&fdset);
        FD_SET(q, &fdset);

        /* Add timeout */
        if (select(q + 1, &fdset, NULL, NULL, &socket_timeout) == 0) {
            /* Timeout */
            continue;
        }

        /* Check for error */
        if (!FD_ISSET(q, &fdset)) {
            merror(SELECT_ERROR, errno, strerror(errno));
            continue;
        }

        /* Receive the message */
        if (OS_RecvUnix(q, OS_MAXSTR, buffer) == 0) {
            merror(QUEUE_ERROR, EXECQUEUE, strerror(errno));
            continue;
        }

        mdebug2("Received message: '%s'", buffer);

        ExecdRun(buffer, &childcount);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }
}

#else

int WinExecdStart()
{
    int c;
    char *cfg = OSSECCONF;
    winexec_queue = queue_init(OS_SIZE_128);

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        mlerror_exit(LOGLEVEL_ERROR, CONFIG_ERROR, cfg);
    }

    /* Active response disabled */
    if (c == 1) {
        minfo(EXEC_DISABLED);
        return (0);
    }

    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        merror_exit(LIST_ERROR);
    }

    if (repeated_offenders_timeout[0] != 0) {
        repeated_hash = OSHash_Create();
    } else {
        repeated_hash = NULL;
    }

    /* Delete pending AR at succesfull exit */
    atexit(ExecdShutdown);

    /* Start up message */
    minfo(STARTUP_MSG, getpid());

    w_create_thread(NULL, 0, win_exec_main,
                    winexec_queue, 0, NULL);

    return (1);
}

// Create a thread to run windows AR simultaneous
DWORD WINAPI win_exec_main(__attribute__((unused)) void * args) {
    while(1) {
        char* exec_msg = queue_pop_ex(winexec_queue);
        if (exec_msg) {
            ExecdRun(exec_msg);
            os_free(exec_msg);
        }
    }
}

#endif
