/* Copyright (C) 2015-2020, Wazuh Inc.
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

static char exec_names[MAX_AR + 1][OS_FLSIZE + 1];
static char exec_cmd[MAX_AR + 1][OS_FLSIZE + 1];
static int  exec_timeout[MAX_AR + 1];
static int  exec_size = 0;
static int  f_time_reading = 1;

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};
time_t pending_upg = 0;

/* Global variables */
STATIC OSListNode *timeout_node;
OSList *timeout_list;

#ifndef WIN32
STATIC OSHash *repeated_hash;
STATIC int CheckManagerConfiguration(char ** output);

#ifdef WAZUH_UNIT_TESTING
STATIC void execd_start(int q);
#else
STATIC void execd_start(int q) __attribute__((noreturn));
#endif


/** @copydoc execd_start */
void execd_start(int q) {
    int i, childcount = 0;
    time_t curr_time;

    char buffer[OS_MAXSTR + 1];
    char *cmd_api[MAX_ARGS];
    pthread_t wcom_thread;

    // Start com request thread
    if (CreateThreadJoinable(&wcom_thread, wcom_main, NULL) < 0) {
        return;
    }

    /* If AR is disabled, do not continue */
    if (is_disabled == 1) {
        pthread_join(wcom_thread, NULL);
        return;
    }

    /* Select */
    fd_set fdset;
    struct timeval socket_timeout;

    /* Clear the buffer */
    memset(buffer, '\0', OS_MAXSTR + 1);

    /* Initialize the api cmd arguments */
    for (i = 0; i < MAX_ARGS; i++) {
        cmd_api[i] = NULL;
    }

    if (repeated_offenders_timeout[0] != 0) {
        repeated_hash = OSHash_Create();
    } else {
        repeated_hash = NULL;
    }

    /* Main loop */
    while (1) {
        cJSON *json_root = NULL;
        char *name = NULL;
        char *cmd[2] = { NULL, NULL };
        char *cmd_parameters = NULL;
        int timeout_value;
        int added_before = 0;
        timeout_data *timeout_entry;

        /* Clean up any children */
        while (childcount) {
            int wp;
            wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0 && errno != ECHILD) {
                mterror(WM_EXECD_LOGTAG, WAITPID_ERROR, errno, strerror(errno));
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

        /* Get current time */
        curr_time = time(0);

        /* Check if there is any timed out command to execute */
        timeout_node = OSList_GetFirstNode(timeout_list);
        while (timeout_node) {
            timeout_data *list_entry;

            list_entry = (timeout_data *)timeout_node->data;

            /* Timed out */
            if ((curr_time - list_entry->time_of_addition) > list_entry->time_to_block) {

                mtdebug1(WM_EXECD_LOGTAG, "Executing command '%s %s' after a timeout of '%ds'",
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

                /* Delete current node - already sets the pointer to next */
                OSList_DeleteCurrentlyNode(timeout_list);
                timeout_node = OSList_GetCurrentlyNode(timeout_list);

                /* Clear the memory */
                free_timeout_entry(list_entry);

                childcount++;
            } else {
                timeout_node = OSList_GetNextNode(timeout_list);
            }
        }

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
            mterror(WM_EXECD_LOGTAG, SELECT_ERROR, errno, strerror(errno));
            continue;
        }

        /* Receive the message */
        if (OS_RecvUnix(q, OS_MAXSTR, buffer) == 0) {
            mterror(WM_EXECD_LOGTAG, QUEUE_ERROR, EXECQUEUE, strerror(errno));
            continue;
        }

        mtdebug2(WM_EXECD_LOGTAG, "Received message: '%s'", buffer);

        /* Current time */
        curr_time = time(0);

        /* Parse message */
        if (json_root = cJSON_Parse(buffer), !json_root) {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_JSON, buffer);
            continue;
        }

        /* Get application name */
        cJSON *json_command = cJSON_GetObjectItem(json_root, "command");
        if (json_command && (json_command->type == cJSON_String)) {
            name = json_command->valuestring;
        } else {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_CMD, buffer);
            cJSON_Delete(json_root);
            continue;
        }

        /* Check manager configuration */
        if (!strcmp(name, "check-manager-configuration")) {
            cJSON_Delete(json_root);

            char *output = NULL;
            cJSON *result_obj = cJSON_CreateObject();

            if(CheckManagerConfiguration(&output)) {
                char error_msg[OS_SIZE_4096 - 27] = {0};
                snprintf(error_msg, OS_SIZE_4096 - 27, "%s", output);

                cJSON_AddNumberToObject(result_obj, "error", 1);
                cJSON_AddStringToObject(result_obj, "message", error_msg);
                os_free(output);
                output = cJSON_PrintUnformatted(result_obj);
            } else {
                cJSON_AddNumberToObject(result_obj, "error", 0);
                cJSON_AddStringToObject(result_obj, "message", "ok");
                os_free(output);
                output = cJSON_PrintUnformatted(result_obj);
            }

            cJSON_Delete(result_obj);
            mtdebug1(WM_EXECD_LOGTAG, "Sending configuration check: %s", output);

            int rc;
            /* Start api socket */
            int api_sock;
            if ((api_sock = StartMQ(EXECQUEUEA, WRITE, 1)) < 0) {
                mterror(WM_EXECD_LOGTAG, QUEUE_ERROR, EXECQUEUEA, strerror(errno));
                os_free(output);
                continue;
            }

            if ((rc = OS_SendUnix(api_sock, output, 0)) < 0) {
                /* Error on the socket */
                if (rc == OS_SOCKTERR) {
                    mterror(WM_EXECD_LOGTAG, "socketerr (not available).");
                    os_free(output);
                    close(api_sock);
                    continue;
                }

                /* Unable to send. Socket busy */
                mtdebug2(WM_EXECD_LOGTAG, "Socket busy, discarding message.");
            }
            close(api_sock);
            os_free(output);
            continue;
        }

        /* Restart Wazuh */
        if (!strcmp(name, "restart-wazuh")) {
            cJSON_Delete(json_root);

            if(cmd_api[0] == NULL) {
                char script_path[PATH_MAX] = {0};
                snprintf(script_path, PATH_MAX, "%s", "active-response/bin/restart.sh");
                os_strdup(script_path, cmd_api[0]);
            }

            if(cmd_api[1] == NULL) {
                #ifdef CLIENT
                    os_strdup("agent", cmd_api[1]);
                #else
                    os_strdup("manager", cmd_api[1]);
                #endif
            }

            exec_command(cmd_api);
            continue;
        }

        /* Get command to execute */
        cmd[0] = get_command_by_name(name, &timeout_value);
        if (!cmd[0]) {
            read_exec_config();
            cmd[0] = get_command_by_name(name, &timeout_value);
            if (!cmd[0]) {
                mterror(WM_EXECD_LOGTAG, EXEC_INV_NAME, name);
                cJSON_Delete(json_root);
                continue;
            }
        }
        if (cmd[0][0] == '\0') {
            cJSON_Delete(json_root);
            continue;
        }

        if (name[0] != '!') {
            added_before = 0;

            /* Check if this command was already executed */
            timeout_node = OSList_GetFirstNode(timeout_list);
            while (timeout_node) {
                timeout_data *list_entry;

                list_entry = (timeout_data *)timeout_node->data;
                if (strcmp(list_entry->command[0], cmd[0]) == 0) {
                    /* Means we executed this command before and we don't need to add it again */
                    added_before = 1;

                    /* Update the timeout */
                    mtdebug1(WM_EXECD_LOGTAG, "Command already received, updating time of addition to now.");
                    list_entry->time_of_addition = curr_time;

                    if (repeated_offenders_timeout[0] != 0 && repeated_hash != NULL) {
                        char *ntimes = NULL;
                        char rkey[256];
                        rkey[255] = '\0';
                        snprintf(rkey, 255, "%s", cmd[0]);

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
                                free(ntimes);       /* In hash_op.c, data belongs to caller */
                                os_calloc(16, sizeof(char), ntimes);
                                new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                                ntimes_int++;
                                snprintf(ntimes, 16, "%d", ntimes_int);
                                if (OSHash_Update(repeated_hash, rkey, ntimes) != 1) {
                                    free(ntimes);
                                    mterror(WM_EXECD_LOGTAG, "At execd_start: OSHash_Update() failed");
                                }
                            }
                            mtdebug1(WM_EXECD_LOGTAG, "Repeated offender. Setting timeout to '%ds'", new_timeout);
                            list_entry->time_to_block = new_timeout;
                        }
                    }
                    break;
                }

                /* Continue with the next entry in timeout list*/
                timeout_node = OSList_GetNextNode(timeout_list);
            }
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
            mtdebug1(WM_EXECD_LOGTAG, "Executing command '%s %s'", cmd[0], cmd_parameters ? cmd_parameters : "");

            wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
            if (wfd) {
                fwrite(cmd_parameters, 1, strlen(cmd_parameters), wfd->file);
                wpclose(wfd);
            } else {
                mterror(WM_EXECD_LOGTAG, EXEC_CMD_FAIL, strerror(errno), errno);
                os_free(cmd_parameters);
                cJSON_Delete(json_root);
                continue;
            }

            /* We don't need to add to the list if the timeout_value == 0 */
            if (timeout_value) {
                if (repeated_hash != NULL) {
                    char *ntimes = NULL;
                    char rkey[256];
                    rkey[255] = '\0';
                    snprintf(rkey, 255, "%s", cmd[0]);

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
                            free(ntimes);       /* In hash_op.c, data belongs to caller */
                            os_calloc(16, sizeof(char), ntimes);
                            new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                            ntimes_int++;
                            snprintf(ntimes, 16, "%d", ntimes_int);
                            if (OSHash_Update(repeated_hash, rkey, ntimes) != 1) {
                                free(ntimes);
                                mterror(WM_EXECD_LOGTAG, "At execd_start: OSHash_Update() failed");
                            }
                        }
                        timeout_value = new_timeout;
                    } else {
                        /* Add to the repeat offenders list */
                        char *tmp_zero;
                        os_strdup("0", tmp_zero);
                        if (OSHash_Add(repeated_hash, rkey, tmp_zero) != 2) free(tmp_zero);
                        tmp_zero = NULL;
                    }
                }

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
                mtdebug1(WM_EXECD_LOGTAG, "Adding command '%s %s' to the timeout list, with a timeout of '%ds'.",
                    timeout_entry->command[0],
                    timeout_entry->parameters,
                    timeout_entry->time_to_block
                );

                if (!OSList_AddData(timeout_list, timeout_entry)) {
                    mterror(WM_EXECD_LOGTAG, LIST_ADD_ERROR);
                    free_timeout_entry(timeout_entry);
                }
            }

            childcount++;
        }

        os_free(cmd_parameters);
        cJSON_Delete(json_root);

    #ifdef WAZUH_UNIT_TESTING
        break;
    #endif
    }

#ifdef WAZUH_UNIT_TESTING
    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        free_timeout_entry((timeout_data *)timeout_node->data);
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);
    }
    os_free(timeout_list);
#endif
}

STATIC int CheckManagerConfiguration(char ** output) {
    int ret_val;
    int result_code;
    int timeout = 2000;
    char command_in[PATH_MAX] = {0};
    char *output_msg = NULL;
    char *daemons[] = { "bin/wazuh-authd", "bin/wazuh-remoted", "bin/wazuh-analysisd", "bin/wazuh-integratord", "bin/wazuh-maild", "bin/wazuh-modulesd", "bin/wazuh-clusterd", "bin/wazuh-agentlessd", "bin/wazuh-integratord", "bin/wazuh-dbd", "bin/wazuh-csyslogd", NULL };
    int i;
    ret_val = 0;

    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (i = 0; daemons[i]; i++) {
        output_msg = NULL;
        snprintf(command_in, PATH_MAX, "%s %s", daemons[i], "-t");

        if (wm_exec(command_in, &output_msg, &result_code, timeout, NULL) < 0) {
            if (result_code == EXECVE_ERROR) {
                mtwarn(WM_EXECD_LOGTAG, "Path is invalid or file has insufficient permissions. %s", command_in);
            } else {
                mtwarn(WM_EXECD_LOGTAG, "Error executing [%s]", command_in);
            }

            goto error;
        }

        if (output_msg && *output_msg) {
            // Remove last newline
            size_t lastchar = strlen(output_msg) - 1;
            output_msg[lastchar] = output_msg[lastchar] == '\n' ? '\0' : output_msg[lastchar];

            wm_strcat(output, output_msg, ' ');
        }

        os_free(output_msg);

        if(result_code) {
            ret_val = result_code;
            break;
        }
    }

    gettimeofday(&end, NULL);

    double elapsed = (end.tv_usec - start.tv_usec) / 1000.0;
    mtdebug1(WM_EXECD_LOGTAG, "Elapsed configuration check time: %0.3f milliseconds", elapsed);

    return ret_val;

error:
    ret_val = 1;
    return ret_val;
}

/** @copydoc exec_command */
void exec_command(char *const *cmd) {
    pid_t pid;

    /* Fork and leave it running */
    pid = fork();
    if (pid == 0) {
        if (execv(*cmd, cmd) < 0) {
            mterror(WM_EXECD_LOGTAG, EXEC_CMDERROR, *cmd, strerror(errno));
            exit(1);
        }

        exit(0);
    }
}

#else

/** @copydoc exec_cmd_win */
void exec_cmd_win(char *cmd) {
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                       &si, &pi)) {
        mterror(WM_EXECD_LOGTAG, "Unable to create active response process. ");
        return;
    }

    /* Wait until process exits */
    WaitForSingleObject(pi.hProcess, INFINITE );

    /* Close process and thread */
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );

    return;
}
#endif /* !WIN32 */

//
// Independent OS functions.
//

/** @copydoc execd_shutdown */
void execd_shutdown() {
    /* Remove pending active responses */
    mtinfo(WM_EXECD_LOGTAG, EXEC_SHUTDOWN);

    timeout_node = timeout_list ? OSList_GetFirstNode(timeout_list) : NULL;
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        mtdebug2(WM_EXECD_LOGTAG, "Delete pending AR: '%s' '%s'", list_entry->command[0], list_entry->parameters);
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
        free_timeout_entry(list_entry);
    }
}

/** @copydoc free_timeout_entry */
void free_timeout_entry(timeout_data *timeout_entry) {
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

    os_free(timeout_entry);
}

/** @copydoc read_exec_config */
int read_exec_config() {
    int i = 0, j = 0, dup_entry = 0;
    FILE *fp;
    FILE *process_file;
    char buffer[OS_MAXSTR + 1];

    /* Clean up */
    for (i = 0; i <= exec_size + 1; i++) {
        memset(exec_names[i], '\0', OS_FLSIZE + 1);
        memset(exec_cmd[i], '\0', OS_FLSIZE + 1);
        exec_timeout[i] = 0;
    }
    exec_size = 0;

    /* Open file */
    fp = fopen(DEFAULTAR, "r");
    if (!fp) {
        mterror(WM_EXECD_LOGTAG, FOPEN_ERROR, DEFAULTAR, errno, strerror(errno));
        return (0);
    }

    /* Read config */
    while (fgets(buffer, OS_MAXSTR, fp) != NULL) {
        char *str_pt;
        char *tmp_str;

        str_pt = buffer;

        // The command name must not start with '!'

        if (buffer[0] == '!') {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_CONF, DEFAULTAR);
            continue;
        }

        /* Clean up the buffer */
        tmp_str = strstr(buffer, " - ");
        if (!tmp_str) {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_CONF, DEFAULTAR);
            continue;
        }
        *tmp_str = '\0';
        tmp_str += 3;

        /* Set the name */
        strncpy(exec_names[exec_size], str_pt, OS_FLSIZE);
        exec_names[exec_size][OS_FLSIZE] = '\0';

        str_pt = tmp_str;

        /* Search for ' ' and - */
        tmp_str = strstr(tmp_str, " - ");
        if (!tmp_str) {
            mterror(WM_EXECD_LOGTAG, EXEC_INV_CONF, DEFAULTAR);
            continue;
        }
        *tmp_str = '\0';
        tmp_str += 3;

        // Directory transversal test

        if (w_ref_parent_folder(str_pt)) {
            mterror(WM_EXECD_LOGTAG, "Active response command '%s' vulnerable to directory transversal attack. Ignoring.", str_pt);
            exec_cmd[exec_size][0] = '\0';
        } else {
            /* Write the full command path */
            snprintf(exec_cmd[exec_size], OS_FLSIZE,
                     "%s/%s",
                     AR_BINDIR,
                     str_pt);
            process_file = fopen(exec_cmd[exec_size], "r");
            if (!process_file) {
                if (f_time_reading) {
                    mtinfo(WM_EXECD_LOGTAG, "Active response command not present: '%s'. "
                            "Not using it on this system.",
                            exec_cmd[exec_size]);
                }

                exec_cmd[exec_size][0] = '\0';
            } else {
                fclose(process_file);
            }
        }

        str_pt = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }

        /* Get the exec timeout */
        exec_timeout[exec_size] = atoi(str_pt);

        /* Check if name is duplicated */
        dup_entry = 0;
        for (j = 0; j < exec_size; j++) {
            if (strcmp(exec_names[j], exec_names[exec_size]) == 0) {
                if (exec_cmd[j][0] == '\0') {
                    strncpy(exec_cmd[j], exec_cmd[exec_size], OS_FLSIZE);
                    exec_cmd[j][OS_FLSIZE] = '\0';
                    dup_entry = 1;
                    break;
                } else if (exec_cmd[exec_size][0] == '\0') {
                    dup_entry = 1;
                }
            }
        }

        if (dup_entry) {
            exec_cmd[exec_size][0] = '\0';
            exec_names[exec_size][0] = '\0';
            exec_timeout[exec_size] = 0;
        } else {
            exec_size++;
        }
    }

    fclose(fp);
    f_time_reading = 0;

    return (1);
}

/** @copydoc get_command_by_name*/
char *get_command_by_name(const char *name, int *timeout) {
    int i = 0;

    // Filter custom commands

    if (name[0] == '!') {
        static char command[OS_FLSIZE];

        if (snprintf(command, sizeof(command), "%s/%s", AR_BINDIR, name + 1) >= (int)sizeof(command)) {
            mtwarn(WM_EXECD_LOGTAG, "Cannot execute command '%32s...': path too long.", name + 1);
            return NULL;
        }

        *timeout = 0;
        return command;
    }

    for (; i < exec_size; i++) {
        if (strcmp(name, exec_names[i]) == 0) {
            *timeout = exec_timeout[i];
            return (exec_cmd[i]);
        }
    }

    return (NULL);
}
