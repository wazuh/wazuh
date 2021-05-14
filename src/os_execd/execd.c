/* Copyright (C) 2015-2021, Wazuh Inc.
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

#ifdef WAZUH_UNIT_TESTING
// Remove static qualifier when unit testing
#define STATIC
#else
#define STATIC static
#endif

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};
time_t pending_upg = 0;

#ifndef WIN32

/* Prototypes */
static void help_execd(char * home_path) __attribute__((noreturn));
STATIC void execd_shutdown(int sig) __attribute__((noreturn));
#ifdef WAZUH_UNIT_TESTING
STATIC void ExecdStart(int q);
#else
STATIC void ExecdStart(int q) __attribute__((noreturn));
#endif

/* Global variables */
STATIC OSList *timeout_list;
STATIC OSListNode *timeout_node;
STATIC OSHash *repeated_hash;


/* Print help statement */
static void help_execd(char * home_path)
{
    print_header();
    print_out("  %s: -[Vhdtf] [-g group] [-c config]", ARGV0);
    print_out("    -V          Version and license message");
    print_out("    -h          This help message");
    print_out("    -d          Execute in debug mode. This parameter");
    print_out("                can be specified multiple times");
    print_out("                to increase the debug level.");
    print_out("    -t          Test configuration");
    print_out("    -f          Run in foreground");
    print_out("    -g <group>  Group to run as (default: %s)", GROUPGLOBAL);
    print_out("    -c <config> Configuration file to use (default: %s)", WAZUHCONF_AGENT);
    print_out(" ");
    os_free(home_path);
    exit(1);
}

/* Shut down execd properly */
STATIC void execd_shutdown(int sig)
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
            fwrite(list_entry->parameters, 1, strlen(list_entry->parameters), wfd->file);
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

    HandleSIG(sig);
}

#ifdef WAZUH_UNIT_TESTING
__attribute((weak))
#endif
int main(int argc, char **argv)
{
    int c;
    int test_config = 0, run_foreground = 0;
    gid_t gid;
    int m_queue = 0;
    int debug_level = 0;
    pthread_t wcom_thread;

    /* Set the name */
    OS_SetName(ARGV0);

    // Define current working directory
    char * home_path = w_homedir(argv[0]);
    if (chdir(home_path) == -1) {
        merror_exit(CHDIR_ERROR, home_path, errno, strerror(errno));
    }

    const char *group = GROUPGLOBAL;
    const char *cfg = WAZUHCONF_AGENT;


    while ((c = getopt(argc, argv, "Vtdhfg:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_execd(home_path);
                break;
            case 'd':
                debug_level = 1;
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'g':
                if (!optarg) {
                    merror_exit("-g needs an argument.");
                }
                group = optarg;
                break;
            case 'c':
                if (!optarg) {
                    merror_exit("-c needs an argument.");
                }
                cfg = optarg;
                break;
            case 't':
                test_config = 1;
                break;
            default:
                help_execd(home_path);
                break;
        }
    }

    if (debug_level == 0) {
        /* Get debug level */
        debug_level = getDefine_Int("execd", "debug", 0, 2);
        while (debug_level != 0) {
            nowDebug();
            debug_level--;
        }
    }

    mdebug1(WAZUH_HOMEDIR, home_path);
    os_free(home_path);

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group, strerror(errno), errno);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        merror_exit(SETGID_ERROR, group, errno, strerror(errno));
    }

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        merror_exit(CONFIG_ERROR, cfg);
    }

    /* Exit if test_config */
    if (test_config) {
        exit(0);
    }

    /* Signal manipulation */
    StartSIG2(ARGV0, execd_shutdown);

    if (!run_foreground) {
        /* Going daemon */
        nowDaemon();
        goDaemon();
    }

    /* Active response disabled */
    if (c == 1) {
        minfo(EXEC_DISABLED);
    }

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror_exit(PID_ERROR);
    }

    // Start com request thread
    if (CreateThreadJoinable(&wcom_thread, wcom_main, NULL) < 0) {
        exit(EXIT_FAILURE);
    }

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* If AR is disabled, do not continue */
    if (c == 1) {
        pthread_join(wcom_thread, NULL);
        exit(EXIT_SUCCESS);
    }

    /* Start exec queue */
    if ((m_queue = StartMQ(EXECQUEUE, READ, 0)) < 0) {
        merror_exit(QUEUE_ERROR, EXECQUEUE, strerror(errno));
    }

    /* The real daemon Now */
    ExecdStart(m_queue);

    exit(0);
}

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

    os_free(timeout_entry);
}

#ifndef WIN32

/* Main function on the execd. Does all the data receiving, etc. */
STATIC void ExecdStart(int q)
{
    int i, childcount = 0;
    time_t curr_time;

    char buffer[OS_MAXSTR + 1];
    char *cmd_api[MAX_ARGS];

    /* Select */
    fd_set fdset;
    struct timeval socket_timeout;

    /* Clear the buffer */
    memset(buffer, '\0', OS_MAXSTR + 1);

    /* Initialize the api cmd arguments */
    for (i = 0; i < MAX_ARGS; i++) {
        cmd_api[i] = NULL;
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

        /* Get current time */
        curr_time = time(0);

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
                    merror(EXEC_CMD_FAIL, strerror(errno), errno);
                }

                /* Delete current node - already sets the pointer to next */
                OSList_DeleteCurrentlyNode(timeout_list);
                timeout_node = OSList_GetCurrentlyNode(timeout_list);

                /* Clear the memory */
                FreeTimeoutEntry(list_entry);

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
            merror(SELECT_ERROR, errno, strerror(errno));
            continue;
        }

        /* Receive the message */
        if (OS_RecvUnix(q, OS_MAXSTR, buffer) == 0) {
            merror(QUEUE_ERROR, EXECQUEUE, strerror(errno));
            continue;
        }

        mdebug2("Received message: '%s'", buffer);

        /* Current time */
        curr_time = time(0);

        /* Parse message */
        if (json_root = cJSON_Parse(buffer), !json_root) {
            merror(EXEC_INV_JSON, buffer);
            continue;
        }

        /* Get application name */
        cJSON *json_command = cJSON_GetObjectItem(json_root, "command");
        if (json_command && (json_command->type == cJSON_String)) {
            name = json_command->valuestring;
        } else {
            merror(EXEC_INV_CMD, buffer);
            cJSON_Delete(json_root);
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

            ExecCmd(cmd_api);
            continue;
        }

        /* Get command to execute */
        cmd[0] = GetCommandbyName(name, &timeout_value);
        if (!cmd[0]) {
            ReadExecConfig();
            cmd[0] = GetCommandbyName(name, &timeout_value);
            if (!cmd[0]) {
                merror(EXEC_INV_NAME, name);
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
                    mdebug1("Command already received, updating time of addition to now.");
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
                                    merror("At ExecdStart: OSHash_Update() failed");
                                }
                            }
                            mdebug1("Repeated offender. Setting timeout to '%ds'", new_timeout);
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
            mdebug1("Executing command '%s %s'", cmd[0], cmd_parameters ? cmd_parameters : "");

            wfd_t *wfd = wpopenv(cmd[0], cmd, W_BIND_STDIN);
            if (wfd) {
                fwrite(cmd_parameters, 1, strlen(cmd_parameters), wfd->file);
                wpclose(wfd);
            } else {
                merror(EXEC_CMD_FAIL, strerror(errno), errno);
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
                                merror("At ExecdStart: OSHash_Update() failed");
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
        FreeTimeoutEntry((timeout_data *)timeout_node->data);
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);
    }
    os_free(timeout_list);
#endif
}

#endif /* !WIN32 */
