/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
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

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};
time_t pending_upg = 0;

#ifndef WIN32

/* Prototypes */
static void help_execd(void) __attribute__((noreturn));
static void execd_shutdown(int sig) __attribute__((noreturn));
static void ExecdStart(int q) __attribute__((noreturn));
static int CheckManagerConfiguration(char ** output);

/* Global variables */
static OSList *timeout_list;
static OSListNode *timeout_node;
static OSHash *repeated_hash;


/* Print help statement */
static void help_execd()
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
    print_out("    -c <config> Configuration file to use (default: %s)", DEFAULTCPATH);
    print_out(" ");
    exit(1);
}

/* Shut down execd properly */
static void execd_shutdown(int sig)
{
    /* Remove pending active responses */
    minfo(EXEC_SHUTDOWN);

    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        mdebug2("Delete pending AR: %s", list_entry->command[0]);
        ExecCmd(list_entry->command);

        /* Delete current node - already sets the pointer to next */
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);
    }

    HandleSIG(sig);
}

int main(int argc, char **argv)
{
    int c;
    int test_config = 0, run_foreground = 0;
    gid_t gid;
    int m_queue = 0;
    int debug_level = 0;

    const char *group = GROUPGLOBAL;
    const char *cfg = DEFAULTCPATH;

    /* Set the name */
    OS_SetName(ARGV0);

    while ((c = getopt(argc, argv, "Vtdhfg:c:")) != -1) {
        switch (c) {
            case 'V':
                print_version();
                break;
            case 'h':
                help_execd();
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
                help_execd();
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

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        merror_exit(USER_ERROR, "", group);
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

#ifdef CLIENT
    CheckExecConfig();
#endif

    // Start com request thread
    w_create_thread(wcom_main, NULL);

    /* Start up message */
    minfo(STARTUP_MSG, (int)getpid());

    /* If AR is disabled, close this thread */
    if (c == 1) {
        pthread_exit(NULL);
    }

    /* Start exec queue */
    if ((m_queue = StartMQ(EXECQUEUEPATH, READ)) < 0) {
        merror_exit(QUEUE_ERROR, EXECQUEUEPATH, strerror(errno));
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
        timeout_entry->command = NULL;
    }

    free(timeout_entry);
}

#ifndef WIN32

/* Main function on the execd. Does all the data receiving, etc. */
static void ExecdStart(int q)
{
    int i, childcount = 0;
    time_t curr_time;

    char buffer[OS_MAXSTR + 1];
    char *tmp_msg = NULL;
    char *name;
    char *command;
    char *cmd_args[MAX_ARGS + 2];
    char *cmd_api[MAX_ARGS];

    /* Select */
    fd_set fdset;
    struct timeval socket_timeout;

    /* Clear the buffer */
    memset(buffer, '\0', OS_MAXSTR + 1);

    /* Initialize the cmd arguments */
    for (i = 0; i <= MAX_ARGS + 1; i++) {
        cmd_args[i] = NULL;
    }

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
        int timeout_value;
        int added_before = 0;
        char **timeout_args;
        timeout_data *timeout_entry;

        /* Clean up any children */
        while (childcount) {
            int wp;
            wp = waitpid((pid_t) - 1, NULL, WNOHANG);
            if (wp < 0) {
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
            if ((curr_time - list_entry->time_of_addition) >
                    list_entry->time_to_block) {
                ExecCmd(list_entry->command);

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
            merror(QUEUE_ERROR, EXECQUEUEPATH, strerror(errno));
            continue;
        }

        /* Current time */
        curr_time = time(0);

        /* Get application name */
        name = buffer;

        /* Zero the name */
        tmp_msg = strchr(buffer, ' ');
        if (!tmp_msg) {
            if (name[0] != '!') {
                mwarn(EXECD_INV_MSG, buffer);
                continue;
            } else {
                tmp_msg = buffer + strlen(buffer);
            }
        } else {
            *tmp_msg = '\0';
            tmp_msg++;
        }

        if(!strcmp(name,"check-manager-configuration")) {
            char *output = NULL;
            cJSON *result_obj = cJSON_CreateObject();

            if(CheckManagerConfiguration(&output)) {
                char error_msg[OS_SIZE_4096 - 27] = {0};
                snprintf(error_msg,OS_SIZE_4096 - 27,"%s",output);

                cJSON_AddNumberToObject(result_obj,"error",1);
                cJSON_AddStringToObject(result_obj,"message",error_msg);
                os_free(output);
                output = cJSON_PrintUnformatted(result_obj);

            } else {

                cJSON_AddNumberToObject(result_obj,"error",0);
                cJSON_AddStringToObject(result_obj,"message","ok");
                os_free(output);
                output = cJSON_PrintUnformatted(result_obj);
            }

            cJSON_Delete(result_obj);
            mdebug1("Sending configuration check: %s",output);

            int rc;
            /* Start api socket */
            int api_sock;
            if ((api_sock = StartMQ(EXECQUEUEPATHAPI, WRITE)) < 0) {
                merror(QUEUE_ERROR, EXECQUEUEPATHAPI, strerror(errno));
                os_free(output);
                continue;
            }

            if ((rc = OS_SendUnix(api_sock, output, 0)) < 0) {
                /* Error on the socket */
                if (rc == OS_SOCKTERR) {
                    merror("socketerr (not available).");
                    os_free(output);
                    close(api_sock);
                    continue;
                }

                /* Unable to send. Socket busy */
                mdebug2("Socket busy, discarding message.");
            }
            close(api_sock);
            os_free(output);
            continue;
        }

        /* Get the command to execute (valid name) */
        if(!strcmp(name, "restart-wazuh")) {

            if(cmd_api[0] == NULL) {
                char script_path[PATH_MAX] = {0};
                snprintf(script_path, PATH_MAX, "%s/%s", DEFAULTDIR, "active-response/bin/restart.sh");
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

        command = GetCommandbyName(name, &timeout_value);
        if (!command) {
            ReadExecConfig();
            command = GetCommandbyName(name, &timeout_value);
            if (!command) {
                merror(EXEC_INV_NAME, name);
                continue;
            }
        }

        /* Command not present */
        if (command[0] == '\0') {
            continue;
        }

        /* Allocate memory for the timeout argument */
        os_calloc(MAX_ARGS + 2, sizeof(char *), timeout_args);

        /* Add initial variables to the cmd_arg and to the timeout cmd */
        cmd_args[0] = command;
        cmd_args[1] = ADD_ENTRY;
        os_strdup(command, timeout_args[0]);
        os_strdup(DELETE_ENTRY, timeout_args[1]);

        cmd_args[2] = NULL;
        timeout_args[2] = NULL;

        /* Get the arguments */
        for (i = 2; *tmp_msg && i < (MAX_ARGS - 1); i++) {
            cmd_args[i] = tmp_msg;
            cmd_args[i + 1] = NULL;

            tmp_msg = strchr(tmp_msg, ' ');
            if (!tmp_msg) {
                timeout_args[i] = strdup(cmd_args[i]);
                timeout_args[i + 1] = NULL;
                break;
            }
            *tmp_msg = '\0';
            tmp_msg++;

            timeout_args[i] = strdup(cmd_args[i]);
            timeout_args[i + 1] = NULL;
        }

        /* Check if this command was already executed */
        timeout_node = OSList_GetFirstNode(timeout_list);
        added_before = 0;

        /* Check for the username and IP argument */
        if (name[0] != '!' && (!timeout_args[2] || !timeout_args[3])) {
            added_before = 1;
            merror("Invalid number of arguments (%s).", name);
        }

        while (timeout_node) {
            timeout_data *list_entry;

            list_entry = (timeout_data *)timeout_node->data;
            if ((strcmp(list_entry->command[3], timeout_args[3]) == 0) &&
                    (strcmp(list_entry->command[0], timeout_args[0]) == 0)) {
                /* Means we executed this command before
                 * and we don't need to add it again
                 */
                added_before = 1;

                /* Update the timeout */
                list_entry->time_of_addition = curr_time;

                if (repeated_offenders_timeout[0] != 0 &&
                        repeated_hash != NULL &&
                        strncmp(timeout_args[3], "-", 1) != 0) {
                    char *ntimes = NULL;
                    char rkey[256];
                    rkey[255] = '\0';
                    snprintf(rkey, 255, "%s%s", list_entry->command[0],
                             timeout_args[3]);

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
                        list_entry->time_to_block = new_timeout;
                    }
                }
                break;
            }

            /* Continue with the next entry in timeout list*/
            timeout_node = OSList_GetNextNode(timeout_list);
        }

        /* If it wasn't added before, do it now */
        if (!added_before) {
            /* Execute command */
            ExecCmd(cmd_args);

            /* We don't need to add to the list if the timeout_value == 0 */
            if (timeout_value) {
                char *ntimes;
                char rkey[256];
                rkey[255] = '\0';
                snprintf(rkey, 255, "%s%s", timeout_args[0],
                         timeout_args[3]);

                if (repeated_hash != NULL) {
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

            childcount++;
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

        /* Some cleanup */
        while (i > 0) {
            cmd_args[i] = NULL;
            i--;
        }
    }
}

static int CheckManagerConfiguration(char ** output) {
    int ret_val;
    int result_code;
    int timeout = 2000;
    char command_in[PATH_MAX] = {0};
    char *output_msg = NULL;
    char *daemons[] = { "bin/ossec-authd", "bin/ossec-remoted", "bin/ossec-execd", "bin/ossec-analysisd", "bin/ossec-logcollector", "bin/ossec-integratord",  "bin/ossec-syscheckd", NULL };
    int i;
    ret_val = 0;

    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (i = 0; daemons[i]; i++) {
        snprintf(command_in, PATH_MAX, "%s/%s %s", DEFAULTDIR, daemons[i],"-t");

        if (wm_exec(command_in, output, &result_code, timeout, NULL) < 0) {

            if (result_code == 0x7F) {
                mwarn("Path is invalid or file has insufficient permissions. %s", command_in);
            } else {
                mwarn("Error executing [%s]", command_in);
            }

            os_free(*output);
            goto error;
        }

        wm_strcat(&output_msg,*output,' ');
        os_free(*output);
        *output = output_msg;

        if(result_code) {
            ret_val = result_code;
            break;
        }
    }

    gettimeofday(&end, NULL);

    double elapsed = (end.tv_usec - start.tv_usec) / 1000;
    mdebug1("Elapsed configuration check time: %0.3f milliseconds",elapsed);

    return ret_val;

error:

    ret_val = 1;
    return ret_val;
}

#endif /* !WIN32 */
