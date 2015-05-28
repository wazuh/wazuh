/* Copyright (C) 2009 Trend Micro Inc.
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
#include "execd.h"

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};

#ifndef WIN32

/* Prototypes */
static void help_execd(void) __attribute__((noreturn));
static void execd_shutdown(int sig) __attribute__((noreturn));
static void ExecdStart(int q) __attribute__((noreturn));

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
    struct timespec delay;
    delay.tv_sec = 0;
    delay.tv_nsec = AR_FLUSH_INTERVAL;

    /* Remove pending active responses */
    merror(EXEC_SHUTDOWN, ARGV0);

    timeout_node = OSList_GetFirstNode(timeout_list);
    while (timeout_node) {
        timeout_data *list_entry;

        list_entry = (timeout_data *)timeout_node->data;

        ExecCmd(list_entry->command);

        /* Delete current node - already sets the pointer to next */
        OSList_DeleteCurrentlyNode(timeout_list);
        timeout_node = OSList_GetCurrentlyNode(timeout_list);

        /* Delay to prevent system from being overwhelmed by locked
           processes if there are many nodes */
        nanosleep(&delay, NULL);
    }

    HandleSIG(sig);
}

int main(int argc, char **argv)
{
    int c;
    int test_config = 0, run_foreground = 0;
    gid_t gid;
    int m_queue = 0;

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
                nowDebug();
                break;
            case 'f':
                run_foreground = 1;
                break;
            case 'g':
                if (!optarg) {
                    ErrorExit("%s: -g needs an argument.", ARGV0);
                }
                group = optarg;
                break;
            case 'c':
                if (!optarg) {
                    ErrorExit("%s: -c needs an argument.", ARGV0);
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

    /* Check if the group given is valid */
    gid = Privsep_GetGroup(group);
    if (gid == (gid_t) - 1) {
        ErrorExit(USER_ERROR, ARGV0, "", group);
    }

    /* Privilege separation */
    if (Privsep_SetGroup(gid) < 0) {
        ErrorExit(SETGID_ERROR, ARGV0, group, errno, strerror(errno));
    }

    /* Read config */
    if ((c = ExecdConfig(cfg)) < 0) {
        ErrorExit(CONFIG_ERROR, ARGV0, cfg);
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
        verbose(EXEC_DISABLED, ARGV0);
        exit(0);
    }

    /* Create the PID file */
    if (CreatePID(ARGV0, getpid()) < 0) {
        merror(PID_ERROR, ARGV0);
    }

    /* Start exec queue */
    if ((m_queue = StartMQ(EXECQUEUEPATH, READ)) < 0) {
        ErrorExit(QUEUE_ERROR, ARGV0, EXECQUEUEPATH, strerror(errno));
    }

    /* Start up message */
    verbose(STARTUP_MSG, ARGV0, (int)getpid());

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

    /* Select */
    fd_set fdset;
    struct timeval socket_timeout;

    /* Clear the buffer */
    memset(buffer, '\0', OS_MAXSTR + 1);

    /* Initialize the cmd arguments */
    for (i = 0; i <= MAX_ARGS + 1; i++) {
        cmd_args[i] = NULL;
    }

    /* Create list for timeout */
    timeout_list = OSList_Create();
    if (!timeout_list) {
        ErrorExit(LIST_ERROR, ARGV0);
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
                merror(WAITPID_ERROR, ARGV0, errno, strerror(errno));
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
            merror(SELECT_ERROR, ARGV0, errno, strerror(errno));
            continue;
        }

        /* Receive the message */
        if (OS_RecvUnix(q, OS_MAXSTR, buffer) == 0) {
            merror(QUEUE_ERROR, ARGV0, EXECQUEUEPATH, strerror(errno));
            continue;
        }

        /* Current time */
        curr_time = time(0);

        /* Get application name */
        name = buffer;

        /* Zero the name */
        tmp_msg = strchr(buffer, ' ');
        if (!tmp_msg) {
            merror(EXECD_INV_MSG, ARGV0, buffer);
            continue;
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
        i = 2;
        while (i < (MAX_ARGS - 1)) {
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

            i++;
        }

        /* Check if this command was already executed */
        timeout_node = OSList_GetFirstNode(timeout_list);
        added_before = 0;

        /* Check for the username and IP argument */
        if (!timeout_args[2] || !timeout_args[3]) {
            added_before = 1;
            merror("%s: Invalid number of arguments.", ARGV0);
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
                            os_calloc(10, sizeof(char), ntimes);
                            new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                            ntimes_int++;
                            snprintf(ntimes, 9, "%d", ntimes_int);
                            OSHash_Update(repeated_hash, rkey, ntimes);
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
                            os_calloc(10, sizeof(char), ntimes);
                            new_timeout = repeated_offenders_timeout[ntimes_int] * 60;
                            ntimes_int++;
                            snprintf(ntimes, 9, "%d", ntimes_int);
                            OSHash_Update(repeated_hash, rkey, ntimes);
                        }
                        timeout_value = new_timeout;
                    } else {
                        /* Add to the repeat offenders list */
                        OSHash_Add(repeated_hash,
                                   rkey, strdup("0"));
                    }
                }

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

#endif /* !WIN32 */

