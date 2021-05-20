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

static char exec_names[MAX_AR + 1][OS_FLSIZE + 1];
static char exec_cmd[MAX_AR + 1][OS_FLSIZE + 1];
static int  exec_timeout[MAX_AR + 1];
static int  exec_size = 0;
static int  f_time_reading = 1;

int repeated_offenders_timeout[] = {0, 0, 0, 0, 0, 0, 0};
time_t pending_upg = 0;

#ifndef WIN32

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
