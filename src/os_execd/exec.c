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
#include "os_regex/os_regex.h"
#include "execd.h"

/* Number of command slots the table grows by */
#define EXEC_TABLE_CHUNK 32

typedef struct exec_entry {
    char *name;
    char *cmd;
    int timeout;
} exec_entry_t;

static exec_entry_t *exec_table = NULL;
static int exec_size = 0;
static int exec_capacity = 0;
static int f_time_reading = 1;
static int f_max_reported = 0;

/* Discard the loaded commands, keeping the allocated slots for the next read */
static void ClearExecTable()
{
    int i;

    for (i = 0; i < exec_size; i++) {
        os_free(exec_table[i].name);
        os_free(exec_table[i].cmd);
        exec_table[i].timeout = 0;
    }

    exec_size = 0;
}

/* Append a command to the table, growing it when there is no slot left */
static void AddExecEntry(const char *name, const char *cmd, int timeout)
{
    if (exec_size == exec_capacity) {
        exec_capacity += EXEC_TABLE_CHUNK;
        os_realloc(exec_table, exec_capacity * sizeof(exec_entry_t), exec_table);
    }

    os_strdup(name, exec_table[exec_size].name);
    os_strdup(cmd, exec_table[exec_size].cmd);
    exec_table[exec_size].timeout = timeout;
    exec_size++;
}

/* Release the command table */
void FreeExecConfig()
{
    ClearExecTable();
    os_free(exec_table);
    exec_capacity = 0;
}

/* Read the shared exec config
 * Returns 1 on success or 0 on failure
 * Format of the file is 'name - command - timeout'
 */
int ReadExecConfig()
{
    int j = 0, dup_entry = 0, truncated = 0;
    FILE *fp;
    FILE *process_file;
    char buffer[OS_MAXSTR + 1];
    char name[OS_FLSIZE + 1];
    char cmd[OS_FLSIZE + 1];

    /* Clean up */
    ClearExecTable();

    /* Open file */
    fp = wfopen(DEFAULTAR, "r");
    if (!fp) {
        merror(FOPEN_ERROR, DEFAULTAR, errno, strerror(errno));
        return (0);
    }

    /* Read config */
    while (fgets(buffer, OS_MAXSTR, fp) != NULL) {
        char *str_pt;
        char *tmp_str;

        str_pt = buffer;
        name[0] = '\0';
        cmd[0] = '\0';

        // The command name must not start with '!'

        if (buffer[0] == '!') {
            merror(EXEC_INV_CONF, DEFAULTAR);
            continue;
        }

        /* Clean up the buffer */
        tmp_str = strstr(buffer, " - ");
        if (!tmp_str) {
            merror(EXEC_INV_CONF, DEFAULTAR);
            continue;
        }
        *tmp_str = '\0';
        tmp_str += 3;

        /* Set the name */
        const int bytes_written = snprintf(name, sizeof(name), "%s", str_pt);

        if (bytes_written < 0) {
            merror(EXEC_BAD_NAME " Error %d (%s).", name, errno, strerror(errno));
        } else if ((size_t)bytes_written >= sizeof(name)) {
            merror(EXEC_BAD_NAME, name);
        }

        str_pt = tmp_str;

        /* Search for ' ' and - */
        tmp_str = strstr(tmp_str, " - ");
        if (!tmp_str) {
            merror(EXEC_INV_CONF, DEFAULTAR);
            continue;
        }
        *tmp_str = '\0';
        tmp_str += 3;

        // Directory traversal test

        if (w_ref_parent_folder(str_pt)) {
            merror("Active response command '%s' vulnerable to directory traversal attack. Ignoring.", str_pt);
        } else {
            /* Write the full command path */
            snprintf(cmd, OS_FLSIZE,
                     "%s/%s",
                     AR_BINDIR,
                     str_pt);
            process_file = wfopen(cmd, "r");
            if (!process_file) {
                if (f_time_reading) {
                    minfo("Active response command not present: '%s'. "
                            "Not using it on this system.",
                            cmd);
                }

                cmd[0] = '\0';
            } else {
                fclose(process_file);
            }
        }

        str_pt = tmp_str;
        tmp_str = strchr(tmp_str, '\n');
        if (tmp_str) {
            *tmp_str = '\0';
        }

        /* Check if name is duplicated */
        dup_entry = 0;
        for (j = 0; j < exec_size; j++) {
            if (strcmp(exec_table[j].name, name) == 0) {
                if (exec_table[j].cmd[0] == '\0') {
                    os_free(exec_table[j].cmd);
                    os_strdup(cmd, exec_table[j].cmd);
                    dup_entry = 1;
                    break;
                } else if (cmd[0] == '\0') {
                    dup_entry = 1;
                }
            }
        }

        if (!dup_entry) {
            if (exec_size == MAX_AR_COMMANDS) {
                // No room left in the command table

                truncated = 1;
                break;
            }

            /* Get the exec timeout */
            AddExecEntry(name, cmd, atoi(str_pt));
        }
    }

    fclose(fp);
    f_time_reading = 0;

    /* Report only when the configuration starts being truncated */
    if (truncated && !f_max_reported) {
        merror(EXEC_MAX_AR, MAX_AR_COMMANDS, DEFAULTAR);
    }

    f_max_reported = truncated;

    return (1);
}

/* Returns a pointer to the command name (full path)
 * The pointer is only valid until the next call to ReadExecConfig()
 * Returns NULL if name cannot be found
 * If timeout is not NULL, write the timeout for that
 * command to it
 */
char *GetCommandbyName(const char *name, int *timeout)
{
    int i = 0;

    // Filter custom commands

    if (name[0] == '!') {
        if (w_ref_parent_folder(name + 1)) {
            mwarn("Active response command '%s' vulnerable to directory traversal attack. Ignoring.", name + 1);
            return NULL;
        }

        static char command[OS_FLSIZE];

        if (snprintf(command, sizeof(command), "%s/%s", AR_BINDIR, name + 1) >= (int)sizeof(command)) {
            mwarn("Cannot execute command '%32s...': path too long.", name + 1);
            return NULL;
        }

        *timeout = 0;
        return command;
    }

    for (; i < exec_size; i++) {
        if (strcmp(name, exec_table[i].name) == 0) {
            *timeout = exec_table[i].timeout;
            return (exec_table[i].cmd);
        }
    }

    return (NULL);
}

#ifndef WIN32

/* Execute command given. Must be a argv** NULL terminated.
 * Prints error to log message in case of problems
 */
void ExecCmd(char *const *cmd)
{
    pid_t pid;

    /* Fork and leave it running */
    pid = fork();
    if (pid == 0) {
        if (execv(*cmd, cmd) < 0) {
            merror(EXEC_CMDERROR, *cmd, strerror(errno));
            exit(1);
        }

        exit(0);
    }

    return;
}

#else

void ExecCmd_Win32(char *cmd)
{
    STARTUPINFO si;
    PROCESS_INFORMATION pi;

    ZeroMemory( &si, sizeof(si) );
    si.cb = sizeof(si);
    ZeroMemory( &pi, sizeof(pi) );

    if (!CreateProcess(NULL, cmd, NULL, NULL, FALSE, 0, NULL, NULL,
                       &si, &pi)) {
        merror("Unable to create active response process. ");
        return;
    }

    /* Wait until process exits */
    WaitForSingleObject(pi.hProcess, INFINITE );

    /* Close process and thread */
    CloseHandle( pi.hProcess );
    CloseHandle( pi.hThread );

    return;
}
#endif
