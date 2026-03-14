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
#include "execd.h"

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
