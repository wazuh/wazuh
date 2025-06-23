/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifdef WIN32

#include "shared.h"
#include "wazuh_modules/wmodules.h"
#include "client-agent/agentd.h"
#include "logcollector/logcollector.h"
#include "wazuh_modules/wmodules.h"
#include "os_win.h"
#include "os_net/os_net.h"
#include "os_execd/execd.h"
#include "os_crypto/md5/md5_op.h"
#include "external/cJSON/cJSON.h"
#include "socket_reload.h"
#include "wazuh_reload.h"

#ifndef ARGV0
#define ARGV0 "wazuh-agent"
#endif

/**************************************************************************************
    WARNING: all the logging functions of this file must use the plain_ variant
    to avoid calling any external library that could be loaded before the signature
    verification can be executed in local_start.
**************************************************************************************/

/* Help message */
void agent_help()
{
    printf("\n%s %s %s .\n", __ossec_name, ARGV0, __ossec_version);
    printf("Available options:\n");
    printf("\t/?                This help message.\n");
    printf("\t-h                This help message.\n");
    printf("\thelp              This help message.\n");
    printf("\tinstall-service   Installs as a service\n");
    printf("\tuninstall-service Uninstalls as a service\n");
    printf("\tstart             Manually starts (not from services)\n");
    exit(1);
}

int main(int argc, char **argv)
{
    char *tmpstr;
    char mypath[OS_MAXSTR + 1];
    char myfinalpath[OS_MAXSTR + 1];
    char myfile[OS_MAXSTR + 1];

    /* Set the name */
    OS_SetName(ARGV0);

    /* Find where we are */
    mypath[OS_MAXSTR] = '\0';
    myfinalpath[OS_MAXSTR] = '\0';
    myfile[OS_MAXSTR] = '\0';

    /* mypath is going to be the whole path of the file */
    strncpy(mypath, argv[0], OS_MAXSTR);
    tmpstr = strrchr(mypath, '\\');
    if (tmpstr) {
        /* tmpstr is now the file name */
        *tmpstr = '\0';
        tmpstr++;
        strncpy(myfile, tmpstr, OS_MAXSTR);
    } else {
        strncpy(myfile, argv[0], OS_MAXSTR);
        mypath[0] = '.';
        mypath[1] = '\0';
    }
    if (chdir(mypath) < 0) {
        plain_merror_exit(CHDIR_ERROR, mypath, errno, strerror(errno));
    }
    getcwd(mypath, OS_MAXSTR - 1);
    snprintf(myfinalpath, OS_MAXSTR, "\"%s\\%s\"", mypath, myfile);

    if (argc > 1) {
        if (strcmp(argv[1], "install-service") == 0) {
            return (InstallService(myfinalpath));
        } else if (strcmp(argv[1], "uninstall-service") == 0) {
            return (UninstallService());
        } else if (strcmp(argv[1], "start") == 0) {
            return (local_start());
        } else if (strcmp(argv[1], "/?") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "-h") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "help") == 0) {
            agent_help();
        } else if (argc > 2 && strcmp(argv[1], "control") == 0 && strcmp(argv[2], "reload") == 0) {
            // Send a reload command to the agent control pipe
            HANDLE hPipe = CreateFileA(
                RELOAD_PIPE_CONTROL, GENERIC_WRITE, 0, NULL, OPEN_EXISTING, 0, NULL
            );
            if (hPipe == INVALID_HANDLE_VALUE) {
                printf("Cannot connect to agent control pipe (is agent running?): %d\n", GetLastError());
                return 1;
            }
            DWORD written;
            if (!WriteFile(hPipe, "reload", 6, &written, NULL)) {
                printf("Failed to write reload command.\n");
            }
            CloseHandle(hPipe);
            printf("Reload command sent.\n");
            return 0;
        }
        else if (argc > 2 && strcmp(argv[1], "--reload-child") == 0) {
            // This is the child process that will handle the reload
            plain_minfo("Hello from reload child, restoring socket...");
            if (handle_reload_child(argv[2]) != 0) {
                plain_merror("Reload child: failed to restore socket.");
                exit(1);
            }
            // Continue normal operation after restoring the socket
            // start_reload_control_thread(myfinalpath);
            // if (!os_WinMain(argc, argv)) {
            //     plain_merror_exit("Unable to start WinMain.");
            // }
            plain_minfo("Reload child: socket restored, continuing normal operation.");
            // return os_start_service();
            return local_start();
        } else {
            plain_merror("Unknown option: %s", argv[1]);
            exit(1);
        }
    }

    // Start the reload control thread
    start_reload_control_thread(myfinalpath);

    /* Start it */
    if (!os_WinMain(argc, argv)) {
        plain_merror_exit("Unable to start WinMain.");
    }

    return (0);
}

#endif
