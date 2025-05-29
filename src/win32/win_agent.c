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
    printf("\treload            Manually reload the agent service\n");
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
        } else if (strcmp(argv[1], "reload") == 0) {
            return (local_reload());
        } else if (strcmp(argv[1], "/?") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "-h") == 0) {
            agent_help();
        } else if (strcmp(argv[1], "help") == 0) {
            agent_help();
        } else {
            plain_merror("Unknown option: %s", argv[1]);
            exit(1);
        }
    }

    /* Start it */
    if (!os_WinMain(argc, argv)) {
        plain_merror_exit("Unable to start WinMain.");
    }

    return (0);
}

#endif
