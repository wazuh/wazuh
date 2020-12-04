/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "setup-shared.h"


/* Set up Windows after installation */
int main(int argc, char **argv)
{
    /* Set the name */
    OS_SetName(ARGV0);

    if (argc < 2) {
        printf("%s: Invalid syntax.\n", argv[0]);
        printf("Try: '%s directory'\n\n", argv[0]);
        return (0);
    }

    /* Try to chdir to the OSSEC directory */
    if (chdir(argv[1]) != 0) {
        printf("%s: Invalid directory: '%s'.\n", argv[0], argv[1]);
        return (0);
    }

    /* Configure OSSEC for automatic startup */
    system("sc config OssecSvc start= auto");

    /* Change permissions */
    if (checkVista()) {
        char cmd[OS_MAXSTR + 1];

        /* Copy some files to outside */

        snprintf(cmd, OS_MAXSTR, "move win32ui.exe ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move uninstall.exe ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move doc.html ../");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move help.txt ../");
        system(cmd);

        /* Change permissions */

        system("echo y|icacls .  /inheritancelevel:d ");

        system("echo y|icacls .  /remove  \"*S-1-5-32-545\" ");

        system("echo y|icacls ossec.conf  /remove  \"*S-1-1-0\" ");

        /* Copy them back */

        snprintf(cmd, OS_MAXSTR, "move ..\\win32ui.exe .");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move ..\\uninstall.exe .");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move ..\\doc.html .");
        system(cmd);

        snprintf(cmd, OS_MAXSTR, "move ..\\help.txt .");
        system(cmd);
    }

    return (1);
}
