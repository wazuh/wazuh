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
#include "active-response.h"

#ifndef WIN32
#include <sys/types.h>
#include <grp.h>
#endif

/* The lines that AR_ReadConfig() always writes hold two distinct names, and every
 * platform ships at most one of the executables of each, so the agents keep two
 * entries out of them. Should a platform ever ship two executables of the same
 * name, that name would take one further entry.
 */
#define AR_DEFAULT_COMMANDS 2

/* Active response commands */
OSList *ar_commands;
OSList *active_responses;

/* Initialize active response */
void AR_Init()
{
    ar_commands = OSList_Create();
    active_responses = OSList_Create();
    ar_flag = 0;

    if (!ar_commands || !active_responses) {
        merror_exit(LIST_ERROR);
    }
}

/* Read active response configuration and write it
 * to the appropriate lists.
 */
int AR_ReadConfig(const char *cfgfile)
{
    FILE *fp;
    int modules = 0;

    modules |= CAR;

    /* Clean ar file */
    fp = wfopen(DEFAULTAR, "w");
    if (!fp) {
        merror(FOPEN_ERROR, DEFAULTAR, errno, strerror(errno));
        return (OS_INVALID);
    }
    fprintf(fp, "restart-ossec0 - restart-ossec.sh - 0\nrestart-ossec0 - restart-ossec.cmd - 0\n"
                "restart-wazuh0 - restart-ossec.sh - 0\nrestart-wazuh0 - restart-ossec.cmd - 0\n"
                "restart-wazuh0 - restart-wazuh - 0\nrestart-wazuh0 - restart-wazuh.exe - 0\n");
    fclose(fp);

#ifndef WIN32
    gid_t gr_gid;
    if (gr_gid = Privsep_GetGroup(USER), gr_gid == (uid_t) -1) {
        merror("Could not get '%s' gid.", USER);
        return (OS_INVALID);
    }

    if ((chown(DEFAULTAR, (uid_t) - 1, gr_gid)) == -1) {
        merror("Could not change the group to '%s': %d", GROUPGLOBAL, errno);
        return (OS_INVALID);
    }
#endif

    /* Set right permission */
    if (chmod(DEFAULTAR, 0640) == -1) {
        merror(CHMOD_ERROR, DEFAULTAR, errno, strerror(errno));
        return (OS_INVALID);
    }

    /* Read configuration */
    if (ReadConfig(modules, cfgfile, ar_commands, active_responses) < 0) {
        return (OS_INVALID);
    }

    /* The entries above plus one per active response make up the shared file */
    const int total_commands = AR_DEFAULT_COMMANDS + active_responses->currently_size;

    if (total_commands > MAX_AR) {
        mwarn(AR_MAX_COMMANDS, total_commands, MAX_AR, DEFAULTAR);
    }

    return (0);
}
