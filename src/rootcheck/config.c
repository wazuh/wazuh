/* Copyright (C) 2015, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifdef OSSECHIDS
#include "shared.h"
#include "rootcheck.h"
#include "config/config.h"
#include "external/cJSON/cJSON.h"


/* Read the rootcheck config */
int Read_Rootcheck_Config(const char *cfgfile)
{
    int modules = 0;

    modules |= CROOTCHECK;
    if (ReadConfig(modules, cfgfile, &rootcheck, NULL) < 0) {
        return (OS_INVALID);
    }

#ifdef CLIENT
    /* Read shared config */
    modules |= CAGENT_CONFIG;
    ReadConfig(modules, AGENTCONFIG, &rootcheck, NULL);
#endif

    switch (rootcheck.disabled) {
    case RK_CONF_UNPARSED:
        rootcheck.disabled = 1;
        break;
    case RK_CONF_UNDEFINED:
        rootcheck.disabled = 0;
    }

    return (0);
}


cJSON *getRootcheckConfig(void) {

    cJSON *root = cJSON_CreateObject();
    cJSON *rtck = cJSON_CreateObject();
    unsigned int i;

    if (rootcheck.disabled) cJSON_AddStringToObject(rtck,"disabled","yes"); else cJSON_AddStringToObject(rtck,"disabled","no");
    if (rootcheck.basedir) cJSON_AddStringToObject(rtck,"base_directory",rootcheck.basedir);
    if (rootcheck.scanall) cJSON_AddStringToObject(rtck,"scanall","yes"); else cJSON_AddStringToObject(rtck,"scanall","no");
    if (rootcheck.skip_nfs) cJSON_AddStringToObject(rtck,"skip_nfs","yes"); else cJSON_AddStringToObject(rtck,"skip_nfs","no");
    cJSON_AddNumberToObject(rtck,"frequency",rootcheck.time);
    if (rootcheck.checks.rc_dev) cJSON_AddStringToObject(rtck,"check_dev","yes"); else cJSON_AddStringToObject(rtck,"check_dev","no");
    if (rootcheck.checks.rc_if) cJSON_AddStringToObject(rtck,"check_if","yes"); else cJSON_AddStringToObject(rtck,"check_if","no");
    if (rootcheck.checks.rc_pids) cJSON_AddStringToObject(rtck,"check_pids","yes"); else cJSON_AddStringToObject(rtck,"check_pids","no");
    if (rootcheck.checks.rc_ports) cJSON_AddStringToObject(rtck,"check_ports","yes"); else cJSON_AddStringToObject(rtck,"check_ports","no");
    if (rootcheck.checks.rc_sys) cJSON_AddStringToObject(rtck,"check_sys","yes"); else cJSON_AddStringToObject(rtck,"check_sys","no");

    if (rootcheck.ignore) {
        cJSON *igns = NULL;
        cJSON *ignsregex = NULL;

        for (i=0; rootcheck.ignore[i]; i++) {
            if (rootcheck.ignore_sregex[i]) {
                if (!ignsregex) ignsregex = cJSON_CreateArray();
                cJSON_AddItemToArray(ignsregex, cJSON_CreateString(rootcheck.ignore_sregex[i]->raw));
            } else {
                if (!igns) igns = cJSON_CreateArray();
                cJSON_AddItemToArray(igns, cJSON_CreateString(rootcheck.ignore[i]));
            }
        }

        if (igns) cJSON_AddItemToObject(rtck, "ignore", igns);
        if (ignsregex) cJSON_AddItemToObject(rtck, "ignore_sregex", ignsregex);
    }

    cJSON_AddItemToObject(root, "rootcheck", rtck);

    return root;
}

#endif /* OSSECHIDS */
