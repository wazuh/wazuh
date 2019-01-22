/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
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

    if (rootcheck.disabled) cJSON_AddStringToObject(rtck,"disabled","yes"); else cJSON_AddStringToObject(rtck,"disabled","no");
    if (rootcheck.basedir) cJSON_AddStringToObject(rtck,"base_directory",rootcheck.basedir);
    if (rootcheck.rootkit_files) cJSON_AddStringToObject(rtck,"rootkit_files",rootcheck.rootkit_files);
    if (rootcheck.rootkit_trojans) cJSON_AddStringToObject(rtck,"rootkit_trojans",rootcheck.rootkit_trojans);
    if (rootcheck.scanall) cJSON_AddStringToObject(rtck,"scanall","yes"); else cJSON_AddStringToObject(rtck,"scanall","no");
    if (rootcheck.skip_nfs) cJSON_AddStringToObject(rtck,"skip_nfs","yes"); else cJSON_AddStringToObject(rtck,"skip_nfs","no");
    cJSON_AddNumberToObject(rtck,"frequency",rootcheck.time);
    if (rootcheck.checks.rc_dev) cJSON_AddStringToObject(rtck,"check_dev","yes"); else cJSON_AddStringToObject(rtck,"check_dev","no");
    if (rootcheck.checks.rc_files) cJSON_AddStringToObject(rtck,"check_files","yes"); else cJSON_AddStringToObject(rtck,"check_files","no");
    if (rootcheck.checks.rc_if) cJSON_AddStringToObject(rtck,"check_if","yes"); else cJSON_AddStringToObject(rtck,"check_if","no");
    if (rootcheck.checks.rc_pids) cJSON_AddStringToObject(rtck,"check_pids","yes"); else cJSON_AddStringToObject(rtck,"check_pids","no");
    if (rootcheck.checks.rc_ports) cJSON_AddStringToObject(rtck,"check_ports","yes"); else cJSON_AddStringToObject(rtck,"check_ports","no");
    if (rootcheck.checks.rc_sys) cJSON_AddStringToObject(rtck,"check_sys","yes"); else cJSON_AddStringToObject(rtck,"check_sys","no");
    if (rootcheck.checks.rc_trojans) cJSON_AddStringToObject(rtck,"check_trojans","yes"); else cJSON_AddStringToObject(rtck,"check_trojans","no");
#ifdef WIN32
    if (rootcheck.checks.rc_winaudit) cJSON_AddStringToObject(rtck,"check_winaudit","yes"); else cJSON_AddStringToObject(rtck,"check_winaudit","no");
    if (rootcheck.checks.rc_winmalware) cJSON_AddStringToObject(rtck,"check_winmalware","yes"); else cJSON_AddStringToObject(rtck,"check_winmalware","no");
    if (rootcheck.checks.rc_winapps) cJSON_AddStringToObject(rtck,"check_winapps","yes"); else cJSON_AddStringToObject(rtck,"check_winapps","no");
    if (rootcheck.winapps) cJSON_AddStringToObject(rtck,"windows_apps",rootcheck.winapps);
    if (rootcheck.winmalware) cJSON_AddStringToObject(rtck,"windows_malware",rootcheck.winmalware);
    if (rootcheck.winaudit) cJSON_AddStringToObject(rtck,"windows_audit",rootcheck.winaudit);
#else
    unsigned int i;
    if (rootcheck.checks.rc_unixaudit) cJSON_AddStringToObject(rtck,"check_unixaudit","yes"); else cJSON_AddStringToObject(rtck,"check_unixaudit","no");
    if (rootcheck.unixaudit) {
        cJSON *uaudit = cJSON_CreateArray();
        for (i=0;rootcheck.unixaudit[i];i++) {
            cJSON_AddItemToArray(uaudit, cJSON_CreateString(rootcheck.unixaudit[i]));
        }
        cJSON_AddItemToObject(rtck,"system_audit",uaudit);
    }
#endif

    cJSON_AddItemToObject(root,"rootcheck",rtck);

    return root;
}

#endif /* OSSECHIDS */
