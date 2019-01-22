/* Copyright (C) 2015-2019, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rootcheck-config.h"
#include "config.h"


static short eval_bool(const char *str)
{
    if (str == NULL) {
        return (OS_INVALID);
    } else if (strcmp(str, "yes") == 0) {
        return (1);
    } else if (strcmp(str, "no") == 0) {
        return (0);
    } else {
        return (OS_INVALID);
    }
}

/* Read the rootcheck config */
int Read_Rootcheck(XML_NODE node, void *configp, __attribute__((unused)) void *mailp)
{
    int i = 0;
    rkconfig *rootcheck;

    /* XML Definitions */
    const char *xml_rootkit_files = "rootkit_files";
    const char *xml_rootkit_trojans = "rootkit_trojans";
    const char *xml_winaudit = "windows_audit";
    const char *xml_unixaudit = "system_audit";
    const char *xml_winapps = "windows_apps";
    const char *xml_winmalware = "windows_malware";
    const char *xml_scanall = "scanall";
    const char *xml_readall = "readall";
    const char *xml_time = "frequency";
    const char *xml_disabled = "disabled";
    const char *xml_skip_nfs = "skip_nfs";
    const char *xml_base_dir = "base_directory";
    const char *xml_ignore = "ignore";

    const char *xml_check_dev = "check_dev";
    const char *xml_check_files = "check_files";
    const char *xml_check_if = "check_if";
    const char *xml_check_pids = "check_pids";
    const char *xml_check_ports = "check_ports";
    const char *xml_check_sys = "check_sys";
    const char *xml_check_trojans = "check_trojans";
    const char *xml_check_unixaudit = "check_unixaudit";
    const char *xml_check_winapps = "check_winapps";
    const char *xml_check_winaudit = "check_winaudit";
    const char *xml_check_winmalware = "check_winmalware";

    rootcheck = (rkconfig *)configp;

    /* If rootcheck is defined, enable it by default */
    if (rootcheck->disabled == RK_CONF_UNPARSED) {
        rootcheck->disabled = RK_CONF_UNDEFINED;
    }

    if (!node)
        return 0;

    while (node[i]) {
        if (!node[i]->element) {
            merror(XML_ELEMNULL);
            return (OS_INVALID);
        } else if (!node[i]->content) {
            merror(XML_VALUENULL, node[i]->element);
            return (OS_INVALID);
        }

        /* Get frequency */
        else if (strcmp(node[i]->element, xml_time) == 0) {
            if (!OS_StrIsNum(node[i]->content)) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }

            rootcheck->time = atoi(node[i]->content);
        }
        /* Get scan all */
        else if (strcmp(node[i]->element, xml_scanall) == 0) {
            rootcheck->scanall = eval_bool(node[i]->content);
            if (rootcheck->scanall == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_disabled) == 0) {
            rootcheck->disabled = eval_bool(node[i]->content);
            if (rootcheck->disabled == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element, xml_skip_nfs) == 0)
        {
            rootcheck->skip_nfs = eval_bool(node[i]->content);
            if (rootcheck->skip_nfs == OS_INVALID)
            {
                merror(XML_VALUEERR,node[i]->element,node[i]->content);
                return(OS_INVALID);
            }
        }
        else if(strcmp(node[i]->element,xml_readall) == 0)
        {
            rootcheck->readall = eval_bool(node[i]->content);
            if (rootcheck->readall == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_rootkit_files) == 0) {
            rootcheck->checks.rc_files = 1;
            os_strdup(node[i]->content, rootcheck->rootkit_files);
        } else if (strcmp(node[i]->element, xml_rootkit_trojans) == 0) {
            rootcheck->checks.rc_trojans = 1;
            os_strdup(node[i]->content, rootcheck->rootkit_trojans);
        } else if (strcmp(node[i]->element, xml_winaudit) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winaudit = 1;
#endif
            os_strdup(node[i]->content, rootcheck->winaudit);
        } else if (strcmp(node[i]->element, xml_unixaudit) == 0) {
            unsigned int j = 0;
            while (rootcheck->unixaudit && rootcheck->unixaudit[j]) {
                j++;
            }

            os_realloc(rootcheck->unixaudit, sizeof(char *) * (j + 2),
                       rootcheck->unixaudit);
            rootcheck->unixaudit[j] = NULL;
            rootcheck->unixaudit[j + 1] = NULL;

#ifndef WIN32
            rootcheck->checks.rc_unixaudit = 1;
#endif
            os_strdup(node[i]->content, rootcheck->unixaudit[j]);
        } else if (strcmp(node[i]->element, xml_ignore) == 0) {
            unsigned int j = 0;
            while (rootcheck->ignore && rootcheck->ignore[j]) {
                j++;
            }

            os_realloc(rootcheck->ignore, sizeof(char *) * (j + 2),
                       rootcheck->ignore);
            rootcheck->ignore[j] = NULL;
            rootcheck->ignore[j + 1] = NULL;

            os_strdup(node[i]->content, rootcheck->ignore[j]);
        } else if (strcmp(node[i]->element, xml_winmalware) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winmalware = 1;
#endif
            os_strdup(node[i]->content, rootcheck->winmalware);
        } else if (strcmp(node[i]->element, xml_winapps) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winapps = 1;
#endif
            os_strdup(node[i]->content, rootcheck->winapps);
        } else if (strcmp(node[i]->element, xml_base_dir) == 0) {
            os_strdup(node[i]->content, rootcheck->basedir);
        } else if (strcmp(node[i]->element, xml_check_dev) == 0) {
            rootcheck->checks.rc_dev = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_dev == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_files) == 0) {
            rootcheck->checks.rc_files = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_files == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_if) == 0) {
            rootcheck->checks.rc_if = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_if == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_pids) == 0) {
            rootcheck->checks.rc_pids = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_pids == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_ports) == 0) {
            rootcheck->checks.rc_ports = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_ports == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_sys) == 0) {
            rootcheck->checks.rc_sys = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_sys == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_trojans) == 0) {
            rootcheck->checks.rc_trojans = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_trojans == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
        } else if (strcmp(node[i]->element, xml_check_unixaudit) == 0) {
#ifndef WIN32
            rootcheck->checks.rc_unixaudit = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_unixaudit == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
#endif
        } else if (strcmp(node[i]->element, xml_check_winapps) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winapps = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winapps == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
#endif
        } else if (strcmp(node[i]->element, xml_check_winaudit) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winaudit = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winaudit == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
#endif
        } else if (strcmp(node[i]->element, xml_check_winmalware) == 0) {
#ifdef WIN32
            rootcheck->checks.rc_winmalware = eval_bool(node[i]->content);
            if (rootcheck->checks.rc_winmalware == OS_INVALID) {
                merror(XML_VALUEERR, node[i]->element, node[i]->content);
                return (OS_INVALID);
            }
#endif
        } else {
            merror(XML_INVELEM, node[i]->element);
            return (OS_INVALID);
        }
        i++;
    }
    return (0);
}

int Test_Rootcheck(const char * path){
    int fail = 0;
    rkconfig test_rootcheck = { .workdir = 0 };

    if (ReadConfig(CAGENT_CONFIG | CROOTCHECK, path, &test_rootcheck, NULL) < 0) {
        merror(RCONFIG_ERROR,"Rootcheck", path);
		fail = 1;
	}

    Free_Rootcheck(&test_rootcheck);

    if (fail) {
        return -1;
    } else {
        return 0;
    }
}

void Free_Rootcheck(rkconfig * config){
    if (config) {
        int i;
        free((char*) config->workdir);
        free(config->basedir);
        free(config->rootkit_files);
        free(config->rootkit_trojans);
        if (config->unixaudit) {
            for (i=0; config->unixaudit[i] != NULL; i++) {
                free(config->unixaudit[i]);
            }
            free(config->unixaudit);
        }
        if (config->ignore) {
            for (i=0; config->ignore[i] != NULL; i++) {
                free(config->ignore[i]);
            }
            free(config->ignore);
        }
        free(config->winaudit);
        free(config->winmalware);
        free(config->winapps);
        if (config->alert_msg) {
            for (i=0; config->alert_msg[i] != NULL; i++) {
                free(config->alert_msg[i]);
            }
            free(config->alert_msg);
        }
        if (config->fp) {
            fclose(config->fp);
        }
    }
}
